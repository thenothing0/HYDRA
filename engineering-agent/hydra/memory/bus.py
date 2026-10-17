"""
╔══════════════════════════════════════════════════════════════╗
║  Shared Memory Bus — Redis-Backed Async Message Bus         ║
║  The ONLY communication channel between agents              ║
║  Agents are stateless; all state lives here                  ║
╚══════════════════════════════════════════════════════════════╝

Design:
  - Task Queue:     Coordinator pushes tasks → agents pull tasks
  - Result Store:   Agents push results → Coordinator reads them
  - State Store:    Global scan state, attack graph, findings
  - Pub/Sub:        Event notifications (non-blocking)
  
Agents NEVER talk to each other. All routing goes through the bus.
"""

import asyncio
import json
import time
import uuid
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger("hydra.memory.bus")


# ──────────────────────────────────────────────
#  Data Structures
# ──────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(int, Enum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass
class Task:
    """A unit of work routed through the memory bus."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = ""                    # e.g. "recon", "vuln_scan", "exploit_hypothesis"
    agent_type: str = ""                   # target agent class
    priority: int = TaskPriority.NORMAL
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    assigned_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    parent_task_id: Optional[str] = None   # for task chaining
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Task":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ScanState:
    """Global scan state stored in the memory bus."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    status: str = "initializing"
    started_at: float = field(default_factory=time.time)
    assets_discovered: List[str] = field(default_factory=list)
    endpoints_found: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    agent_status: Dict[str, str] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)


class MemoryBus:
    """
    Redis-backed shared memory bus.
    
    Falls back to in-memory implementation when Redis is unavailable,
    allowing local single-machine operation without dependencies.
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self._redis_url = redis_url
        self._redis = None
        self._fallback_mode = False
        
        # In-memory fallback stores
        self._task_queues: Dict[str, asyncio.Queue] = {}
        self._results: Dict[str, Task] = {}
        self._state: Dict[str, Any] = {}
        self._pubsub_handlers: Dict[str, List] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self):
        """Connect to Redis or fall back to in-memory mode."""
        if self._redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    max_connections=20,
                )
                await self._redis.ping()
                logger.info(f"✅ Memory bus connected to Redis: {self._redis_url}")
                return
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}), falling back to in-memory mode")
        
        self._fallback_mode = True
        logger.info("📦 Memory bus running in local in-memory mode")
    
    async def disconnect(self):
        """Gracefully disconnect."""
        if self._redis:
            await self._redis.close()
            logger.info("Memory bus disconnected from Redis")
    
    # ──────────────────────────────────────────
    #  Task Queue Operations
    # ──────────────────────────────────────────
    
    async def push_task(self, task: Task) -> str:
        """Push a task onto the queue for a specific agent type."""
        queue_key = f"hydra:tasks:{task.agent_type}"
        task_data = json.dumps(task.to_dict())
        
        if self._redis and not self._fallback_mode:
            # Use Redis sorted set for priority ordering (lower = higher priority)
            await self._redis.zadd(queue_key, {task_data: task.priority})
            await self._redis.hset("hydra:task_registry", task.id, task_data)
        else:
            async with self._lock:
                if queue_key not in self._task_queues:
                    self._task_queues[queue_key] = asyncio.PriorityQueue()
                await self._task_queues[queue_key].put((task.priority, task.id, task))
                self._results[task.id] = task
        
        logger.debug(f"📤 Task pushed: {task.id} → {task.agent_type} (priority={task.priority})")
        return task.id
    
    async def pull_task(self, agent_type: str, timeout: float = 5.0) -> Optional[Task]:
        """Pull the highest-priority task for a given agent type."""
        queue_key = f"hydra:tasks:{agent_type}"
        
        if self._redis and not self._fallback_mode:
            # Pop lowest score (highest priority) from sorted set
            results = await self._redis.zpopmin(queue_key, count=1)
            if results:
                task_data, _score = results[0]
                task = Task.from_dict(json.loads(task_data))
                task.status = TaskStatus.ASSIGNED
                task.assigned_at = time.time()
                await self._redis.hset("hydra:task_registry", task.id, json.dumps(task.to_dict()))
                return task
        else:
            async with self._lock:
                if queue_key in self._task_queues and not self._task_queues[queue_key].empty():
                    _priority, _id, task = self._task_queues[queue_key].get_nowait()
                    task.status = TaskStatus.ASSIGNED
                    task.assigned_at = time.time()
                    self._results[task.id] = task
                    return task
        
        return None
    
    async def complete_task(self, task_id: str, result: Dict[str, Any]):
        """Mark a task as completed with its result."""
        if self._redis and not self._fallback_mode:
            raw = await self._redis.hget("hydra:task_registry", task_id)
            if raw:
                task = Task.from_dict(json.loads(raw))
                task.status = TaskStatus.COMPLETED
                task.completed_at = time.time()
                task.result = result
                await self._redis.hset("hydra:task_registry", task_id, json.dumps(task.to_dict()))
                await self._redis.lpush(f"hydra:results:{task_id}", json.dumps(result))
        else:
            async with self._lock:
                if task_id in self._results:
                    self._results[task_id].status = TaskStatus.COMPLETED
                    self._results[task_id].completed_at = time.time()
                    self._results[task_id].result = result
        
        await self.publish("task_completed", {"task_id": task_id})
        logger.debug(f"✅ Task completed: {task_id}")
    
    async def fail_task(self, task_id: str, error: str):
        """Mark a task as failed."""
        if self._redis and not self._fallback_mode:
            raw = await self._redis.hget("hydra:task_registry", task_id)
            if raw:
                task = Task.from_dict(json.loads(raw))
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()
                task.error = error
                task.retries += 1
                await self._redis.hset("hydra:task_registry", task_id, json.dumps(task.to_dict()))
        else:
            async with self._lock:
                if task_id in self._results:
                    self._results[task_id].status = TaskStatus.FAILED
                    self._results[task_id].error = error
                    self._results[task_id].retries += 1
        
        await self.publish("task_failed", {"task_id": task_id, "error": error})
        logger.warning(f"❌ Task failed: {task_id} — {error}")
    
    async def get_task(self, task_id: str) -> Optional[Task]:
        """Retrieve a task by ID."""
        if self._redis and not self._fallback_mode:
            raw = await self._redis.hget("hydra:task_registry", task_id)
            if raw:
                return Task.from_dict(json.loads(raw))
        else:
            return self._results.get(task_id)
        return None
    
    # ──────────────────────────────────────────
    #  State Store Operations
    # ──────────────────────────────────────────
    
    async def set_state(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set a key-value pair in the global state store."""
        if self._redis and not self._fallback_mode:
            data = json.dumps(value) if not isinstance(value, str) else value
            if ttl:
                await self._redis.setex(f"hydra:state:{key}", ttl, data)
            else:
                await self._redis.set(f"hydra:state:{key}", data)
        else:
            async with self._lock:
                self._state[key] = value
    
    async def get_state(self, key: str, default: Any = None) -> Any:
        """Get a value from the global state store."""
        if self._redis and not self._fallback_mode:
            raw = await self._redis.get(f"hydra:state:{key}")
            if raw:
                try:
                    return json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    return raw
            return default
        else:
            return self._state.get(key, default)
    
    async def append_to_list(self, key: str, value: Any):
        """Append a value to a list in the state store."""
        if self._redis and not self._fallback_mode:
            await self._redis.rpush(f"hydra:list:{key}", json.dumps(value))
        else:
            async with self._lock:
                if key not in self._state:
                    self._state[key] = []
                self._state[key].append(value)
    
    async def get_list(self, key: str) -> List[Any]:
        """Get all values from a list in the state store."""
        if self._redis and not self._fallback_mode:
            raw_list = await self._redis.lrange(f"hydra:list:{key}", 0, -1)
            results = []
            for item in raw_list:
                try:
                    results.append(json.loads(item))
                except (json.JSONDecodeError, TypeError):
                    results.append(item)
            return results
        else:
            return self._state.get(key, [])
    
    # ──────────────────────────────────────────
    #  Pub/Sub Operations
    # ──────────────────────────────────────────
    
    async def publish(self, channel: str, message: Dict[str, Any]):
        """Publish an event to a channel."""
        if self._redis and not self._fallback_mode:
            await self._redis.publish(f"hydra:events:{channel}", json.dumps(message))
        else:
            # Local pub/sub
            handlers = self._pubsub_handlers.get(channel, [])
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(message)
                    else:
                        handler(message)
                except Exception as e:
                    logger.error(f"Pub/sub handler error on '{channel}': {e}")
    
    def subscribe(self, channel: str, handler):
        """Subscribe a handler to a channel (in-memory mode only)."""
        if channel not in self._pubsub_handlers:
            self._pubsub_handlers[channel] = []
        self._pubsub_handlers[channel].append(handler)
    
    # ──────────────────────────────────────────
    #  Metrics & Monitoring
    # ──────────────────────────────────────────
    
    async def get_queue_depths(self) -> Dict[str, int]:
        """Get the depth of each agent task queue."""
        depths = {}
        if self._redis and not self._fallback_mode:
            keys = await self._redis.keys("hydra:tasks:*")
            for key in keys:
                agent_type = key.split(":")[-1]
                depths[agent_type] = await self._redis.zcard(key)
        else:
            for key, queue in self._task_queues.items():
                agent_type = key.split(":")[-1]
                depths[agent_type] = queue.qsize()
        return depths
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get bus-level metrics."""
        return {
            "mode": "redis" if (self._redis and not self._fallback_mode) else "in-memory",
            "queue_depths": await self.get_queue_depths(),
            "total_tasks": len(self._results) if self._fallback_mode else "N/A",
        }
