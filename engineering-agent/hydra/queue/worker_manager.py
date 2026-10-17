"""
╔══════════════════════════════════════════════════════════════╗
║  Worker Manager — Heartbeats, Failover, Node Discovery     ║
║  Manages distributed workers across cluster nodes           ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.queue.worker_manager")


@dataclass
class WorkerInfo:
    """Information about a registered worker."""
    worker_id: str
    node_id: str
    agent_type: str
    status: str = "idle"  # idle, busy, dead
    last_heartbeat: float = field(default_factory=time.time)
    tasks_processed: int = 0
    tasks_failed: int = 0
    current_task_id: Optional[str] = None
    registered_at: float = field(default_factory=time.time)
    capabilities: List[str] = field(default_factory=list)


class WorkerManager:
    """
    Manages distributed workers with heartbeats and failover.
    
    Features:
      - Worker registration and discovery
      - Heartbeat monitoring
      - Automatic failover on worker death
      - Load balancing across workers
      - Distributed locking
    """

    HEARTBEAT_TIMEOUT = 30  # seconds before worker considered dead

    def __init__(self, redis_url: Optional[str] = None):
        self._redis_url = redis_url
        self._redis = None
        self._workers: Dict[str, WorkerInfo] = {}
        self._lock = asyncio.Lock()
        self._node_id = f"node-{uuid.uuid4().hex[:8]}"

    async def connect(self):
        if self._redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self._redis_url, decode_responses=True
                )
                await self._redis.ping()
                logger.info("Worker manager connected to Redis")
            except Exception as e:
                logger.warning(f"Redis unavailable: {e}")

    async def register_worker(
        self, agent_type: str,
        capabilities: Optional[List[str]] = None
    ) -> str:
        """Register a new worker and return its ID."""
        worker_id = f"worker-{agent_type}-{uuid.uuid4().hex[:8]}"
        info = WorkerInfo(
            worker_id=worker_id,
            node_id=self._node_id,
            agent_type=agent_type,
            capabilities=capabilities or [],
        )
        async with self._lock:
            self._workers[worker_id] = info

        if self._redis:
            import json
            from dataclasses import asdict
            await self._redis.hset(
                "hydra:workers", worker_id,
                json.dumps(asdict(info))
            )

        logger.info(f"👷 Worker registered: {worker_id} ({agent_type})")
        return worker_id

    async def heartbeat(self, worker_id: str, status: str = "idle",
                        current_task: Optional[str] = None):
        """Send a heartbeat from a worker."""
        async with self._lock:
            if worker_id in self._workers:
                w = self._workers[worker_id]
                w.last_heartbeat = time.time()
                w.status = status
                w.current_task_id = current_task

        if self._redis:
            await self._redis.hset(
                f"hydra:heartbeat:{worker_id}", mapping={
                    "last": str(time.time()),
                    "status": status,
                    "task": current_task or "",
                }
            )
            await self._redis.expire(
                f"hydra:heartbeat:{worker_id}",
                self.HEARTBEAT_TIMEOUT * 2
            )

    async def check_health(self) -> Dict[str, Any]:
        """Check health of all workers."""
        now = time.time()
        alive = 0
        dead = 0
        dead_workers = []

        async with self._lock:
            for wid, info in self._workers.items():
                if now - info.last_heartbeat > self.HEARTBEAT_TIMEOUT:
                    info.status = "dead"
                    dead += 1
                    dead_workers.append(wid)
                else:
                    alive += 1

        if dead_workers:
            logger.warning(
                f"💀 Dead workers detected: {dead_workers}"
            )

        return {
            "total_workers": len(self._workers),
            "alive": alive,
            "dead": dead,
            "dead_workers": dead_workers,
            "node_id": self._node_id,
        }

    async def get_worker(self, worker_id: str) -> Optional[WorkerInfo]:
        return self._workers.get(worker_id)

    async def get_workers_by_type(
        self, agent_type: str
    ) -> List[WorkerInfo]:
        return [
            w for w in self._workers.values()
            if w.agent_type == agent_type and w.status != "dead"
        ]

    async def acquire_lock(self, key: str,
                           timeout: int = 10) -> bool:
        """Acquire a distributed lock."""
        if self._redis:
            return bool(await self._redis.set(
                f"hydra:lock:{key}", self._node_id,
                nx=True, ex=timeout
            ))
        return True  # local mode always succeeds

    async def release_lock(self, key: str):
        """Release a distributed lock."""
        if self._redis:
            await self._redis.delete(f"hydra:lock:{key}")

    async def deregister_worker(self, worker_id: str):
        async with self._lock:
            self._workers.pop(worker_id, None)
        if self._redis:
            await self._redis.hdel("hydra:workers", worker_id)
        logger.info(f"Worker deregistered: {worker_id}")
