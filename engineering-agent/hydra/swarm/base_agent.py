"""
╔══════════════════════════════════════════════════════════════╗
║  Base Agent — Abstract Foundation for All Swarm Agents      ║
║  Stateless by design; all state flows through MemoryBus     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import logging
import time
import traceback
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from hydra.memory.bus import MemoryBus, Task, TaskStatus

logger = logging.getLogger("hydra.swarm.agent")


class BaseAgent(ABC):
    """
    Abstract base class for all HYDRA swarm agents.
    
    Contract:
      - Agents are STATELESS. No instance variables should persist across tasks.
      - All communication goes through the MemoryBus — NEVER direct agent-to-agent.
      - The Coordinator is the ONLY orchestrator.
      - execute() is the single entry point for task processing.
    """
    
    # Override in subclass
    AGENT_TYPE: str = "base"
    AGENT_NAME: str = "Base Agent"
    
    def __init__(self, bus: MemoryBus, agent_id: Optional[str] = None):
        self.bus = bus
        self.agent_id = agent_id or f"{self.AGENT_TYPE}-{id(self)}"
        self._running = False
        self._tasks_processed = 0
        self._tasks_failed = 0
        self._total_time = 0.0
        self.logger = logging.getLogger(f"hydra.agent.{self.AGENT_TYPE}")
    
    @abstractmethod
    async def execute(self, task: Task) -> Dict[str, Any]:
        """
        Execute a single task. Must be implemented by every agent.
        
        Args:
            task: The task pulled from the memory bus.
            
        Returns:
            Dict with results to be stored back in the bus.
            
        Raises:
            Exception: On unrecoverable failure.
        """
        raise NotImplementedError
    
    async def run(self):
        """Main agent loop — pull tasks, execute, report results."""
        self._running = True
        self.logger.info(f"🚀 Agent started: {self.AGENT_NAME} ({self.agent_id})")
        
        while self._running:
            try:
                # Pull next task from the bus
                task = await self.bus.pull_task(self.AGENT_TYPE)
                
                if task is None:
                    await asyncio.sleep(0.5)
                    continue
                
                # Update agent status on the bus
                await self.bus.set_state(
                    f"agent_status:{self.agent_id}",
                    {"status": "busy", "task_id": task.id, "since": time.time()}
                )
                
                # Execute with timing
                start = time.time()
                try:
                    task.status = TaskStatus.RUNNING
                    result = await asyncio.wait_for(
                        self.execute(task),
                        timeout=task.metadata.get("timeout", 300)
                    )
                    elapsed = time.time() - start
                    self._tasks_processed += 1
                    self._total_time += elapsed
                    
                    # Report success
                    await self.bus.complete_task(task.id, result)
                    self.logger.info(
                        f"✅ {self.AGENT_NAME} completed task {task.id[:8]}… "
                        f"in {elapsed:.1f}s"
                    )
                    
                except asyncio.TimeoutError:
                    elapsed = time.time() - start
                    self._tasks_failed += 1
                    await self.bus.fail_task(task.id, f"Timeout after {elapsed:.1f}s")
                    self.logger.warning(f"⏰ Task {task.id[:8]}… timed out")
                    
                except Exception as e:
                    elapsed = time.time() - start
                    self._tasks_failed += 1
                    tb = traceback.format_exc()
                    await self.bus.fail_task(task.id, f"{type(e).__name__}: {e}\n{tb}")
                    self.logger.error(f"💥 Task {task.id[:8]}… failed: {e}")
                
                finally:
                    # Update agent status back to idle
                    await self.bus.set_state(
                        f"agent_status:{self.agent_id}",
                        {"status": "idle", "since": time.time()}
                    )
                    
            except asyncio.CancelledError:
                self.logger.info(f"Agent {self.agent_id} cancelled")
                break
            except Exception as e:
                self.logger.error(f"Agent loop error: {e}")
                await asyncio.sleep(1)
        
        self.logger.info(
            f"🛑 Agent stopped: {self.AGENT_NAME} — "
            f"processed={self._tasks_processed} failed={self._tasks_failed}"
        )
    
    async def stop(self):
        """Gracefully stop the agent."""
        self._running = False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Return agent performance metrics."""
        avg_time = (self._total_time / self._tasks_processed) if self._tasks_processed else 0
        return {
            "agent_id": self.agent_id,
            "agent_type": self.AGENT_TYPE,
            "tasks_processed": self._tasks_processed,
            "tasks_failed": self._tasks_failed,
            "average_task_time": round(avg_time, 3),
            "running": self._running,
        }
