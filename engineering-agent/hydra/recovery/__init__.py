"""
╔══════════════════════════════════════════════════════════════╗
║  Workflow Recovery — Checkpointing & Auto-Recovery         ║
║  Retry orchestration, state restoration, degraded mode     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.recovery")


@dataclass
class Checkpoint:
    """Workflow checkpoint for state restoration."""
    checkpoint_id: str
    scan_id: str
    phase: str
    state: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class FailureClassifier:
    """Classify failures to determine recovery strategy."""

    TRANSIENT_ERRORS = [
        "timeout", "connection reset", "temporary",
        "rate limit", "503", "429", "econnrefused",
    ]
    PERMANENT_ERRORS = [
        "not found", "permission denied", "invalid",
        "authentication failed", "403", "401",
    ]

    def classify(self, error: str) -> str:
        """Classify an error as transient or permanent."""
        error_lower = error.lower()
        for pattern in self.TRANSIENT_ERRORS:
            if pattern in error_lower:
                return "transient"
        for pattern in self.PERMANENT_ERRORS:
            if pattern in error_lower:
                return "permanent"
        return "unknown"

    def get_retry_delay(self, attempt: int,
                        error_type: str) -> float:
        """Get retry delay with exponential backoff."""
        if error_type == "permanent":
            return -1  # Don't retry
        base_delay = 2.0
        max_delay = 120.0
        delay = min(base_delay * (2 ** attempt), max_delay)
        return delay


class WorkflowRecovery:
    """
    Autonomous workflow recovery system.
    
    Features:
      - Workflow checkpointing
      - State restoration from checkpoints
      - Failure classification
      - Retry orchestration with backoff
      - Partial task replay
      - Degraded operation mode
      - Recovery policies
    """

    def __init__(self, checkpoint_dir: Optional[str] = None):
        self._checkpoint_dir = Path(checkpoint_dir or "data/checkpoints")
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoints: Dict[str, Checkpoint] = {}
        self._classifier = FailureClassifier()
        self._recovery_log: List[Dict[str, Any]] = []
        self._degraded_mode = False

    async def save_checkpoint(
        self, scan_id: str, phase: str,
        state: Dict[str, Any],
    ) -> str:
        """Save a workflow checkpoint."""
        cp_id = f"cp-{scan_id}-{phase}-{int(time.time())}"
        checkpoint = Checkpoint(
            checkpoint_id=cp_id, scan_id=scan_id,
            phase=phase, state=state,
        )

        self._checkpoints[cp_id] = checkpoint

        # Persist to disk
        cp_file = self._checkpoint_dir / f"{cp_id}.json"
        cp_file.write_text(
            json.dumps({
                "checkpoint_id": cp_id, "scan_id": scan_id,
                "phase": phase, "state": state,
                "timestamp": checkpoint.timestamp,
            }, indent=2, default=str),
            encoding="utf-8",
        )

        logger.info(f"💾 Checkpoint saved: {cp_id}")
        return cp_id

    async def restore_checkpoint(
        self, checkpoint_id: str
    ) -> Optional[Dict[str, Any]]:
        """Restore state from a checkpoint."""
        # Try memory first
        cp = self._checkpoints.get(checkpoint_id)
        if cp:
            logger.info(f"🔄 Restored from memory: {checkpoint_id}")
            return cp.state

        # Try disk
        cp_file = self._checkpoint_dir / f"{checkpoint_id}.json"
        if cp_file.exists():
            data = json.loads(cp_file.read_text(encoding="utf-8"))
            logger.info(f"🔄 Restored from disk: {checkpoint_id}")
            return data.get("state", {})

        logger.warning(f"Checkpoint not found: {checkpoint_id}")
        return None

    async def get_latest_checkpoint(
        self, scan_id: str
    ) -> Optional[Checkpoint]:
        """Get the most recent checkpoint for a scan."""
        candidates = [
            cp for cp in self._checkpoints.values()
            if cp.scan_id == scan_id
        ]
        if candidates:
            return max(candidates, key=lambda c: c.timestamp)

        # Check disk
        latest = None
        latest_time = 0
        for cp_file in self._checkpoint_dir.glob(f"cp-{scan_id}-*.json"):
            data = json.loads(cp_file.read_text(encoding="utf-8"))
            ts = data.get("timestamp", 0)
            if ts > latest_time:
                latest_time = ts
                latest = Checkpoint(
                    checkpoint_id=data["checkpoint_id"],
                    scan_id=data["scan_id"],
                    phase=data["phase"],
                    state=data["state"],
                    timestamp=ts,
                )
        return latest

    async def handle_failure(
        self, scan_id: str, task_id: str, error: str,
        attempt: int = 1,
    ) -> Dict[str, Any]:
        """Handle a task failure with recovery logic."""
        error_type = self._classifier.classify(error)
        retry_delay = self._classifier.get_retry_delay(attempt, error_type)

        recovery_action = {
            "task_id": task_id, "error_type": error_type,
            "attempt": attempt, "timestamp": time.time(),
        }

        if error_type == "permanent":
            recovery_action["action"] = "skip"
            recovery_action["reason"] = "Permanent failure — skipping"
            logger.warning(f"⏭️ Permanent failure, skipping: {task_id}")
        elif attempt >= 5:
            recovery_action["action"] = "abandon"
            recovery_action["reason"] = "Max retries exceeded"
            logger.error(f"🛑 Max retries exceeded: {task_id}")
        else:
            recovery_action["action"] = "retry"
            recovery_action["delay"] = retry_delay
            recovery_action["reason"] = f"Transient failure, retry in {retry_delay}s"
            logger.info(
                f"🔄 Will retry {task_id} in {retry_delay}s "
                f"(attempt {attempt})"
            )

        self._recovery_log.append(recovery_action)
        return recovery_action

    def enter_degraded_mode(self, reason: str):
        """Enter degraded operation mode."""
        self._degraded_mode = True
        logger.warning(f"⚠️ Entering degraded mode: {reason}")
        self._recovery_log.append({
            "action": "degraded_mode",
            "reason": reason,
            "timestamp": time.time(),
        })

    def exit_degraded_mode(self):
        self._degraded_mode = False
        logger.info("✅ Exiting degraded mode")

    @property
    def is_degraded(self) -> bool:
        return self._degraded_mode

    def get_recovery_summary(self) -> Dict[str, Any]:
        total = len(self._recovery_log)
        retries = sum(1 for r in self._recovery_log if r.get("action") == "retry")
        skipped = sum(1 for r in self._recovery_log if r.get("action") == "skip")
        abandoned = sum(1 for r in self._recovery_log if r.get("action") == "abandon")
        return {
            "total_recoveries": total,
            "retries": retries, "skipped": skipped,
            "abandoned": abandoned,
            "degraded_mode": self._degraded_mode,
            "checkpoints": len(self._checkpoints),
        }
