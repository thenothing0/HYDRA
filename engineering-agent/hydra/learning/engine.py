"""
╔══════════════════════════════════════════════════════════════╗
║  Self-Learning Engine — Continuous Improvement System       ║
║  Tracks past results, rewards/penalizes, adapts routing     ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import sqlite3
import time
import threading
from typing import Any, Dict, List, Optional
from pathlib import Path

from hydra.config import get_config

logger = logging.getLogger("hydra.learning.engine")


class LearningEngine:
    """
    Self-learning feedback loop that continuously improves scan accuracy.
    
    Tracks:
      - Tool effectiveness per target type
      - Template/rule success rates
      - False positive rates by finding type
      - Agent performance over time
      
    Adapts:
      - Routing priorities based on past success
      - Confidence thresholds per finding type
      - Tool selection preferences
    """
    
    def __init__(self, db_path: Optional[str] = None):
        config = get_config()
        self.db_path = db_path or config.learning.db_path
        self.config = config.learning
        self._lock = threading.Lock()
        self._initialized = False
    
    def initialize(self):
        """Create the learning database schema."""
        if self._initialized:
            return
        
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        template_id TEXT,
                        severity TEXT,
                        confidence REAL,
                        is_true_positive INTEGER DEFAULT -1,
                        tool_used TEXT,
                        elapsed REAL,
                        created_at REAL NOT NULL
                    );
                    
                    CREATE TABLE IF NOT EXISTS tool_performance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool_name TEXT NOT NULL,
                        target_type TEXT,
                        success INTEGER NOT NULL,
                        elapsed REAL,
                        findings_count INTEGER DEFAULT 0,
                        created_at REAL NOT NULL
                    );
                    
                    CREATE TABLE IF NOT EXISTS agent_performance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_type TEXT NOT NULL,
                        task_type TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        elapsed REAL,
                        error TEXT,
                        created_at REAL NOT NULL
                    );
                    
                    CREATE TABLE IF NOT EXISTS routing_weights (
                        key TEXT PRIMARY KEY,
                        weight REAL NOT NULL,
                        samples INTEGER DEFAULT 0,
                        updated_at REAL NOT NULL
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_scan_results_type
                        ON scan_results(finding_type);
                    CREATE INDEX IF NOT EXISTS idx_scan_results_template
                        ON scan_results(template_id);
                    CREATE INDEX IF NOT EXISTS idx_tool_perf_name
                        ON tool_performance(tool_name);
                    CREATE INDEX IF NOT EXISTS idx_agent_perf_type
                        ON agent_performance(agent_type);
                """)
                conn.commit()
            finally:
                conn.close()
        
        self._initialized = True
        logger.info("🧠 Learning engine initialized")
    
    def _conn(self) -> sqlite3.Connection:
        """Get a thread-safe database connection."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    
    # ──────────────────────────────────────────
    #  Record Events
    # ──────────────────────────────────────────
    
    def record_finding(
        self,
        scan_id: str,
        target: str,
        finding_type: str,
        template_id: str = "",
        severity: str = "info",
        confidence: float = 0.5,
        tool_used: str = "",
        elapsed: float = 0.0,
        is_true_positive: int = -1,
    ):
        """Record a scan finding for learning."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO scan_results
                       (scan_id, target, finding_type, template_id, severity,
                        confidence, is_true_positive, tool_used, elapsed, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, target, finding_type, template_id, severity,
                     confidence, is_true_positive, tool_used, elapsed, time.time()),
                )
                conn.commit()
            finally:
                conn.close()
    
    def record_tool_execution(
        self,
        tool_name: str,
        success: bool,
        elapsed: float = 0.0,
        findings_count: int = 0,
        target_type: str = "web",
    ):
        """Record a tool execution result."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO tool_performance
                       (tool_name, target_type, success, elapsed, findings_count, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (tool_name, target_type, int(success), elapsed, findings_count, time.time()),
                )
                conn.commit()
            finally:
                conn.close()
    
    def record_agent_task(
        self,
        agent_type: str,
        task_type: str,
        success: bool,
        elapsed: float = 0.0,
        error: str = "",
    ):
        """Record an agent task result."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """INSERT INTO agent_performance
                       (agent_type, task_type, success, elapsed, error, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (agent_type, task_type, int(success), elapsed, error, time.time()),
                )
                conn.commit()
            finally:
                conn.close()
    
    def mark_true_positive(self, scan_id: str, template_id: str, is_tp: bool):
        """Mark a finding as true/false positive (feedback loop)."""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """UPDATE scan_results SET is_true_positive = ?
                       WHERE scan_id = ? AND template_id = ?""",
                    (int(is_tp), scan_id, template_id),
                )
                conn.commit()
                
                # Update routing weight
                self._update_weight(conn, f"template:{template_id}",
                                    self.config.reward_success if is_tp
                                    else self.config.penalty_false_positive)
                conn.commit()
            finally:
                conn.close()
    
    def _update_weight(self, conn: sqlite3.Connection, key: str, reward: float):
        """Update a routing weight with exponential decay."""
        row = conn.execute(
            "SELECT weight, samples FROM routing_weights WHERE key = ?", (key,)
        ).fetchone()
        
        if row:
            old_weight = row["weight"]
            samples = row["samples"] + 1
            new_weight = (old_weight * self.config.decay_factor +
                         reward * self.config.learning_rate)
            conn.execute(
                """UPDATE routing_weights SET weight = ?, samples = ?, updated_at = ?
                   WHERE key = ?""",
                (new_weight, samples, time.time(), key),
            )
        else:
            conn.execute(
                """INSERT INTO routing_weights (key, weight, samples, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (key, 0.5 + reward * self.config.learning_rate, 1, time.time()),
            )
    
    # ──────────────────────────────────────────
    #  Query Learning Data
    # ──────────────────────────────────────────
    
    async def get_historical_accuracy(self, finding_type: str) -> Optional[float]:
        """Get historical accuracy for a finding type."""
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         SUM(CASE WHEN is_true_positive = 1 THEN 1 ELSE 0 END) as tp
                       FROM scan_results
                       WHERE (finding_type = ? OR template_id = ?)
                         AND is_true_positive >= 0""",
                    (finding_type, finding_type),
                ).fetchone()
                
                if row and row["total"] >= self.config.min_samples_to_learn:
                    return row["tp"] / row["total"]
                return None
            finally:
                conn.close()
    
    def get_tool_effectiveness(self, tool_name: str) -> Dict[str, float]:
        """Get effectiveness stats for a tool."""
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    """SELECT
                         COUNT(*) as total,
                         SUM(success) as successes,
                         AVG(elapsed) as avg_time,
                         AVG(findings_count) as avg_findings
                       FROM tool_performance WHERE tool_name = ?""",
                    (tool_name,),
                ).fetchone()
                
                if row and row["total"] > 0:
                    return {
                        "total_runs": row["total"],
                        "success_rate": row["successes"] / row["total"],
                        "avg_time": round(row["avg_time"], 2),
                        "avg_findings": round(row["avg_findings"] or 0, 1),
                    }
                return {"total_runs": 0, "success_rate": 0, "avg_time": 0, "avg_findings": 0}
            finally:
                conn.close()
    
    def get_routing_weight(self, key: str) -> float:
        """Get a routing weight (for adaptive decisions)."""
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT weight FROM routing_weights WHERE key = ?", (key,)
                ).fetchone()
                return row["weight"] if row else 0.5
            finally:
                conn.close()
    
    def export_labelled_findings(self) -> List[Dict[str, Any]]:
        """Return labelled scan_results rows for ML training.

        Only rows with a decided label (is_true_positive in {0,1}) are
        returned. Each dict is shaped like a finding plus an `is_true_positive`
        key, ready for FalsePositiveClassifier.train().
        """
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    """SELECT target, finding_type, template_id, severity,
                              confidence, tool_used, is_true_positive
                       FROM scan_results
                       WHERE is_true_positive IN (0, 1)"""
                ).fetchall()
            finally:
                conn.close()
        return [
            {
                "name": r["finding_type"],
                "type": r["finding_type"],
                "template_id": r["template_id"],
                "severity": r["severity"],
                "confidence": r["confidence"],
                "tool_used": r["tool_used"],
                "is_true_positive": r["is_true_positive"],
            }
            for r in rows
        ]

    def train_fp_classifier(self) -> Dict[str, Any]:
        """Train the PyTorch false-positive classifier on recorded feedback."""
        from hydra.ml import FalsePositiveClassifier
        samples = [(f, f["is_true_positive"]) for f in self.export_labelled_findings()]
        return FalsePositiveClassifier().train(samples)

    def get_summary(self) -> Dict[str, Any]:
        """Get a learning engine summary."""
        with self._lock:
            conn = self._conn()
            try:
                findings_count = conn.execute(
                    "SELECT COUNT(*) as c FROM scan_results"
                ).fetchone()["c"]
                tool_count = conn.execute(
                    "SELECT COUNT(DISTINCT tool_name) as c FROM tool_performance"
                ).fetchone()["c"]
                weight_count = conn.execute(
                    "SELECT COUNT(*) as c FROM routing_weights"
                ).fetchone()["c"]
                
                return {
                    "total_findings_recorded": findings_count,
                    "tools_tracked": tool_count,
                    "routing_weights": weight_count,
                    "db_path": self.db_path,
                }
            finally:
                conn.close()
