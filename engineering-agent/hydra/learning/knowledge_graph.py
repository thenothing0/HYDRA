"""
╔══════════════════════════════════════════════════════════════╗
║  Knowledge Graph — Learning Correlation Engine             ║
║  Correlates methodologies, tool sequences, exploit paths   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
import sqlite3
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("hydra.learning.knowledge_graph")


class KnowledgeGraph:
    """
    Knowledge graph that learns from scan results.
    
    Learns:
      - Which workflows produce valid findings
      - Which tools perform best on target types
      - Which exploit paths are high-confidence
      - Effective tool sequences
      - High-value recon paths
      
    Uses this knowledge for adaptive scan optimization.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "data/knowledge_graph.db"
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False

    def initialize(self):
        """Create the knowledge graph schema."""
        if self._initialized:
            return

        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS workflow_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_name TEXT NOT NULL,
                    target_type TEXT,
                    steps_json TEXT,
                    findings_count INTEGER DEFAULT 0,
                    valid_findings INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    success_score REAL DEFAULT 0.0,
                    duration REAL DEFAULT 0.0,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_sequences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence_json TEXT NOT NULL,
                    target_type TEXT,
                    findings_produced INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0,
                    avg_duration REAL DEFAULT 0.0,
                    usage_count INTEGER DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS exploit_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT NOT NULL,
                    vuln_type TEXT,
                    chain_json TEXT,
                    confidence REAL DEFAULT 0.5,
                    times_validated INTEGER DEFAULT 0,
                    times_failed INTEGER DEFAULT 0,
                    target_tech TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS target_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT NOT NULL,
                    technology_stack TEXT,
                    effective_tools TEXT,
                    common_vulns TEXT,
                    scan_count INTEGER DEFAULT 1,
                    last_scan REAL,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_workflow_name
                    ON workflow_outcomes(workflow_name);
                CREATE INDEX IF NOT EXISTS idx_exploit_vuln
                    ON exploit_patterns(vuln_type);
                CREATE INDEX IF NOT EXISTS idx_target_domain
                    ON target_profiles(target_domain);
            """)
            conn.commit()
        finally:
            conn.close()

        self._initialized = True
        logger.info("🧠 Knowledge graph initialized")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def record_workflow_outcome(
        self, workflow_name: str, steps: List[str],
        findings_count: int, valid_findings: int,
        false_positives: int, duration: float,
        target_type: str = "web",
    ):
        """Record the outcome of a workflow execution."""
        if not self._initialized:
            self.initialize()

        success_score = (
            valid_findings / max(findings_count, 1)
            if findings_count > 0 else 0.0
        )

        conn = self._conn()
        try:
            conn.execute(
                """INSERT INTO workflow_outcomes
                   (workflow_name, target_type, steps_json,
                    findings_count, valid_findings, false_positives,
                    success_score, duration, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (workflow_name, target_type, json.dumps(steps),
                 findings_count, valid_findings, false_positives,
                 success_score, duration, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def record_tool_sequence(
        self, sequence: List[str], target_type: str,
        findings_produced: int, success_rate: float,
        duration: float,
    ):
        """Record an effective tool sequence."""
        if not self._initialized:
            self.initialize()

        seq_json = json.dumps(sequence)
        conn = self._conn()
        try:
            existing = conn.execute(
                "SELECT id, usage_count FROM tool_sequences WHERE sequence_json = ?",
                (seq_json,),
            ).fetchone()

            if existing:
                conn.execute(
                    """UPDATE tool_sequences
                       SET usage_count = usage_count + 1,
                           findings_produced = ?,
                           success_rate = ?,
                           avg_duration = ?,
                           updated_at = ?
                       WHERE id = ?""",
                    (findings_produced, success_rate, duration,
                     time.time(), existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO tool_sequences
                       (sequence_json, target_type, findings_produced,
                        success_rate, avg_duration, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (seq_json, target_type, findings_produced,
                     success_rate, duration, time.time(), time.time()),
                )
            conn.commit()
        finally:
            conn.close()

    def record_exploit_pattern(
        self, pattern_name: str, vuln_type: str,
        chain: List[str], confidence: float,
        validated: bool, target_tech: str = "",
    ):
        """Record an exploit pattern outcome."""
        if not self._initialized:
            self.initialize()

        conn = self._conn()
        try:
            existing = conn.execute(
                "SELECT id, times_validated, times_failed FROM exploit_patterns WHERE pattern_name = ? AND vuln_type = ?",
                (pattern_name, vuln_type),
            ).fetchone()

            if existing:
                if validated:
                    conn.execute(
                        "UPDATE exploit_patterns SET times_validated = times_validated + 1, confidence = ?, updated_at = ? WHERE id = ?",
                        (confidence, time.time(), existing["id"]),
                    )
                else:
                    conn.execute(
                        "UPDATE exploit_patterns SET times_failed = times_failed + 1, updated_at = ? WHERE id = ?",
                        (time.time(), existing["id"]),
                    )
            else:
                conn.execute(
                    """INSERT INTO exploit_patterns
                       (pattern_name, vuln_type, chain_json, confidence,
                        times_validated, times_failed, target_tech,
                        created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (pattern_name, vuln_type, json.dumps(chain),
                     confidence, 1 if validated else 0,
                     0 if validated else 1, target_tech,
                     time.time(), time.time()),
                )
            conn.commit()
        finally:
            conn.close()

    def get_best_workflow(
        self, target_type: str = "web"
    ) -> Optional[Dict[str, Any]]:
        """Get the best performing workflow for a target type."""
        if not self._initialized:
            self.initialize()

        conn = self._conn()
        try:
            row = conn.execute(
                """SELECT workflow_name, AVG(success_score) as avg_score,
                          SUM(valid_findings) as total_valid,
                          COUNT(*) as runs
                   FROM workflow_outcomes
                   WHERE target_type = ?
                   GROUP BY workflow_name
                   HAVING runs >= 2
                   ORDER BY avg_score DESC
                   LIMIT 1""",
                (target_type,),
            ).fetchone()

            if row:
                return {
                    "workflow": row["workflow_name"],
                    "avg_score": round(row["avg_score"], 4),
                    "total_valid_findings": row["total_valid"],
                    "runs": row["runs"],
                }
            return None
        finally:
            conn.close()

    def get_best_tool_sequence(
        self, target_type: str = "web"
    ) -> Optional[List[str]]:
        """Get the best performing tool sequence."""
        if not self._initialized:
            self.initialize()

        conn = self._conn()
        try:
            row = conn.execute(
                """SELECT sequence_json, success_rate
                   FROM tool_sequences
                   WHERE target_type = ?
                   ORDER BY success_rate DESC, usage_count DESC
                   LIMIT 1""",
                (target_type,),
            ).fetchone()

            if row:
                return json.loads(row["sequence_json"])
            return None
        finally:
            conn.close()

    def get_high_confidence_patterns(
        self, min_confidence: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Get exploit patterns with high validation confidence."""
        if not self._initialized:
            self.initialize()

        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT pattern_name, vuln_type, chain_json,
                          confidence, times_validated, times_failed
                   FROM exploit_patterns
                   WHERE confidence >= ?
                   ORDER BY confidence DESC, times_validated DESC
                   LIMIT 20""",
                (min_confidence,),
            ).fetchall()

            return [
                {
                    "pattern": row["pattern_name"],
                    "vuln_type": row["vuln_type"],
                    "chain": json.loads(row["chain_json"]),
                    "confidence": row["confidence"],
                    "validated": row["times_validated"],
                    "failed": row["times_failed"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def get_summary(self) -> Dict[str, Any]:
        """Get knowledge graph summary."""
        if not self._initialized:
            self.initialize()

        conn = self._conn()
        try:
            workflows = conn.execute(
                "SELECT COUNT(*) as c FROM workflow_outcomes"
            ).fetchone()["c"]
            sequences = conn.execute(
                "SELECT COUNT(*) as c FROM tool_sequences"
            ).fetchone()["c"]
            patterns = conn.execute(
                "SELECT COUNT(*) as c FROM exploit_patterns"
            ).fetchone()["c"]
            profiles = conn.execute(
                "SELECT COUNT(*) as c FROM target_profiles"
            ).fetchone()["c"]

            return {
                "workflow_outcomes_recorded": workflows,
                "tool_sequences_tracked": sequences,
                "exploit_patterns_learned": patterns,
                "target_profiles": profiles,
            }
        finally:
            conn.close()
