"""
╔══════════════════════════════════════════════════════════════╗
║  Cost & Token Management — Budget Enforcement & Analytics  ║
║  Smart routing, usage caps, adaptive model downgrading     ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
import threading
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.cost")


@dataclass
class UsageRecord:
    """Single API usage record."""
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost: float
    task_type: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class BudgetConfig:
    """Budget configuration."""
    monthly_cap_usd: float = 100.0
    daily_cap_usd: float = 10.0
    per_scan_cap_usd: float = 5.0
    warning_threshold: float = 0.8  # warn at 80%
    downgrade_threshold: float = 0.9  # downgrade at 90%
    hard_stop_threshold: float = 1.0  # stop at 100%


# Model cost per 1K tokens (input/output)
MODEL_COSTS = {
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "llama3.1:8b": {"input": 0.0, "output": 0.0},
}

# Task → optimal model tier
TASK_MODEL_TIERS = {
    "reasoning": "premium",
    "exploit_hypothesis": "premium",
    "report_generation": "standard",
    "scoring": "economy",
    "classification": "economy",
    "code_analysis": "premium",
    "fast_classification": "local",
}

MODEL_TIERS = {
    "premium": ["claude-sonnet-4-20250514", "gpt-4o"],
    "standard": ["gpt-4o-mini", "claude-3-haiku"],
    "economy": ["gpt-4o-mini", "llama3.1:8b"],
    "local": ["llama3.1:8b"],
}


class CostTracker:
    """
    Enterprise-grade AI cost tracking and budget enforcement.
    
    Features:
      - Token counting per provider/model
      - Cost estimation
      - Budget enforcement (daily/monthly/per-scan)
      - Adaptive model downgrading
      - Smart fallback routing
      - Usage analytics
    """

    def __init__(self, budget: Optional[BudgetConfig] = None):
        self.budget = budget or BudgetConfig()
        self._records: List[UsageRecord] = []
        self._lock = threading.Lock()
        self._scan_costs: Dict[str, float] = {}

    def record_usage(
        self, provider: str, model: str,
        input_tokens: int, output_tokens: int,
        task_type: str = "", scan_id: str = "",
    ) -> float:
        """Record token usage and return estimated cost."""
        costs = MODEL_COSTS.get(model, {"input": 0.001, "output": 0.002})
        cost = (
            (input_tokens / 1000) * costs["input"]
            + (output_tokens / 1000) * costs["output"]
        )

        record = UsageRecord(
            provider=provider, model=model,
            input_tokens=input_tokens, output_tokens=output_tokens,
            cost=cost, task_type=task_type,
        )

        with self._lock:
            self._records.append(record)
            if scan_id:
                self._scan_costs[scan_id] = (
                    self._scan_costs.get(scan_id, 0) + cost
                )

        return cost

    def get_recommended_model(
        self, task_type: str, scan_id: str = ""
    ) -> Optional[str]:
        """Get recommended model based on budget and task type."""
        daily_usage = self._get_daily_cost()
        monthly_usage = self._get_monthly_cost()
        scan_usage = self._scan_costs.get(scan_id, 0)

        # Check hard limits
        if monthly_usage >= self.budget.monthly_cap_usd:
            logger.warning("⛔ Monthly budget exceeded — local only")
            return "llama3.1:8b"

        if daily_usage >= self.budget.daily_cap_usd:
            logger.warning("⛔ Daily budget exceeded — local only")
            return "llama3.1:8b"

        if scan_id and scan_usage >= self.budget.per_scan_cap_usd:
            logger.warning("⛔ Scan budget exceeded — local only")
            return "llama3.1:8b"

        # Check downgrade threshold
        daily_pct = daily_usage / max(self.budget.daily_cap_usd, 0.01)
        if daily_pct >= self.budget.downgrade_threshold:
            tier = "economy"
        elif daily_pct >= self.budget.warning_threshold:
            tier = "standard"
        else:
            tier = TASK_MODEL_TIERS.get(task_type, "standard")

        models = MODEL_TIERS.get(tier, MODEL_TIERS["standard"])
        return models[0] if models else None

    def check_budget(self, scan_id: str = "") -> Dict[str, Any]:
        """Check current budget status."""
        daily = self._get_daily_cost()
        monthly = self._get_monthly_cost()
        scan = self._scan_costs.get(scan_id, 0)

        return {
            "daily_cost": round(daily, 4),
            "daily_cap": self.budget.daily_cap_usd,
            "daily_pct": round(daily / max(self.budget.daily_cap_usd, 0.01) * 100, 1),
            "monthly_cost": round(monthly, 4),
            "monthly_cap": self.budget.monthly_cap_usd,
            "monthly_pct": round(monthly / max(self.budget.monthly_cap_usd, 0.01) * 100, 1),
            "scan_cost": round(scan, 4),
            "scan_cap": self.budget.per_scan_cap_usd,
            "budget_ok": (
                daily < self.budget.daily_cap_usd
                and monthly < self.budget.monthly_cap_usd
            ),
        }

    def _get_daily_cost(self) -> float:
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            return sum(
                r.cost for r in self._records
                if time.strftime("%Y-%m-%d", time.localtime(r.timestamp)) == today
            )

    def _get_monthly_cost(self) -> float:
        month = time.strftime("%Y-%m")
        with self._lock:
            return sum(
                r.cost for r in self._records
                if time.strftime("%Y-%m", time.localtime(r.timestamp)) == month
            )

    def get_analytics(self) -> Dict[str, Any]:
        """Get usage analytics."""
        with self._lock:
            total_cost = sum(r.cost for r in self._records)
            total_input = sum(r.input_tokens for r in self._records)
            total_output = sum(r.output_tokens for r in self._records)

            by_provider: Dict[str, float] = {}
            by_task: Dict[str, float] = {}
            for r in self._records:
                by_provider[r.provider] = by_provider.get(r.provider, 0) + r.cost
                by_task[r.task_type] = by_task.get(r.task_type, 0) + r.cost

            return {
                "total_cost": round(total_cost, 4),
                "total_requests": len(self._records),
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "cost_by_provider": {
                    k: round(v, 4) for k, v in by_provider.items()
                },
                "cost_by_task": {
                    k: round(v, 4) for k, v in by_task.items()
                },
                "budget_status": self.check_budget(),
            }
