"""Small per-run limits enforced independently of model instructions."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import time
import uuid


class RunStopped(RuntimeError):
    def __init__(self, reason, *, status="budget_exhausted"):
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class RunLimits:
    max_steps: int = 30
    max_seconds: int = 600
    max_tool_calls: int = 30
    max_tokens: int | None = None
    max_context_chars: int = 64000
    max_failures: int = 5
    max_repeated_failures: int = 3

    def __post_init__(self):
        for name, maximum in (
            ("max_steps", 200),
            ("max_seconds", 7200),
            ("max_tool_calls", 200),
            ("max_context_chars", 2_000_000),
            ("max_failures", 100),
            ("max_repeated_failures", 100),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be 1..{maximum}")
        if self.max_tokens is not None and (
            type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 100_000_000
        ):
            raise ValueError("max_tokens must be 1..100000000 or unset")


class RunGovernor:
    def __init__(self, limits, initial_usage=None):
        self.limits = limits
        self.started = time.monotonic()
        self.baseline = self.token_count(initial_usage)
        self.last_usage = self.baseline
        self.last_failure = None
        self.repeated = 0
        self.state = {
            "run_id": uuid.uuid4().hex,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "limits": asdict(limits),
            "model_requests": 0,
            "tool_calls": 0,
            "observed_tokens": 0,
            "failures": 0,
            "elapsed_seconds": 0.0,
            "stop_reason": None,
            "token_usage_available": None,
        }

    @staticmethod
    def token_count(usage):
        if not isinstance(usage, dict):
            return None
        values = [usage.get(key) for key in ("input_tokens", "output_tokens")]
        if any(type(value) is not int or value < 0 for value in values):
            return None
        return sum(values)

    def remaining(self):
        elapsed = time.monotonic() - self.started
        self.state["elapsed_seconds"] = round(elapsed, 3)
        remaining = self.limits.max_seconds - elapsed
        if remaining <= 0:
            raise RunStopped("max_seconds")
        return remaining

    def before_model(self, prompt):
        self.remaining()
        if self.state["model_requests"] >= self.limits.max_steps:
            raise RunStopped("max_steps")
        if self.state["tool_calls"] >= self.limits.max_tool_calls:
            raise RunStopped("max_tool_calls")
        if len(prompt) > self.limits.max_context_chars:
            raise RunStopped("max_context_chars")
        if self.limits.max_tokens is not None:
            if self.baseline is None:
                raise RunStopped("token_usage_unavailable", status="blocked")
            if self.state["observed_tokens"] >= self.limits.max_tokens:
                raise RunStopped("max_tokens")
        self.state["model_requests"] += 1

    def observe_usage(self, usage, *, usage_available=None):
        tokens = self.token_count(usage)
        valid = usage_available is not False
        if tokens is not None and self.baseline is not None and tokens >= self.last_usage:
            self.state["observed_tokens"] = tokens - self.baseline
            self.last_usage = tokens
        else:
            valid = False
        if self.state["token_usage_available"] is not False:
            self.state["token_usage_available"] = valid
        return valid

    def after_model(self, usage, *, usage_available=None):
        self.observe_usage(usage, usage_available=usage_available)
        self.remaining()
        if self.limits.max_tokens is not None:
            if not self.state["token_usage_available"]:
                raise RunStopped("token_usage_unavailable", status="blocked")
            if self.state["observed_tokens"] >= self.limits.max_tokens:
                raise RunStopped("max_tokens")

    def before_tool(self):
        self.remaining()
        if self.state["tool_calls"] >= self.limits.max_tool_calls:
            raise RunStopped("max_tool_calls")
        self.state["tool_calls"] += 1

    def result(self, action, success):
        if success:
            self.last_failure = None
            self.repeated = 0
            return
        self.state["failures"] += 1
        signature = json.dumps(action, sort_keys=True, ensure_ascii=False)
        self.repeated = self.repeated + 1 if signature == self.last_failure else 1
        self.last_failure = signature
        if self.state["failures"] >= self.limits.max_failures:
            raise RunStopped("max_failures", status="blocked")
        if self.repeated >= self.limits.max_repeated_failures:
            raise RunStopped("repeated_failure", status="blocked")
