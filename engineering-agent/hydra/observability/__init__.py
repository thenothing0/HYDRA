"""
╔══════════════════════════════════════════════════════════════╗
║  Observability — Prometheus Metrics, Tracing, Health       ║
║  Full production monitoring stack integration              ║
╚══════════════════════════════════════════════════════════════╝
"""

import logging
import time
import threading
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("hydra.observability")


class MetricsCollector:
    """
    Prometheus-compatible metrics collector.
    
    Tracks: scan duration, model latency, tool success rate,
    false positive rate, agent health, queue depths.
    """

    def __init__(self):
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def inc_counter(self, name: str, value: float = 1.0,
                    labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float,
                  labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe_histogram(self, name: str, value: float,
                          labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)

    def _make_key(self, name: str,
                  labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus exposition format."""
        lines = []
        with self._lock:
            for key, val in self._counters.items():
                lines.append(f"hydra_{key} {val}")
            for key, val in self._gauges.items():
                lines.append(f"hydra_{key} {val}")
            for key, values in self._histograms.items():
                if values:
                    avg = sum(values) / len(values)
                    lines.append(f"hydra_{key}_count {len(values)}")
                    lines.append(f"hydra_{key}_sum {sum(values):.4f}")
                    lines.append(f"hydra_{key}_avg {avg:.4f}")
        return "\n".join(lines)

    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    k: {
                        "count": len(v),
                        "sum": round(sum(v), 4),
                        "avg": round(sum(v) / len(v), 4) if v else 0,
                        "min": round(min(v), 4) if v else 0,
                        "max": round(max(v), 4) if v else 0,
                    }
                    for k, v in self._histograms.items()
                },
            }


class HealthMonitor:
    """Monitor health of all HYDRA subsystems."""

    def __init__(self):
        self._checks: Dict[str, Dict[str, Any]] = {}
        self._start_time = time.time()

    def register_check(self, name: str, check_fn):
        """Register a health check function."""
        self._checks[name] = {"fn": check_fn, "last_result": None}

    async def run_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {}
        overall_healthy = True

        for name, check in self._checks.items():
            try:
                import asyncio
                if asyncio.iscoroutinefunction(check["fn"]):
                    result = await check["fn"]()
                else:
                    result = check["fn"]()
                results[name] = {
                    "healthy": True, "details": result,
                }
            except Exception as e:
                results[name] = {
                    "healthy": False, "error": str(e),
                }
                overall_healthy = False

        return {
            "healthy": overall_healthy,
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "checks": results,
            "timestamp": time.time(),
        }


class DistributedTracer:
    """Simple distributed tracing for request flows."""

    def __init__(self):
        self._traces: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def start_span(self, trace_id: str, span_name: str,
                   parent_span: Optional[str] = None) -> str:
        """Start a new span in a trace."""
        import uuid
        span_id = uuid.uuid4().hex[:16]
        span = {
            "span_id": span_id, "name": span_name,
            "parent": parent_span,
            "start_time": time.time(), "end_time": None,
            "status": "active", "tags": {},
        }
        with self._lock:
            if trace_id not in self._traces:
                self._traces[trace_id] = []
            self._traces[trace_id].append(span)
        return span_id

    def end_span(self, trace_id: str, span_id: str,
                 status: str = "ok", tags: Optional[Dict] = None):
        """End a span."""
        with self._lock:
            if trace_id in self._traces:
                for span in self._traces[trace_id]:
                    if span["span_id"] == span_id:
                        span["end_time"] = time.time()
                        span["status"] = status
                        if tags:
                            span["tags"].update(tags)
                        break

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._traces.get(trace_id, []))


# Global metrics instance
metrics = MetricsCollector()
health = HealthMonitor()
tracer = DistributedTracer()
