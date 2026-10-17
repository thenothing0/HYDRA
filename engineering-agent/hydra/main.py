"""Compatibility imports and launcher for the security runtime.

Prefer `python -m hydra security ...`; existing imports and -m hydra.main work.
"""

from hydra.security.engine import HydraEngine
from hydra.security.parser import build_parser, AVAILABLE_WORKFLOWS
from hydra.security.console import (
    console,
    rprint,
    setup_logging,
    print_tool_status,
    print_workflows,
    print_summary,
)
from hydra.security.cli import BANNER, async_main, entry

__all__ = [
    "HydraEngine",
    "build_parser",
    "AVAILABLE_WORKFLOWS",
    "BANNER",
    "async_main",
    "entry",
    "console",
    "rprint",
    "setup_logging",
    "print_tool_status",
    "print_workflows",
    "print_summary",
]

if __name__ == "__main__":
    entry()
