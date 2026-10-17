"""Doctrine / system-prompt loader for HYDRA.

Exposes the authorized red-team doctrine (the operating instructions the agent
follows during an engagement) as a string, loaded from the packaged markdown so
the doctrine lives in one editable place rather than hard-coded in Python.
"""

from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent
RED_TEAM_DOCTRINE_FILE = _PROMPTS_DIR / "red_team_doctrine.md"


@lru_cache(maxsize=None)
def load_doctrine(name: str = "red_team") -> str:
    """Return the text of a named doctrine.

    `name` maps to `<name>_doctrine.md` in this package. Raises FileNotFoundError
    for an unknown name so a typo fails loudly rather than silently arming the
    agent with an empty prompt.
    """
    path = _PROMPTS_DIR / f"{name}_doctrine.md"
    if not path.exists():
        raise FileNotFoundError(f"No doctrine named '{name}' at {path}")
    return path.read_text(encoding="utf-8")


def red_team_doctrine() -> str:
    """The authorized red-team continuous-testing doctrine (system prompt)."""
    return load_doctrine("red_team")


__all__ = ["load_doctrine", "red_team_doctrine", "RED_TEAM_DOCTRINE_FILE"]
