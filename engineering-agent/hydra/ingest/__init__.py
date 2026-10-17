"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Ingest — Public write-up / report collectors          ║
║    Pulls PUBLIC, disclosed security write-ups from external   ║
║    sources (GitHub, Medium, …) via official APIs / RSS and    ║
║    feeds them into the learning subsystem.                    ║
╚══════════════════════════════════════════════════════════════╝

Design goals:
  • Extensible: add a new source by subclassing SourceAdapter.
  • Polite: official APIs / RSS only, with rate limiting and a
    descriptive User-Agent. No aggressive scraping, no auth-walled
    content, no ToS violations.
  • Safe: only ingests text for learning; never executes anything.
"""

from hydra.ingest.base import SourceAdapter, Writeup, REGISTRY, register
from hydra.ingest.pipeline import IngestPipeline

# Import adapters so they self-register.
from hydra.ingest.sources import github as _github          # noqa: F401
from hydra.ingest.sources import medium as _medium          # noqa: F401
from hydra.ingest.sources import hackerone as _hackerone     # noqa: F401
from hydra.ingest.sources import exploitdb as _exploitdb     # noqa: F401

__all__ = ["SourceAdapter", "Writeup", "IngestPipeline", "REGISTRY", "register"]
