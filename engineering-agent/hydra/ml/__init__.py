"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA ML — Deep-learning models (PyTorch)                   ║
║    • FalsePositiveClassifier — filters false positives       ║
║    • VulnerabilityClassifier — embedding-based vuln typing   ║
╚══════════════════════════════════════════════════════════════╝

All models degrade gracefully: if PyTorch is unavailable or there is not
enough training data, callers get safe heuristic fallbacks instead of errors.
"""

from hydra.ml.fp_classifier import FalsePositiveClassifier, FPPrediction
from hydra.ml.vuln_classifier import VulnerabilityClassifier, VulnPrediction

__all__ = [
    "FalsePositiveClassifier", "FPPrediction",
    "VulnerabilityClassifier", "VulnPrediction",
    "torch_available",
]


def torch_available() -> bool:
    """Return True if PyTorch can be imported."""
    try:
        import torch  # noqa: F401
        return True
    except Exception:
        return False
