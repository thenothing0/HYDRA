"""Feature encoding shared by HYDRA ML models.

Turns a finding dict into a fixed-length numeric feature vector so it can be
fed to a neural network. Encoding is deterministic and dependency-free.
"""

from typing import Any, Dict, List

# Stable ordering — the index of each value IS the feature position.
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

# Common finding-type / tool families. Unknown values hash into a bucket so
# the vector length stays fixed regardless of vocabulary drift.
TYPE_VOCAB = [
    "xss", "sqli", "ssrf", "idor", "rce", "lfi", "ssti", "xxe",
    "open-redirect", "csrf", "auth-bypass", "info", "misconfig",
    "reentrancy", "tx_origin", "selfdestruct", "hardcoded_secret",
]
TOOL_VOCAB = [
    "nuclei", "httpx", "subfinder", "katana", "ffuf", "dirsearch",
    "nmap", "whatweb", "wafw00f", "amass", "gau", "solidity", "code_review",
]

_TYPE_BUCKETS = 4   # extra hashed buckets for out-of-vocab types
_TOOL_BUCKETS = 3

# Total feature vector length
FEATURE_DIM = (
    len(SEVERITY_LEVELS)
    + len(TYPE_VOCAB) + _TYPE_BUCKETS
    + len(TOOL_VOCAB) + _TOOL_BUCKETS
    + 3  # confidence, has_evidence, name_len (normalised)
)


def _onehot(value: str, vocab: List[str], buckets: int) -> List[float]:
    vec = [0.0] * (len(vocab) + buckets)
    v = (value or "").strip().lower()
    if not v:
        return vec
    matched = False
    for i, token in enumerate(vocab):
        if token in v:
            vec[i] = 1.0
            matched = True
    if not matched and buckets:
        vec[len(vocab) + (hash(v) % buckets)] = 1.0
    return vec


def encode_finding(finding: Dict[str, Any]) -> List[float]:
    """Encode a single finding into a FEATURE_DIM-length float vector."""
    sev = (finding.get("severity", "info") or "info").strip().lower()
    sev_vec = [0.0] * len(SEVERITY_LEVELS)
    if sev in SEVERITY_LEVELS:
        sev_vec[SEVERITY_LEVELS.index(sev)] = 1.0

    ftype = str(finding.get("type") or finding.get("name") or "")
    type_vec = _onehot(ftype, TYPE_VOCAB, _TYPE_BUCKETS)

    tool = str(finding.get("tool_used") or finding.get("tool") or "")
    tool_vec = _onehot(tool, TOOL_VOCAB, _TOOL_BUCKETS)

    try:
        conf = float(finding.get("confidence", finding.get("confidence_score", 0.5)))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))

    has_evidence = 1.0 if finding.get("evidence") else 0.0
    name_len = min(len(str(finding.get("name", ""))) / 60.0, 1.0)

    return sev_vec + type_vec + tool_vec + [conf, has_evidence, name_len]
