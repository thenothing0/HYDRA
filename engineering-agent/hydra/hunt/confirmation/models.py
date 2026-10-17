"""Stable evidence records for confirmation results."""

from dataclasses import dataclass, field
from typing import List
from hydra.hunt.safety import EvidenceLevel


@dataclass
class ProbeExchange:
    """One benign request/response pair, kept for PoC packaging."""

    label: str  # control | payload | repeat | oob-callback
    url: str
    status: int
    note: str = ""


@dataclass
class ConfirmationResult:
    target: str
    param: str
    vuln_class: str
    confirmed: bool = False
    evidence_level: str = EvidenceLevel.UNVERIFIED
    technique: str = ""
    exchanges: List[ProbeExchange] = field(default_factory=list)
    summary: str = ""
    poc: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "param": self.param,
            "vuln_class": self.vuln_class,
            "confirmed": self.confirmed,
            "evidence_level": self.evidence_level,
            "technique": self.technique,
            "exchanges": [vars(e) for e in self.exchanges],
            "summary": self.summary,
            "poc": self.poc,
            "note": self.note,
        }
