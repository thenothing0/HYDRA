"""Rank investigation hypotheses and link only locally observed browser evidence.

Differences and repeated observations are never promoted to exploit confirmation.
"""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from hydra.browser.bridge import origin, clean_url
from hydra.engineering.workspace import atomic_write


METHODS = {
    "authorization": [
        {"name": "Compare two operator-owned test accounts", "checks": ["Capture the same authorized view in each paired tab", "Compare visible object/action access"], "preconditions": ["Two owned test accounts", "Same authorized application origin"]},
        {"name": "Compare UI controls against documented access rules", "checks": ["Inspect form/link structure", "Record expected versus observed role behavior"], "preconditions": ["Documented role matrix"]}],
    "input_validation": [
        {"name": "Observe a harmless unique text marker", "checks": ["Use an authorized test form", "Observe rendering and validation behavior"], "preconditions": ["Page interactions explicitly enabled", "Non-sensitive test input"]},
        {"name": "Review client-side constraints", "checks": ["Inspect field types and required attributes", "Compare constraints with documented server expectations"], "preconditions": ["Application requirements available"]}],
    "session": [
        {"name": "Observe an owned session lifecycle", "checks": ["Record authenticated view", "After operator-controlled logout, observe the same view"], "preconditions": ["Operator-owned test account", "Authorized session lifecycle testing"]}],
    "headers": [
        {"name": "Inspect passive response metadata", "checks": ["Start network metadata recording", "Observe normal authorized navigation", "Review CSP, framing and cache headers in context"], "preconditions": ["Site host permission granted"]}],
    "navigation": [
        {"name": "Review same-origin route and form boundaries", "checks": ["Inspect visible links and form actions", "Compare role-specific navigation in authorized tabs"], "preconditions": ["Explicitly scoped origin"]}],
}


class InvestigationStore:
    def __init__(self, workspace):
        self.root = Path(workspace).resolve()
        self.directory = self.root / ".hydra/browser/investigations"

    def scope(self, url):
        connection = json.loads((self.root / ".hydra/browser/connection.json").read_text(encoding="utf-8"))
        if origin(url) not in connection["origins"]:
            raise ValueError("Investigation URL is outside the bridge's authorized origins")

    def path(self, ident):
        if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise ValueError("Invalid investigation/evidence id")
        return self.directory / (ident + ".json")

    def save(self, case):
        atomic_write(self.path(case["id"]), json.dumps(case, ensure_ascii=False, indent=2).encode("utf-8"))

    def load(self, ident):
        return json.loads(self.path(ident).read_text(encoding="utf-8"))

    def evidence(self, ident):
        self.path(ident)  # validate before constructing any filename
        path = self.root / ".hydra/browser/evidence" / (ident + ".json")
        evidence = json.loads(path.read_text(encoding="utf-8"))
        claimed = evidence.get("sha256")
        original = {k: v for k, v in evidence.items() if k != "sha256"}
        actual = hashlib.sha256(json.dumps(original, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        if evidence.get("id") != ident or actual != claimed:
            raise ValueError("Evidence integrity check failed")
        return evidence

    def create(self, url, category, hypothesis):
        self.scope(url)
        if category not in METHODS or not isinstance(hypothesis, str) or not 5 <= len(hypothesis) <= 2000:
            raise ValueError("Choose a supported category and a bounded explicit hypothesis")
        case = {"id": uuid.uuid4().hex, "url": clean_url(url), "category": category,
                "hypothesis": hypothesis, "classification": "unverified_hypothesis",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "methods": METHODS[category], "observations": [], "comparisons": [],
                "limitations": ["Browser observations alone do not establish exploitability or impact",
                                "No exploit execution or automatic promotion to confirmed vulnerability"]}
        self.save(case)
        return case

    def observe(self, ident, evidence_ids, interpretation):
        case = self.load(ident)
        self.scope(case["url"])
        if not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= 8:
            raise ValueError("Attach 1..8 actual evidence ids")
        if not isinstance(interpretation, str) or len(interpretation) > 2000:
            raise ValueError("Interpretation must be bounded text")
        records = [self.evidence(item) for item in evidence_ids]
        for record in records:
            url = record["data"].get("url")
            if not url or origin(url) != origin(case["url"]):
                raise ValueError("Evidence does not belong to this investigation origin")
        case["observations"].append({"evidence_ids": evidence_ids, "interpretation": interpretation,
                                     "interpretation_status": "inferred_from_observations"})
        case["classification"] = "observed_candidate"
        self.save(case)
        return case

    def compare(self, ident, baseline_id, variant_id):
        case = self.load(ident)
        self.scope(case["url"])
        if baseline_id == variant_id:
            raise ValueError("Use two independently captured evidence records")
        first, second = self.evidence(baseline_id), self.evidence(variant_id)
        for evidence in (first, second):
            if evidence["action"] != "snapshot" or origin(evidence["data"].get("url", "")) != origin(case["url"]):
                raise ValueError("Comparison requires two scoped page snapshots")
        fields = [name for name in ("text", "elements", "forms") if first["data"].get(name) != second["data"].get(name)]
        comparison = {"baseline": baseline_id, "variant": variant_id, "changed_fields": fields,
                      "classification": "observed_difference" if fields else "no_observed_difference",
                      "note": "Different content can be normal application behavior; this is not vulnerability confirmation"}
        case["comparisons"].append(comparison)
        self.save(case)
        return comparison

    def report(self):
        cases = [json.loads(path.read_text(encoding="utf-8")) for path in self.directory.glob("*.json")]
        ranked = []
        for case in cases:
            ids = set(item for observation in case["observations"] for item in observation["evidence_ids"])
            ids.update(item for comparison in case["comparisons"] for item in (comparison["baseline"], comparison["variant"]))
            for ident in ids:
                self.evidence(ident)
            # Evidence coverage ranks review priority, never predicted exploit success.
            case["review_priority"] = min(10, len(ids) + 2 * len(case["comparisons"]))
            ranked.append(case)
        ranked.sort(key=lambda case: case["review_priority"], reverse=True)
        report = {"cases": ranked, "ranking_basis": "observed evidence coverage, not exploitability",
                  "confirmed_vulnerabilities": 0, "limitations": ["Human/domain validation is still required"]}
        destination = self.root / ".hydra/browser/investigation-report.json"
        atomic_write(destination, json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
        return {"report": str(destination), **report}
