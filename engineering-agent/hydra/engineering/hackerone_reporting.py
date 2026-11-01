"""Operator-configured checks gate automatic disclosure; the model cannot mark itself ready."""

import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from hydra.engineering.hackerone_api import HackerOneAPIError, program_handle
from hydra.engineering.workspace import Workspace, atomic_write, digest


REQUIRED_CHECKS = {"reproduction", "negative_control", "impact", "impact_bounds", "report_quality"}
SEVERITIES = {"none", "low", "medium", "high", "critical"}


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def text(value, name, limit=32000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\0" in value:
        raise ValueError(f"{name} must be nonempty bounded text")
    return value.strip()


def utc_epoch(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("expires_at must be an ISO-8601 timestamp with timezone") from None


def scope_allows_url(scope, value):
    if scope.get("asset_type") not in {"URL", "DOMAIN", "WILDCARD"}:
        raise ValueError("Automatic HTTP reporting supports URL/domain scopes only; other asset types need review")
    identifier = scope["asset_identifier"].strip()
    explicit_url = "://" in identifier
    allowed = urlsplit(identifier if explicit_url else "https://" + identifier)
    actual = urlsplit(value)
    decoded = actual.path
    for _ in range(3):
        decoded = unquote(decoded)
    if "\\" in decoded or "%" in decoded or any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("Ambiguous affected URL path requires review")
    host, expected = actual.hostname, allowed.hostname
    if not host or not expected:
        raise ValueError("Scope does not identify a usable HTTP asset")
    matches = (host == expected) if not expected.startswith("*.") else (
        host.endswith(expected[1:]) and host != expected[2:]
    )
    if not matches or (explicit_url and actual.scheme != allowed.scheme):
        raise ValueError("Affected URL is outside the selected scope")
    if allowed.port is not None and (actual.port or (443 if actual.scheme == "https" else 80)) != allowed.port:
        raise ValueError("Affected URL uses a different scope port")
    if explicit_url and (actual.port or (443 if actual.scheme == "https" else 80)) != (
            allowed.port or (443 if allowed.scheme == "https" else 80)):
        raise ValueError("Affected URL uses a different scope port")
    prefix = allowed.path.rstrip("/")
    if prefix and not (actual.path == prefix or actual.path.startswith(prefix + "/")):
        raise ValueError("Affected URL is outside the scope path")


class HackerOneReporting:
    def __init__(self, workspace, client=None):
        self.workspace = workspace if isinstance(workspace, Workspace) else Workspace(workspace)
        self.directory = self.workspace.root / ".hydra/hackerone"
        self.client = client

    def path(self, name):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
            raise ValueError("Invalid reporting storage name")
        target = self.directory / name
        for part in (self.directory.parent, self.directory, target):
            if (part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())
                    or not part.resolve().is_relative_to(self.workspace.root)):
                raise ValueError("Reporting storage must stay inside the workspace without aliases")
        return target

    def read(self, name):
        target = self.path(name)
        if target.stat().st_size > 1_000_000:
            raise ValueError("Reporting record is too large")
        value = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Malformed reporting record")
        return value

    def write(self, name, value):
        target = self.path(name)
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        if len(data) > 1_000_000:
            raise ValueError("Reporting record is too large")
        atomic_write(target, data)

    def receipts(self):
        return [self.read(p.name) for p in sorted(self.directory.glob("*.json"))
                if re.fullmatch(r"[a-f0-9]{64}\.json", p.name)]

    def status(self):
        policy = self.path("policy.json")
        if not policy.exists():
            return {"configured": False, "automatic_submission": False,
                    "next": "Configure a program and operator-owned validation plan with hydra hackerone authorize"}
        value = self.read("policy.json")
        receipts = self.receipts()
        used = sum(r.get("authorized_at") == value["authorized_at"] for r in receipts)
        return {"configured": True, "automatic_submission": utc_epoch(value["expires_at"]) > time.time() and used < value["max_reports"],
                "program": value["program"], "structured_scope_id": value["structured_scope_id"],
                "api_username": value["api_username"],
                "expires_at": value["expires_at"], "max_reports": value["max_reports"],
                "remaining_submissions": max(0, value["max_reports"] - used),
                "required_checks": sorted(REQUIRED_CHECKS), "policy_digest": value["snapshot_digest"],
                "receipts": [{k: r[k] for k in ("finding_id", "status", "program", "report_id", "url") if k in r}
                             for r in receipts[-20:]]}

    @staticmethod
    def eligible(snapshot):
        if (snapshot.get("submission_state") != "open" or not snapshot.get("policy")
                or snapshot["scope"].get("attributes", {}).get("eligible_for_submission") is not True):
            raise ValueError("Program must be open with a policy and this asset explicitly eligible for submission")

    async def authorize(self, plan, *, policy_reviewed=False):
        if not policy_reviewed:
            raise ValueError("Review the current program policy, exclusions and asset instructions before authorization")
        if not isinstance(plan, dict):
            raise ValueError("Validation plan must be an object")
        plan = json.loads(json.dumps(plan))
        program_handle(plan.get("program"))
        if type(plan.get("structured_scope_id")) is not int or plan["structured_scope_id"] < 1:
            raise ValueError("A positive structured_scope_id is required")
        expires = utc_epoch(plan.get("expires_at"))
        if not time.time() < expires <= time.time() + 7 * 86400:
            raise ValueError("Authorization must expire within seven days")
        if type(plan.get("max_reports")) is not int or not 1 <= plan["max_reports"] <= 20:
            raise ValueError("max_reports must be 1..20; one is recommended")
        checks = plan.get("checks")
        if (not isinstance(checks, list) or len(checks) != len(REQUIRED_CHECKS)
                or any(not isinstance(c, dict) or not isinstance(c.get("id"), str) for c in checks)
                or {c["id"] for c in checks} != REQUIRED_CHECKS):
            raise ValueError("The validation plan must contain each required check exactly once")
        for check in checks:
            argv = check.get("argv")
            if (not isinstance(argv, list) or not argv or len(argv) > 80
                    or any(not isinstance(a, str) or not a or "\0" in a for a in argv)
                    or sum(a.count("{finding}") for a in argv) != 1
                    or "{finding}" not in argv):
                raise ValueError("Each check needs fixed argv with one standalone {finding} argument")
            executable = shutil.which(argv[0])
            if not executable:
                raise ValueError("Validation executable was not found")
            argv[0] = str(Path(executable).resolve())
            pins = check.get("pinned_files")
            if not isinstance(pins, list) or not pins or any(not isinstance(p, str) for p in pins):
                raise ValueError("Pin the validation script and its trusted dependencies outside the workspace")
            paths = [Path(argv[0]), *(Path(p) for p in pins)]
            check["pins"] = {}
            for path in paths:
                if not path.is_absolute() or not path.is_file() or path.resolve().is_relative_to(self.workspace.root):
                    raise ValueError("Verifier executables/scripts must be outside the agent workspace")
                resolved = path.resolve()
                check["pins"][str(resolved)] = digest(resolved.read_bytes())
            timeout = check.get("timeout", 60)
            if type(timeout) is not int or not 1 <= timeout <= 120:
                raise ValueError("Check timeout must be 1..120 seconds")
            check["timeout"] = timeout
        snapshot = await self.client.snapshot(plan["program"], plan["structured_scope_id"])
        self.eligible(snapshot)
        if plan.get("reviewed_snapshot_digest") != fingerprint(snapshot):
            raise ValueError("Program snapshot differs from the reviewed digest; inspect the current program before authorization")
        plan.update(schema=1, snapshot_digest=fingerprint(snapshot), snapshot=snapshot,
                    api_username=self.client.username, workspace=str(self.workspace.root),
                    authorized_at=datetime.now(timezone.utc).isoformat())
        lock = self.lock()
        try:
            self.write("policy.json", plan)
        finally:
            lock.unlink()
        return self.status()

    def lock(self):
        lock = self.path("submission.lock")
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError("Another disclosure operation is active; inspect a stale lock after a crash") from None
        os.close(descriptor)
        return lock

    def prepare(self, finding, policy):
        if not isinstance(finding, dict):
            raise ValueError("Finding must be an object")
        required = ("title", "vulnerability_information", "impact", "affected_url", "root_cause",
                    "asset_identifier", "expected_result", "observed_result", "impact_bounds", "limitations")
        normalized = {name: text(finding.get(name), name) for name in required}
        if normalized["asset_identifier"] != policy["snapshot"]["scope"]["attributes"]["asset_identifier"]:
            raise ValueError("Finding asset must exactly match the authorized structured scope")
        parsed = urlsplit(normalized["affected_url"])
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("affected_url must be an HTTP(S) URL without credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Use an affected URL without query secrets or fragments; put redacted requests in evidence")
        scope_allows_url(policy["snapshot"]["scope"]["attributes"], normalized["affected_url"])
        severity = finding.get("severity_rating")
        if not isinstance(severity, str) or severity not in SEVERITIES:
            raise ValueError("Select an evidence-supported severity_rating, including explicit none when appropriate")
        weakness = finding.get("weakness_id")
        if type(weakness) is not int or weakness < 1:
            raise ValueError("A verified HackerOne weakness_id is required; do not guess a CWE number")
        if str(weakness) not in {str(w.get("id")) for w in policy["snapshot"].get("weaknesses", [])}:
            raise ValueError("weakness_id must be listed by the selected program's current Hacker API")
        steps = finding.get("reproduction_steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 30:
            raise ValueError("Provide 1..30 reproducible steps")
        steps = [text(step, "reproduction step", 8000) for step in steps]
        evidence = finding.get("evidence")
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 10:
            raise ValueError("Provide 1..10 redacted evidence files with SHA256 hashes")
        attachments = []
        for item in evidence:
            if not isinstance(item, dict):
                raise ValueError("Evidence must contain path and sha256")
            data = self.workspace.read_bytes(item.get("path"))
            if len(data) > 32000 or digest(data) != item.get("sha256"):
                raise ValueError("Evidence changed or exceeds 32 KB; recheck the finding")
            attachments.append({"path": item["path"], "sha256": item["sha256"], "text": data.decode("utf-8")})
        normalized.update(severity_rating=severity, weakness_id=weakness, reproduction_steps=steps, evidence=attachments)
        serialized = json.dumps(normalized, ensure_ascii=False)
        if len(serialized.encode("utf-8")) > 200000:
            raise ValueError("Finding and evidence exceed 200 KB")
        if self.client and self.client.contains_credential(serialized):
            raise ValueError("Report contains the configured API credential; submission refused")
        if re.search(r"(?im)\b(?:authorization|cookie|set-cookie)\s*:\s*(?!\[REDACTED\])\S+", serialized):
            raise ValueError("Redact authentication and cookie headers before preparing a report")
        return normalized

    @staticmethod
    def payload(finding, policy):
        details = finding["vulnerability_information"] + "\n\n## Steps to reproduce\n"
        details += "\n".join(f"{i}. {step}" for i, step in enumerate(finding["reproduction_steps"], 1))
        for label, key in (("Affected endpoint", "affected_url"), ("Expected result", "expected_result"),
                           ("Observed result", "observed_result"), ("Impact validation and stopping point", "impact_bounds"),
                           ("Limitations", "limitations")):
            details += f"\n\n## {label}\n{finding[key]}"
        details += "\n\n## Redacted evidence\n"
        for item in finding["evidence"]:
            details += f"\n### {item['path']} (SHA256 {item['sha256']})\n\n{item['text']}\n"
        return {"team_handle": policy["program"], "structured_scope_id": policy["structured_scope_id"],
                "title": finding["title"], "vulnerability_information": details, "impact": finding["impact"],
                "severity_rating": finding["severity_rating"], "weakness_id": finding["weakness_id"]}

    async def submit(self, finding, *, run_check, read_only=False):
        if read_only:
            raise PermissionError("Read-only sessions cannot validate or submit disclosures")
        lock = self.lock()
        try:
            return await self._submit(finding, run_check)
        finally:
            lock.unlink()

    async def _submit(self, finding, run_check):
        policy = self.read("policy.json")
        if policy.get("api_username") != self.client.username or policy.get("workspace") != str(self.workspace.root):
            raise ValueError("Disclosure authorization belongs to another account or workspace")
        if utc_epoch(policy["expires_at"]) <= time.time():
            raise ValueError("Automatic disclosure authorization expired")
        normalized = self.prepare(finding, policy)
        identity = fingerprint({"program": policy["program"], "scope": policy["structured_scope_id"],
                                "url": normalized["affected_url"], "weakness": normalized["weakness_id"],
                                "root_cause": normalized["root_cause"].casefold()})
        record_name = identity + ".json"
        if self.path(record_name).exists():
            return {"success": False, "duplicate_prevented": True, **self.read(record_name)}
        used = sum(r.get("authorized_at") == policy["authorized_at"] for r in self.receipts())
        if used >= policy["max_reports"]:
            raise ValueError("Authorized submission budget exhausted; no further report will be sent")
        prepared_name = "finding-" + identity + ".json"
        self.write(prepared_name, normalized)
        prepared_path = self.path(prepared_name)
        prepared_hash = digest(prepared_path.read_bytes())
        checks = []
        for check in policy["checks"]:
            for name, expected in check["pins"].items():
                path = Path(name)
                if not path.is_file() or digest(path.read_bytes()) != expected:
                    raise ValueError("Trusted verifier changed; review and authorize the plan again")
            argv = [str(prepared_path) if arg == "{finding}" else arg for arg in check["argv"]]
            started = time.monotonic()
            result = await run_check(argv, check["timeout"])
            passed = result.get("success") is True and result.get("exit_code") == 0 and not result.get("timed_out")
            checks.append({"id": check["id"], "success": passed, "exit_code": result.get("exit_code"),
                           "elapsed_seconds": round(time.monotonic() - started, 3), "argv_digest": fingerprint(argv),
                           "finding_digest": prepared_hash, "output_digest": fingerprint(result)})
            self.write("checks-" + identity + ".json", {"finding_digest": fingerprint(normalized), "checks": checks})
            if not passed:
                return {"success": False, "status": "blocked", "failed_check": check["id"], "checks": checks}
        if digest(prepared_path.read_bytes()) != prepared_hash:
            raise ValueError("Finding was changed by validation; repeat checks on the final report")
        for check in policy["checks"]:
            for name, expected in check["pins"].items():
                if digest(Path(name).read_bytes()) != expected:
                    raise ValueError("Trusted verifier changed during validation")
        # Re-read all evidence and policy just before the external write.
        if self.prepare(finding, policy) != normalized:
            raise ValueError("Evidence changed during validation")
        snapshot = await self.client.snapshot(policy["program"], policy["structured_scope_id"])
        self.eligible(snapshot)
        if fingerprint(snapshot) != policy["snapshot_digest"]:
            raise ValueError("Program policy, asset or exclusions changed; review before reauthorizing")
        if self.read("policy.json") != policy or utc_epoch(policy["expires_at"]) <= time.time():
            raise ValueError("Disclosure authorization changed or expired during validation")
        record = {"finding_id": identity, "status": "sending", "authorized_at": policy["authorized_at"],
                  "program": policy["program"], "payload_digest": fingerprint(self.payload(normalized, policy)),
                  "checks": checks, "created_at": datetime.now(timezone.utc).isoformat()}
        # Persist before POST: cancellation, process death and uncertain replies must not duplicate a report.
        self.write(record_name, record)
        try:
            response = await self.client.create_report(self.payload(normalized, policy))
            report_id = response.get("data", {}).get("id")
            if not str(report_id).isdigit():
                raise ValueError("Create response did not identify a report")
        except HackerOneAPIError as error:
            record.update(status="rejected" if 400 <= error.status < 500 and error.status != 408 else "unknown",
                          http_status=error.status)
            self.write(record_name, record)
            return {"success": False, **record, "next": "Inspect HackerOne and the local receipt; automatic retry is disabled"}
        except BaseException:
            record["status"] = "unknown"
            self.write(record_name, record)
            raise
        record.update(status="submitted", report_id=str(report_id), url=f"https://hackerone.com/reports/{report_id}")
        self.write(record_name, record)
        return {"success": True, **record}
