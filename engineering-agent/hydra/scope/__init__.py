"""
Scope Intelligence Layer — Mandatory pre-execution scope analysis.
Accepts HackerOne/Bugcrowd/Intigriti URLs. Parses all scope data.
No task may execute without scope validation.
"""

import json, logging, time, re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from urllib.parse import urlparse

logger = logging.getLogger("hydra.scope")


@dataclass
class ProgramScope:
    program_name: str
    platform: str
    in_scope: List[Dict[str, str]] = field(default_factory=list)
    out_of_scope: List[Dict[str, str]] = field(default_factory=list)
    allowed_testing: List[str] = field(default_factory=list)
    forbidden_testing: List[str] = field(default_factory=list)
    rate_limit: Optional[int] = None
    disclosure_policy: str = ""
    bounty_rules: str = ""
    severity_guidelines: Dict[str, str] = field(default_factory=dict)
    bounty_table: Dict[str, str] = field(default_factory=dict)
    response_sla: Dict[str, str] = field(default_factory=dict)
    program_url: str = ""
    last_updated: float = field(default_factory=time.time)
    raw_policy_text: str = ""


@dataclass
class ScopeIntelligenceReport:
    program: ProgramScope
    allowed_testing_matrix: Dict[str, bool] = field(default_factory=dict)
    target_risk_map: List[Dict[str, Any]] = field(default_factory=list)
    recommended_workflow: str = "full_assessment"
    warnings: List[str] = field(default_factory=list)
    planner_directives: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)


@dataclass
class ScopeValidationResult:
    allowed: bool
    target: str = ""
    reason: str = ""
    matched_rule: str = ""
    policy_violations: List[str] = field(default_factory=list)


def detect_platform(url: str) -> str:
    host = urlparse(url).hostname or url.lower()
    if "hackerone" in host: return "hackerone"
    if "bugcrowd" in host: return "bugcrowd"
    if "intigriti" in host: return "intigriti"
    if "yeswehack" in host: return "yeswehack"
    return "custom"


class ProgramAdapter(ABC):
    @abstractmethod
    async def fetch_program(self, program_id: str) -> ProgramScope: ...
    @abstractmethod
    async def parse_scope(self, raw_data: Dict) -> ProgramScope: ...

    def _extract_domains(self, text: str) -> List[str]:
        return list(set(re.findall(r'[\w][\w.-]+\.[\w]{2,}', text)))

    def _extract_wildcards(self, text: str) -> List[str]:
        return list(set(re.findall(r'\*\.[\w.-]+\.[\w]{2,}', text)))

    async def _http_get(self, url: str) -> Optional[str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200: return await r.text()
        except Exception as e:
            logger.warning(f"HTTP fetch failed ({url}): {e}")
        return None

    async def _http_get_json(self, url: str, headers: Dict = None) -> Optional[Dict]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers or {}, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200: return await r.json()
        except Exception as e:
            logger.warning(f"JSON fetch failed ({url}): {e}")
        return None


class HackerOneAdapter(ProgramAdapter):
    API_BASE = "https://api.hackerone.com/v1"
    WEB_BASE = "https://hackerone.com"

    def __init__(self, api_token: str = ""):
        self.api_token = api_token

    async def fetch_program(self, handle: str) -> ProgramScope:
        handle = handle.strip("/").split("/")[-1]
        if self.api_token:
            data = await self._http_get_json(
                f"{self.API_BASE}/hackers/programs/{handle}",
                headers={"Authorization": f"Bearer {self.api_token}"}
            )
            if data: return await self.parse_scope(data)
        html = await self._http_get(f"{self.WEB_BASE}/{handle}")
        if html: return self._parse_html(handle, html)
        return ProgramScope(program_name=handle, platform="hackerone",
                            program_url=f"{self.WEB_BASE}/{handle}")

    async def parse_scope(self, raw: Dict) -> ProgramScope:
        attrs = raw.get("data", raw).get("attributes", raw)
        scope = ProgramScope(
            program_name=attrs.get("handle", attrs.get("name", "")),
            platform="hackerone",
            program_url=f"{self.WEB_BASE}/{attrs.get('handle', '')}",
            disclosure_policy=attrs.get("policy", ""),
            raw_policy_text=json.dumps(raw, default=str)[:5000],
        )
        for a in raw.get("in_scope", attrs.get("targets", {}).get("in_scope", [])):
            scope.in_scope.append({"asset": a.get("asset_identifier", a.get("asset", "")),
                                    "type": a.get("asset_type", "URL"), "instruction": a.get("instruction", "")})
        for a in raw.get("out_of_scope", attrs.get("targets", {}).get("out_of_scope", [])):
            scope.out_of_scope.append({"asset": a.get("asset_identifier", a.get("asset", "")),
                                       "type": a.get("asset_type", "URL"), "reason": a.get("instruction", "")})
        scope.forbidden_testing = raw.get("forbidden", attrs.get("forbidden_testing", []))
        scope.allowed_testing = raw.get("allowed", attrs.get("allowed_testing", []))
        return scope

    def _parse_html(self, handle: str, html: str) -> ProgramScope:
        scope = ProgramScope(program_name=handle, platform="hackerone",
                             program_url=f"{self.WEB_BASE}/{handle}")
        domains = self._extract_domains(html)
        wildcards = self._extract_wildcards(html)
        exclude = {"hackerone.com","cloudflare.com","google.com","googleapis.com",
                    "gstatic.com","jquery.com","jsdelivr.net","cloudfront.net","amazonaws.com"}
        for d in domains:
            if not any(e in d for e in exclude):
                scope.in_scope.append({"asset": d, "type": "URL"})
        for w in wildcards:
            scope.in_scope.append({"asset": w, "type": "WILDCARD"})
        return scope


class BugcrowdAdapter(ProgramAdapter):
    WEB_BASE = "https://bugcrowd.com"

    async def fetch_program(self, handle: str) -> ProgramScope:
        handle = handle.strip("/").split("/")[-1]
        html = await self._http_get(f"{self.WEB_BASE}/{handle}")
        if html: return self._parse_html(handle, html)
        return ProgramScope(program_name=handle, platform="bugcrowd",
                            program_url=f"{self.WEB_BASE}/{handle}")

    async def parse_scope(self, raw: Dict) -> ProgramScope:
        scope = ProgramScope(program_name=raw.get("name", ""), platform="bugcrowd",
                             program_url=raw.get("url", ""))
        for a in raw.get("in_scope", []):
            scope.in_scope.append({"asset": a if isinstance(a, str) else a.get("asset", ""),
                                    "type": "URL"})
        for a in raw.get("out_of_scope", []):
            scope.out_of_scope.append({"asset": a if isinstance(a, str) else a.get("asset", ""),
                                       "type": "URL"})
        scope.forbidden_testing = raw.get("forbidden_testing", [])
        scope.rate_limit = raw.get("rate_limit")
        return scope

    def _parse_html(self, handle: str, html: str) -> ProgramScope:
        scope = ProgramScope(program_name=handle, platform="bugcrowd",
                             program_url=f"{self.WEB_BASE}/{handle}")
        for d in self._extract_domains(html):
            if "bugcrowd" not in d:
                scope.in_scope.append({"asset": d, "type": "URL"})
        return scope


class IntigritiAdapter(ProgramAdapter):
    WEB_BASE = "https://app.intigriti.com"

    async def fetch_program(self, handle: str) -> ProgramScope:
        handle = handle.strip("/").split("/")[-1]
        html = await self._http_get(f"{self.WEB_BASE}/programs/{handle}")
        if html: return self._parse_html(handle, html)
        return ProgramScope(program_name=handle, platform="intigriti",
                            program_url=f"{self.WEB_BASE}/programs/{handle}")

    async def parse_scope(self, raw: Dict) -> ProgramScope:
        scope = ProgramScope(program_name=raw.get("name", ""), platform="intigriti")
        for a in raw.get("in_scope", []):
            scope.in_scope.append({"asset": a if isinstance(a, str) else a.get("asset", ""), "type": "URL"})
        for a in raw.get("out_of_scope", []):
            scope.out_of_scope.append({"asset": a if isinstance(a, str) else a.get("asset", ""), "type": "URL"})
        scope.forbidden_testing = raw.get("forbidden_testing", [])
        scope.rate_limit = raw.get("rate_limit")
        return scope

    def _parse_html(self, handle: str, html: str) -> ProgramScope:
        scope = ProgramScope(program_name=handle, platform="intigriti",
                             program_url=f"{self.WEB_BASE}/programs/{handle}")
        for d in self._extract_domains(html):
            if "intigriti" not in d:
                scope.in_scope.append({"asset": d, "type": "URL"})
        return scope


class CustomProgramAdapter(ProgramAdapter):
    async def fetch_program(self, program_id: str) -> ProgramScope:
        return ProgramScope(program_name=program_id, platform="custom")

    async def parse_scope(self, raw: Dict) -> ProgramScope:
        scope = ProgramScope(program_name=raw.get("name", "custom"), platform="custom")
        for a in raw.get("in_scope", []):
            scope.in_scope.append({"asset": a, "type": "URL"} if isinstance(a, str) else a)
        for a in raw.get("out_of_scope", []):
            scope.out_of_scope.append({"asset": a, "type": "URL"} if isinstance(a, str) else a)
        scope.forbidden_testing = raw.get("forbidden_testing", [])
        scope.allowed_testing = raw.get("allowed_testing", [])
        scope.rate_limit = raw.get("rate_limit")
        scope.disclosure_policy = raw.get("disclosure_policy", "")
        scope.bounty_rules = raw.get("bounty_rules", "")
        scope.bounty_table = raw.get("bounty_table", {})
        scope.severity_guidelines = raw.get("severity_guidelines", {})
        return scope


ADAPTERS = {
    "hackerone": HackerOneAdapter, "bugcrowd": BugcrowdAdapter,
    "intigriti": IntigritiAdapter, "custom": CustomProgramAdapter,
}


class ScopePolicyEngine:
    """
    Mandatory scope enforcement. No task executes without validation.
    
    Before every tool execution:
      1. validate target against scope
      2. validate workflow against forbidden testing
      3. validate policy compliance
    """

    def __init__(self):
        self._scope: Optional[ProgramScope] = None
        self._intel: Optional[ScopeIntelligenceReport] = None
        self._validation_log: List[Dict] = []

    @property
    def scope(self) -> Optional[ProgramScope]:
        return self._scope

    @property
    def is_loaded(self) -> bool:
        return self._scope is not None

    @staticmethod
    def _normalize_asset(entry: Any) -> Dict[str, str]:
        """Normalize a scope entry to a dict with an `asset` key.

        Accepts a bare string, or a dict using either `asset` or `identifier`.
        """
        if isinstance(entry, str):
            return {"asset": entry, "type": "URL"}
        d = dict(entry)
        d["asset"] = d.get("asset") or d.get("identifier") or ""
        d["type"] = d.get("type") or "URL"
        return d

    def load_from_dict(self, data: Dict[str, Any]) -> ProgramScope:
        """Synchronously load scope from an in-memory dict.

        Expects keys like `program`/`name`, `platform`, `in_scope`,
        `out_of_scope`, `forbidden_testing`, `rate_limit`. Scope entries may
        be plain strings or dicts using `asset` or `identifier`.
        """
        scope = ProgramScope(
            program_name=data.get("program", data.get("name", "custom")),
            platform=data.get("platform", "custom"),
            forbidden_testing=list(data.get("forbidden_testing", [])),
            allowed_testing=list(data.get("allowed_testing", [])),
            rate_limit=data.get("rate_limit"),
            disclosure_policy=data.get("disclosure_policy", ""),
            bounty_rules=data.get("bounty_rules", ""),
            severity_guidelines=data.get("severity_guidelines", {}) or {},
        )
        for a in data.get("in_scope", []):
            scope.in_scope.append(self._normalize_asset(a))
        for a in data.get("out_of_scope", []):
            scope.out_of_scope.append(self._normalize_asset(a))
        self._scope = scope
        self._intel = self._build_intelligence()
        logger.info(f"🎯 Scope loaded: {scope.program_name} ({scope.platform}) "
                     f"— {len(scope.in_scope)} in-scope, {len(scope.out_of_scope)} out-of-scope")
        return scope

    async def load_from_url(self, url: str, api_token: str = "") -> ProgramScope:
        platform = detect_platform(url)
        handle = url.strip("/").split("/")[-1]
        return await self.load_scope(platform=platform, program_id=handle, api_token=api_token)

    async def load_scope(self, platform: str = "custom", program_id: str = "",
                         raw_scope: Optional[Dict] = None, api_token: str = "") -> ProgramScope:
        adapter_cls = ADAPTERS.get(platform, CustomProgramAdapter)
        adapter = adapter_cls(api_token=api_token) if platform == "hackerone" and api_token else adapter_cls()
        if raw_scope:
            self._scope = await adapter.parse_scope(raw_scope)
        else:
            self._scope = await adapter.fetch_program(program_id)
        self._intel = self._build_intelligence()
        logger.info(f"🎯 Scope loaded: {self._scope.program_name} ({self._scope.platform}) "
                     f"— {len(self._scope.in_scope)} in-scope, {len(self._scope.out_of_scope)} out-of-scope")
        return self._scope

    def validate_target(self, target: str) -> ScopeValidationResult:
        if not self._scope:
            # Fail-closed: with no scope loaded, nothing is authorized.
            # (Safety rule #1 — no scan without scope validation.)
            return ScopeValidationResult(allowed=False, target=target,
                reason="No scope loaded — blocked (fail-closed)")
        clean = self._clean_target(target)
        for oos in self._scope.out_of_scope:
            asset = oos.get("asset", "").lower()
            if self._domain_matches(clean, asset):
                r = ScopeValidationResult(allowed=False, target=target,
                    reason=f"Out of scope: {asset}", matched_rule=f"out_of_scope:{asset}")
                self._log_validation(r)
                return r
        if self._scope.in_scope:
            for ins in self._scope.in_scope:
                asset = ins.get("asset", "").lower()
                if self._domain_matches(clean, asset):
                    r = ScopeValidationResult(allowed=True, target=target, matched_rule=f"in_scope:{asset}")
                    self._log_validation(r)
                    return r
            r = ScopeValidationResult(allowed=False, target=target, reason="Target not in scope")
            self._log_validation(r)
            return r
        return ScopeValidationResult(allowed=False, target=target,
            reason="No authorized assets in scope — blocked (fail-closed)")

    def validate_workflow(self, workflow_type: str) -> ScopeValidationResult:
        if not self._scope:
            return ScopeValidationResult(allowed=True, reason="No scope loaded")
        forbidden = " ".join(self._scope.forbidden_testing).lower()
        violations = []
        wf = workflow_type.lower()
        checks = {"brute": "brute_force", "fuzz": "fuzzing", "port": "port_scanning",
                  "exploit": "exploitation", "dos": "denial_of_service", "social": "social_engineering"}
        for keyword, label in checks.items():
            if keyword in forbidden and keyword in wf:
                violations.append(f"Forbidden: {label}")
        if violations:
            return ScopeValidationResult(allowed=False, target=workflow_type,
                reason=f"Workflow violates policy", policy_violations=violations)
        return ScopeValidationResult(allowed=True, target=workflow_type)

    def validate_tool_execution(self, tool_name: str, target: str) -> ScopeValidationResult:
        target_check = self.validate_target(target)
        if not target_check.allowed:
            return target_check
        if not self._scope:
            return ScopeValidationResult(allowed=True, target=target)
        forbidden = " ".join(self._scope.forbidden_testing).lower()
        tool_map = {"nmap": "port", "ffuf": "fuzz", "dirsearch": "brute", "nuclei": "scan"}
        for tool_key, forbidden_key in tool_map.items():
            if tool_key in tool_name.lower() and forbidden_key in forbidden:
                return ScopeValidationResult(allowed=False, target=target,
                    reason=f"Tool {tool_name} blocked by scope policy",
                    policy_violations=[f"Forbidden testing: {forbidden_key}"])
        return ScopeValidationResult(allowed=True, target=target)

    def generate_execution_policy(self) -> Dict[str, Any]:
        if not self._scope: return {"policy": "unrestricted"}
        forbidden = " ".join(self._scope.forbidden_testing).lower()
        return {
            "allowed_targets": [a["asset"] for a in self._scope.in_scope],
            "blocked_targets": [a["asset"] for a in self._scope.out_of_scope],
            "forbidden_testing": self._scope.forbidden_testing,
            "rate_limit": self._scope.rate_limit or 50,
            "allow_brute_force": "brute" not in forbidden,
            "allow_port_scan": "port" not in forbidden,
            "allow_fuzzing": "fuzz" not in forbidden,
            "allow_exploitation": "exploit" not in forbidden,
            "program": self._scope.program_name,
            "platform": self._scope.platform,
        }

    def generate_intelligence_report(self) -> ScopeIntelligenceReport:
        if self._intel: return self._intel
        return self._build_intelligence()

    def generate_planner_directives(self) -> List[str]:
        if not self._scope: return ["No scope — run in discovery mode"]
        directives = []
        forbidden = " ".join(self._scope.forbidden_testing).lower()
        if self._scope.rate_limit:
            directives.append(f"RATE_LIMIT: {self._scope.rate_limit} req/s")
        if "brute" in forbidden:
            directives.append("DISABLE: brute_force, directory_bruteforce")
        if "fuzz" in forbidden:
            directives.append("DISABLE: parameter_fuzzing, endpoint_fuzzing")
        if "port" in forbidden:
            directives.append("DISABLE: port_scanning")
        if "exploit" in forbidden:
            directives.append("DISABLE: active_exploitation")
        if "dos" in forbidden or "denial" in forbidden:
            directives.append("DISABLE: stress_testing, dos_testing")
        for asset in self._scope.in_scope:
            atype = asset.get("type", "URL").upper()
            if atype == "API":
                directives.append(f"FOCUS_API: {asset.get('asset', '')}")
            elif "WILDCARD" in atype or asset.get("asset", "").startswith("*."):
                directives.append(f"ENUM_SUBDOMAINS: {asset.get('asset', '')}")
        return directives

    def _build_intelligence(self) -> ScopeIntelligenceReport:
        if not self._scope:
            return ScopeIntelligenceReport(program=ProgramScope(program_name="unknown", platform="custom"))
        scope = self._scope
        forbidden = " ".join(scope.forbidden_testing).lower()
        warnings = []
        if not scope.in_scope: warnings.append("No explicit in-scope assets defined")
        if scope.forbidden_testing: warnings.append(f"Forbidden: {', '.join(scope.forbidden_testing)}")
        matrix = {"subdomain_enum": True, "port_scanning": "port" not in forbidden,
                  "brute_force": "brute" not in forbidden, "vulnerability_scanning": True,
                  "fuzzing": "fuzz" not in forbidden, "exploit_testing": "exploit" not in forbidden,
                  "crawling": True, "tech_fingerprinting": True}
        risk_map = [{"asset": a.get("asset",""), "type": a.get("type","URL"),
                     "estimated_risk": "high" if a.get("type","").upper() in ("API","WILDCARD") else "medium"}
                    for a in scope.in_scope]
        has_api = any(a.get("type","").upper() == "API" for a in scope.in_scope)
        has_wildcard = any("*" in a.get("asset","") for a in scope.in_scope)
        workflow = "api_assessment" if has_api else "full_assessment" if has_wildcard or len(scope.in_scope) > 10 else "quick_scan"
        return ScopeIntelligenceReport(
            program=scope, allowed_testing_matrix=matrix, target_risk_map=risk_map,
            recommended_workflow=workflow, warnings=warnings,
            planner_directives=self.generate_planner_directives())

    def _clean_target(self, target: str) -> str:
        t = target.lower().strip()
        for p in ["https://","http://","ftp://"]:
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0].split(":")[0]

    @staticmethod
    def _domain_matches(target: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            base = pattern[2:]
            return target == base or target.endswith("." + base)
        return target == pattern

    def _log_validation(self, result: ScopeValidationResult):
        self._validation_log.append({"target": result.target, "allowed": result.allowed,
            "reason": result.reason, "timestamp": time.time()})

    def get_validation_log(self) -> List[Dict]:
        return list(self._validation_log)


class ProgramMemory:
    def __init__(self):
        self._programs: Dict[str, Dict[str, Any]] = {}

    def remember_program(self, scope: ProgramScope, findings: Optional[List[Dict]] = None):
        key = f"{scope.platform}:{scope.program_name}"
        if key not in self._programs:
            self._programs[key] = {"scope": scope, "scans": [], "total_findings": 0, "successful_types": {}}
        entry = self._programs[key]
        entry["scope"] = scope
        entry["scans"].append({"timestamp": time.time()})
        if findings:
            entry["total_findings"] += len(findings)
            for f in findings:
                ft = f.get("type", "unknown")
                entry["successful_types"][ft] = entry["successful_types"].get(ft, 0) + 1

    def get_program_history(self, platform: str, name: str) -> Optional[Dict]:
        return self._programs.get(f"{platform}:{name}")

    def get_recommended_focus(self, platform: str, name: str) -> List[str]:
        h = self.get_program_history(platform, name)
        if not h: return []
        types = h.get("successful_types", {})
        return sorted(types, key=types.get, reverse=True)[:5]
