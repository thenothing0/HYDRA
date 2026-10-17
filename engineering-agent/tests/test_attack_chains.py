"""Tests for attack-chain synthesis in HydraEngine (recon+findings → graph)."""

from hydra.main import HydraEngine


def _engine():
    e = HydraEngine(target="shop.example.com", workflow="quick_recon",
                    allow_no_scope=True)
    e.recon_data = {
        "subdomains": ["api.example.com", "shop.example.com"],
        "live_hosts": ["https://api.example.com", "https://shop.example.com"],
    }
    return e


class TestOriginHelper:
    def test_strips_path_and_query(self):
        assert HydraEngine._origin("https://a.example.com/x?y=1") == "https://a.example.com"

    def test_bare_host(self):
        assert HydraEngine._origin("a.example.com/x") == "a.example.com"

    def test_empty(self):
        assert HydraEngine._origin("") == ""


class TestAttackChains:
    def test_no_findings_no_chains(self):
        e = _engine()
        e.findings = []
        assert e._build_attack_chains() == []

    def test_builds_path_to_critical_vuln(self):
        e = _engine()
        e.findings = [{
            "name": "SQL Injection in /login", "severity": "critical",
            "template_id": "sqli-login",
            "matched_at": "https://api.example.com/login", "type": "sqli",
        }]
        chains = e._build_attack_chains()
        assert len(chains) >= 1
        c = chains[0]
        assert c["impact"] == "critical"
        assert c["chain_steps"][-1] == "SQL Injection in /login"
        # Path starts from an asset and traverses the host.
        assert any("example.com" in s for s in c["chain_steps"])

    def test_low_sev_findings_excluded(self):
        e = _engine()
        e.findings = [{
            "name": "Missing security header", "severity": "low",
            "template_id": "hdr-1",
            "matched_at": "https://shop.example.com/", "type": "misc",
        }]
        # get_critical_paths only targets high/critical vulns.
        assert e._build_attack_chains() == []

    def test_dedup_keeps_longest_per_endpoint(self):
        e = _engine()
        e.findings = [{
            "name": "SSRF in webhook", "severity": "high",
            "template_id": "ssrf-1",
            "matched_at": "https://api.example.com/hook", "type": "ssrf",
        }]
        chains = e._build_attack_chains()
        # Only one chain per distinct end vuln despite multiple asset roots.
        ends = [c["chain_steps"][-1] for c in chains]
        assert len(ends) == len(set(ends))
