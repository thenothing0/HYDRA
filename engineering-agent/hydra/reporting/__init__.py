"""
╔══════════════════════════════════════════════════════════════╗
║  Advanced Report Generation — CVSS, CWE, MITRE ATT&CK    ║
║  Markdown, HTML, JSON with attack chain visualization      ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("hydra.reporting")


# CWE mapping
CWE_MAP = {
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting"},
    "sqli": {"id": "CWE-89", "name": "SQL Injection"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    "lfi": {"id": "CWE-98", "name": "Path Traversal"},
    "rce": {"id": "CWE-94", "name": "Code Injection"},
    "auth-bypass": {"id": "CWE-287", "name": "Improper Authentication"},
    "idor": {"id": "CWE-639", "name": "Insecure Direct Object Reference"},
    "ssti": {"id": "CWE-1336", "name": "Template Injection"},
    "open-redirect": {"id": "CWE-601", "name": "Open Redirect"},
    "csrf": {"id": "CWE-352", "name": "Cross-Site Request Forgery"},
    "xxe": {"id": "CWE-611", "name": "XML External Entity"},
    "default-login": {"id": "CWE-798", "name": "Hard-coded Credentials"},
}

# MITRE ATT&CK mapping
MITRE_MAP = {
    "xss": {"tactic": "Initial Access", "technique": "T1189", "name": "Drive-by Compromise"},
    "sqli": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing App"},
    "ssrf": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing App"},
    "rce": {"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting"},
    "auth-bypass": {"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts"},
    "credential": {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
    "lfi": {"tactic": "Collection", "technique": "T1005", "name": "Data from Local System"},
}

# CVSS base score mapping
CVSS_SEVERITY = {
    "critical": {"score": 9.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "high": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "medium": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "low": {"score": 3.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"},
    "info": {"score": 0.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
}


class AdvancedReportEngine:
    """
    Production-grade report generation engine.
    
    Outputs: Markdown, HTML, JSON
    Includes: CVSS scoring, CWE mapping, MITRE ATT&CK,
              executive summary, technical appendix,
              attack chain visualization, reproducibility templates.
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self, target: str, scan_id: str,
        findings: List[Dict[str, Any]],
        attack_chains: Optional[List[Dict]] = None,
        executive_summary: str = "",
        formats: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Generate reports in multiple formats."""
        formats = formats or ["markdown", "json", "html"]
        attack_chains = attack_chains or []

        # Enrich findings
        enriched = [self._enrich_finding(f, i+1) for i, f in enumerate(
            sorted(findings, key=lambda f: self.SEVERITY_ORDER.get(
                f.get("severity", "info"), 5
            ))
        )]

        report_data = {
            "meta": {
                "scan_id": scan_id, "target": target,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_findings": len(enriched),
                "severity_breakdown": self._severity_breakdown(enriched),
            },
            "executive_summary": executive_summary or self._auto_summary(
                target, enriched, attack_chains
            ),
            "findings": enriched,
            "attack_chains": attack_chains[:10],
        }

        report_dir = self.output_dir / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        saved = {}

        if "json" in formats:
            path = report_dir / "report.json"
            path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
            saved["json"] = str(path)

        if "markdown" in formats:
            path = report_dir / "report.md"
            path.write_text(
                self._render_markdown(report_data), encoding="utf-8"
            )
            saved["markdown"] = str(path)

        if "html" in formats:
            path = report_dir / "report.html"
            path.write_text(
                self._render_html(report_data), encoding="utf-8"
            )
            saved["html"] = str(path)

        logger.info(f"📄 Reports generated: {list(saved.keys())} → {report_dir}")
        return saved

    def _enrich_finding(self, finding: Dict, index: int) -> Dict:
        """Enrich a finding with CVSS, CWE, MITRE mappings."""
        severity = finding.get("severity", "info").lower()
        f_type = str(finding.get("type", "")).lower()

        # CWE
        cwe = None
        for key, mapping in CWE_MAP.items():
            if key in f_type:
                cwe = mapping
                break

        # MITRE ATT&CK
        mitre = None
        for key, mapping in MITRE_MAP.items():
            if key in f_type:
                mitre = mapping
                break

        # CVSS
        cvss = CVSS_SEVERITY.get(severity, CVSS_SEVERITY["info"])

        return {
            "id": f"HYDRA-{index:04d}",
            "title": finding.get("name", "Unknown"),
            "severity": severity,
            "cvss_score": cvss["score"],
            "cvss_vector": cvss["vector"],
            "cwe": cwe,
            "mitre_attack": mitre,
            "confidence": finding.get("confidence_score", finding.get("confidence", 0)),
            "type": finding.get("type", "unknown"),
            "host": finding.get("host", finding.get("matched_at", "")),
            "matched_at": finding.get("matched_at", ""),
            "description": finding.get("description", ""),
            "remediation": finding.get("remediation", ""),
            "evidence": finding.get("evidence", ""),
            "reproduction_steps": finding.get("reproduction_steps", []),
            "template_id": finding.get("template_id", ""),
            "cves": finding.get("cves", []),
            "exploit_intel": finding.get("exploit_intel", []),
            "known_exploited": finding.get("known_exploited", False),
            "has_public_exploit": finding.get("has_public_exploit", False),
            "similar_writeups": finding.get("similar_writeups", []),
        }

    def _severity_breakdown(self, findings: list) -> Dict[str, int]:
        bd = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = f.get("severity", "info").lower()
            bd[s] = bd.get(s, 0) + 1
        return bd

    def _auto_summary(self, target: str, findings: list,
                      chains: list) -> str:
        bd = self._severity_breakdown(findings)
        return (
            f"Security assessment of {target} identified "
            f"{len(findings)} findings: "
            f"{bd['critical']} critical, {bd['high']} high, "
            f"{bd['medium']} medium, {bd['low']} low severity. "
            f"{len(chains)} attack chains were identified."
        )

    def _render_markdown(self, report: Dict) -> str:
        meta = report["meta"]
        lines = [
            "# 🔥 HYDRA Security Assessment Report",
            f"## Target: {meta['target']}",
            f"**Scan ID:** {meta['scan_id']}  ",
            f"**Generated:** {meta['generated_at']}  ",
            f"**Total Findings:** {meta['total_findings']}",
            "",
            "## Executive Summary",
            report.get("executive_summary", ""),
            "",
            "## Severity Breakdown",
            "| Severity | Count | CVSS Range |",
            "|----------|-------|------------|",
        ]
        cvss_ranges = {"critical": "9.0-10.0", "high": "7.0-8.9",
                       "medium": "4.0-6.9", "low": "0.1-3.9", "info": "0.0"}
        for sev, count in meta["severity_breakdown"].items():
            lines.append(f"| {sev.upper()} | {count} | {cvss_ranges.get(sev, '')} |")

        lines.extend(["", "## Findings", ""])
        for f in report.get("findings", []):
            lines.extend([
                f"### {f['id']} — {f['title']}",
                f"- **Severity:** {f['severity'].upper()} (CVSS {f['cvss_score']})",
                f"- **Confidence:** {f['confidence']:.1%}" if isinstance(f['confidence'], float) else f"- **Confidence:** {f['confidence']}",
                f"- **Host:** {f.get('host', 'N/A')}",
                f"- **CVSS Vector:** `{f['cvss_vector']}`",
            ])
            if f.get("cwe"):
                lines.append(f"- **CWE:** {f['cwe']['id']} — {f['cwe']['name']}")
            if f.get("mitre_attack"):
                m = f["mitre_attack"]
                lines.append(f"- **MITRE ATT&CK:** {m['technique']} — {m['name']} ({m['tactic']})")
            if f.get("matched_at"):
                lines.append(f"- **Location:** `{f['matched_at']}`")
            if f.get("known_exploited"):
                lines.append("- **⚠️ KNOWN EXPLOITED (CISA KEV):** "
                             "actively exploited in the wild — prioritise")
            elif f.get("has_public_exploit"):
                lines.append("- **Public exploit / PoC available** — elevated risk")
            for block in f.get("exploit_intel", []):
                cid = block.get("cve_id", "")
                bits = []
                if block.get("cvss_score") is not None:
                    bits.append(f"CVSS {block['cvss_score']} "
                                f"{block.get('cvss_severity', '')}".strip())
                if block.get("known_exploited"):
                    kev = f"KEV {block.get('kev_date_added', '')}".strip()
                    if block.get("kev_ransomware"):
                        kev += ", ransomware"
                    bits.append(kev)
                suffix = f" ({'; '.join(bits)})" if bits else ""
                lines.append(f"  - **{cid}**{suffix}")
                for ref in block.get("exploit_refs", [])[:5]:
                    lines.append(f"    - Exploit/PoC: {ref}")
            lines.append(f"- **Description:** {f.get('description', 'N/A')}")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** `{str(f['evidence'])[:300]}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            if f.get("similar_writeups"):
                lines.append("- **Similar disclosed reports:**")
                for sw in f["similar_writeups"]:
                    src = sw.get("source", "")
                    cat = sw.get("category", "")
                    sim = sw.get("similarity", 0)
                    url = sw.get("url", "")
                    label = sw.get("title", "").strip() or url or f"{src} {cat}".strip()
                    ref = f"[{label}]({url})" if url else label
                    kev = " ⚠️ **known-exploited**" if sw.get("known_exploited") else ""
                    lines.append(f"  - {ref} "
                                 f"_({src}, {sim:.0%} similar)_{kev}")
            lines.append("")
            if f.get("reproduction_steps"):
                lines.append("**Reproduction Steps:**")
                for i, step in enumerate(f["reproduction_steps"], 1):
                    lines.append(f"{i}. {step}")
                lines.append("")

        if report.get("attack_chains"):
            lines.extend(["## Attack Chains", ""])
            for chain in report["attack_chains"][:5]:
                name = chain.get("name", "Chain")
                steps = chain.get("chain_steps", [])
                lines.append(f"### {name}")
                lines.append(f"**Impact:** {chain.get('impact', 'N/A')} | **Confidence:** {chain.get('confidence', 'N/A')}")
                lines.append(f"**Path:** {' → '.join(steps)}")
                lines.append("")

        return "\n".join(lines)

    def _render_html(self, report: Dict) -> str:
        import html as html_lib
        meta = report["meta"]
        target = html_lib.escape(meta["target"])
        summary = html_lib.escape(report.get("executive_summary", ""))
        bd = meta["severity_breakdown"]

        findings_html = []
        for f in report.get("findings", []):
            sev = f["severity"]
            color_map = {"critical": "#ff4444", "high": "#ff8800",
                         "medium": "#ffcc00", "low": "#44cc44", "info": "#4488ff"}
            color = color_map.get(sev, "#999")
            findings_html.append(f"""
            <div style="border-left:4px solid {color};padding:15px;margin:10px 0;background:#1a1a2e;border-radius:0 8px 8px 0;">
                <h3 style="color:{color}">{html_lib.escape(f['id'])} — {html_lib.escape(f['title'])}</h3>
                <p><strong>Severity:</strong> <span style="color:{color}">{sev.upper()}</span> (CVSS {f['cvss_score']})</p>
                <p><strong>Host:</strong> {html_lib.escape(f.get('host','N/A'))}</p>
                <p><strong>Description:</strong> {html_lib.escape(f.get('description','N/A'))}</p>
            </div>""")

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>HYDRA Report — {target}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0e0;padding:40px;max-width:900px;margin:auto;}}
h1{{background:linear-gradient(90deg,#00d2ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
h2{{color:#00d2ff;border-bottom:1px solid #333;padding-bottom:8px;}}
table{{width:100%;border-collapse:collapse;}}
th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #333;}}
th{{background:#1a1a2e;}}
</style></head><body>
<h1>🔥 HYDRA Security Report</h1>
<h2>Target: {target}</h2>
<p>Scan: {html_lib.escape(meta['scan_id'])} | Generated: {meta['generated_at']}</p>
<h2>Executive Summary</h2><p>{summary}</p>
<h2>Severity Breakdown</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
{''.join(f"<tr><td>{s.upper()}</td><td>{c}</td></tr>" for s,c in bd.items())}
</table>
<h2>Findings ({meta['total_findings']})</h2>
{''.join(findings_html)}
</body></html>"""
