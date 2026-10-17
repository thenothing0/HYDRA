"""DiscoveryWorkflows: internal methods over the security engine state."""

import logging

logger = logging.getLogger("hydra.security")


class DiscoveryWorkflows:
    async def _wf_quick_recon(self):
        """Fast recon: subdomains → probing → tech detect → nuclei quick."""
        logger.info("[bold]── Phase 1/4: Subdomain Enumeration ──[/bold]")
        subs = await self._run_tool("subfinder", {"target": self.target})
        self.recon_data["subdomains"] = self._lines(subs)
        self._save_lines("recon/subdomains.txt", self.recon_data["subdomains"])
        logger.info(
            f"  Found [green]{len(self.recon_data['subdomains'])}[/] subdomains"
        )

        logger.info("[bold]── Phase 2/4: HTTP Probing ──[/bold]")
        targets_for_probe = "\n".join(self.recon_data["subdomains"]) or self.target
        probe = await self._run_tool(
            "httpx", {"target": self.target}, stdin=targets_for_probe
        )
        self.recon_data["live_hosts"] = self._lines(probe)
        self._save_lines("recon/live_hosts.txt", self.recon_data["live_hosts"])
        logger.info(
            f"  Found [green]{len(self.recon_data['live_hosts'])}[/] live hosts"
        )

        logger.info("[bold]── Phase 3/4: Technology Detection ──[/bold]")
        tech = await self._run_tool("whatweb", {"target": self.target})
        self.recon_data["tech"] = tech.get("output", "")[:2000]
        self._save_text("recon/tech.txt", self.recon_data["tech"])

        logger.info("[bold]── Phase 4/4: Vulnerability Scan (nuclei) ──[/bold]")
        scan = await self._run_tool(
            "nuclei",
            {
                "target": self.target,
                "severity": "medium,high,critical",
            },
        )
        self.findings = self._parse_nuclei(scan.get("output", ""))
        self._save_json("scans/nuclei_results.json", self.findings)
        logger.info(
            f"  Found [{'red' if self.findings else 'green'}]{len(self.findings)}[/] vulnerabilities"
        )

    async def _wf_full_bounty(self):
        """Complete assessment: recon → crawl → fuzz → nuclei full → report."""
        # Phase 1-3: same as quick_recon
        await self._wf_quick_recon()

        logger.info("[bold]── Phase 5: URL Crawling (katana) ──[/bold]")
        crawl = await self._run_tool("katana", {"target": self.target})
        self.recon_data["urls"] = self._lines(crawl)
        self._save_lines("recon/urls.txt", self.recon_data["urls"])
        logger.info(f"  Crawled [green]{len(self.recon_data['urls'])}[/] URLs")

        logger.info("[bold]── Phase 6: Directory Brute ──[/bold]")
        dirs = await self._run_tool("dirsearch", {"target": self.target})
        self.recon_data["dirs"] = dirs.get("output", "")[:2000]

        logger.info("[bold]── Phase 7: Full Nuclei Scan (all severities) ──[/bold]")
        full_scan = await self._run_tool(
            "nuclei",
            {
                "target": self.target,
                "severity": "low,medium,high,critical",
            },
        )
        extra = self._parse_nuclei(full_scan.get("output", ""))
        seen = {f.get("template_id") for f in self.findings}
        for f in extra:
            if f.get("template_id") not in seen:
                self.findings.append(f)
        self._save_json("scans/nuclei_full.json", self.findings)
        logger.info(f"  Total findings: [red]{len(self.findings)}[/]")

    async def _wf_api_only(self):
        """API-focused: probe → nuclei API tags → fuzz."""
        logger.info("[bold]── Phase 1: HTTP Probing ──[/bold]")
        probe = await self._run_tool("httpx", {"target": self.target})
        self.recon_data["live_hosts"] = self._lines(probe)

        logger.info("[bold]── Phase 2: API Vulnerability Scan ──[/bold]")
        scan = await self._run_tool(
            "nuclei",
            {
                "target": self.target,
                "severity": "medium,high,critical",
                "tags": "api,graphql,jwt,oauth,idor",
            },
        )
        self.findings = self._parse_nuclei(scan.get("output", ""))
        self._save_json("scans/api_scan.json", self.findings)
        logger.info(f"  Found [red]{len(self.findings)}[/] API vulnerabilities")

    async def _wf_blackbox(self):
        """Black-box: aggressive recon → full scan → fuzz."""
        await self._wf_full_bounty()  # same pipeline, more aggressive
