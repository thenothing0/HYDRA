"""LocalWorkflows: internal methods over the security engine state."""

import logging
from pathlib import Path

logger = logging.getLogger("hydra.security")


class LocalWorkflows:
    async def _wf_web3_audit(self):
        """Static Solidity analysis: vuln patterns + DeFi patterns + token compliance.

        `target` is a path to a .sol file or a directory containing .sol files.
        """
        from hydra.web3 import SolidityAnalyzer, DeFiPatternDetector, TokenScanner

        path = Path(self.target)
        if path.is_file():
            sol_files = [path]
        elif path.is_dir():
            sol_files = sorted(path.rglob("*.sol"))
        else:
            logger.error(
                f"[red]web3_audit expects a .sol file or a directory. "
                f"Not found:[/] {self.target}"
            )
            return

        if not sol_files:
            logger.warning("[yellow]No .sol files found under the target path.[/]")
            return

        analyzer, defi, tokens = (
            SolidityAnalyzer(),
            DeFiPatternDetector(),
            TokenScanner(),
        )
        logger.info(f"[bold]── Auditing {len(sol_files)} Solidity file(s) ──[/bold]")

        for i, f in enumerate(sol_files, 1):
            src = f.read_text(encoding="utf-8", errors="replace")
            logger.info(
                f"  [{i}/{len(sol_files)}] {f.name} ({src.count(chr(10)) + 1} lines)"
            )

            result = analyzer.analyze(src, filename=str(f))
            for finding in result["findings"]:
                finding["matched_at"] = (
                    f"{finding.get('file', f)}:{finding.get('line', '?')}"
                )
                self.findings.append(finding)

            for d in defi.detect(src):
                self.findings.append(
                    {
                        "name": f"defi:{d['pattern']}",
                        "severity": "info",
                        "description": d["description"],
                        "evidence": ", ".join(d["matched_indicators"]),
                        "matched_at": str(f),
                        "confidence": d["confidence"],
                    }
                )

            for std in ("erc20", "erc721"):
                comp = tokens.check_compliance(src, std)
                if comp["missing_functions"] or comp["missing_events"]:
                    # Only flag when the file clearly looks like that token type
                    present = len(tokens.COMPLIANCE_CHECKS[std]["required"]) - len(
                        comp["missing_functions"]
                    )
                    if present >= 3:
                        self.findings.append(
                            {
                                "name": f"compliance:{std}",
                                "severity": "low",
                                "description": f"Incomplete {std.upper()} implementation",
                                "evidence": f"missing functions: {comp['missing_functions']}; "
                                f"missing events: {comp['missing_events']}",
                                "matched_at": str(f),
                            }
                        )

        self.recon_data["contracts_analyzed"] = [str(f) for f in sol_files]
        self._save_json("scans/web3_audit.json", self.findings)
        logger.info(
            f"  Found [{'red' if self.findings else 'green'}]{len(self.findings)}[/] "
            f"contract issues"
        )

    async def _wf_code_review(self):
        """Static source-code security review over a local directory or file.

        `target` is a path. Runs regex-based rules over source files and routes
        any .sol files through the Solidity analyzer.
        """
        import re

        path = Path(self.target)
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = [
                p
                for p in path.rglob("*")
                if p.is_file()
                and p.suffix.lower() in (self.CODE_REVIEW_EXTS | {".sol"})
                and not {
                    ".git",
                    "node_modules",
                    ".venv",
                    "venv",
                    "__pycache__",
                }.intersection(p.parts)
            ]
        else:
            logger.error(
                f"[red]code_review expects a file or directory. Not found:[/] {self.target}"
            )
            return

        if not files:
            logger.warning(
                "[yellow]No reviewable source files found under the target path.[/]"
            )
            return

        compiled = [
            (name, sev, re.compile(pat), desc)
            for name, sev, pat, desc in self.CODE_REVIEW_RULES
        ]
        logger.info(f"[bold]── Reviewing {len(files)} source file(s) ──[/bold]")

        sol_files = []
        for f in files:
            if f.suffix.lower() == ".sol":
                sol_files.append(f)
                continue
            try:
                src = f.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.debug(f"skip {f}: {e}")
                continue
            for name, sev, rx, desc in compiled:
                for m in rx.finditer(src):
                    line_num = src[: m.start()].count("\n") + 1
                    self.findings.append(
                        {
                            "name": name,
                            "severity": sev,
                            "description": desc,
                            "file": str(f),
                            "line": line_num,
                            "matched_at": f"{f}:{line_num}",
                            "evidence": m.group()[:120],
                            "confidence": 0.6,
                        }
                    )

        # Route Solidity files through the dedicated analyzer
        if sol_files:
            from hydra.web3 import SolidityAnalyzer

            analyzer = SolidityAnalyzer()
            for f in sol_files:
                src = f.read_text(encoding="utf-8", errors="replace")
                for finding in analyzer.analyze(src, filename=str(f))["findings"]:
                    finding["matched_at"] = (
                        f"{finding.get('file', f)}:{finding.get('line', '?')}"
                    )
                    self.findings.append(finding)

        self.recon_data["files_reviewed"] = len(files)
        self._save_json("scans/code_review.json", self.findings)
        logger.info(
            f"  Found [{'red' if self.findings else 'green'}]{len(self.findings)}[/] "
            f"potential issues across {len(files)} files"
        )
