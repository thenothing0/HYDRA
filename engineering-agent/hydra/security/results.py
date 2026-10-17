"""ResultPipeline: internal methods over the security engine state."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("hydra.security")


class ResultPipeline:
    async def _record_and_label(self):
        """Record findings into the learning DB and auto-label them."""
        if not self.findings:
            return
        try:
            from hydra.learning.pipeline import LearningPipeline
        except Exception as e:
            logger.debug(f"Learning pipeline unavailable: {e}")
            return
        try:
            pipeline = LearningPipeline()
            pipeline.record_scan(
                self.scan_id, self.target, self.findings, tool_used=self.workflow_name
            )
            if self.auto_label:
                counts = await pipeline.auto_label(self.scan_id, self.findings)
                logger.info(
                    f"  🧠 Learning: recorded {len(self.findings)}, "
                    f"auto-labeled {counts['true_positive']} TP / "
                    f"{counts['false_positive']} FP "
                    f"(total labelled: {pipeline.labelled_count()})"
                )
            self._save_json("scans/learning_scan_id.json", {"scan_id": self.scan_id})
        except Exception as e:
            logger.warning(f"  ⚠️  Learning loop failed: {e}")

    def _apply_ml(self):
        """Annotate findings with ML predictions and drop likely false positives."""
        try:
            from hydra.ml import (
                FalsePositiveClassifier,
                VulnerabilityClassifier,
                torch_available,
            )
        except Exception as e:
            logger.warning(f"  ⚠️  ML unavailable: {e}")
            return
        if not torch_available():
            logger.warning("  ⚠️  PyTorch not installed — skipping ML filter")
            return
        if not self.findings:
            return

        logger.info(
            "[bold]── ML: false-positive filter + vuln classification ──[/bold]"
        )
        vuln_clf = VulnerabilityClassifier()
        for f in self.findings:
            pred = vuln_clf.predict(f)
            f["ml_vuln_type"] = pred.label
            f["ml_vuln_confidence"] = pred.probability
            if pred.similar:
                f["ml_similar"] = pred.similar

        fp_clf = FalsePositiveClassifier()
        before = len(self.findings)
        self.findings = fp_clf.filter_findings(
            self.findings, threshold=self.ml_threshold
        )
        dropped = before - len(self.findings)
        src = self.findings[0]["fp_source"] if self.findings else "heuristic"
        logger.info(
            f"  ML filter ({src}): kept {len(self.findings)}/{before}, "
            f"dropped {dropped} likely false positive(s)"
        )
        self._save_json("scans/ml_filtered.json", self.findings)

    async def _enrich_from_memory(self, top_k: int = 3, min_similarity: float = 0.35):
        """Attach similar real-world disclosed write-ups to each finding.

        Queries the semantic-memory corpus (populated by --ingest from
        HackerOne/GitHub/Medium/Exploit-DB) so each finding carries links to
        comparable known cases — the payoff of ingesting public reports.
        Best-effort: never fails a scan if memory is empty/unavailable.
        """
        if not self.findings:
            return
        try:
            from hydra.memory.semantic import SemanticMemory
        except Exception as e:
            logger.debug(f"Semantic memory unavailable: {e}")
            return
        try:
            from hydra.config import get_config

            mem = SemanticMemory(persist_dir=get_config().semantic_memory.persist_dir)
            await mem.initialize()
        except Exception as e:
            logger.debug(f"Semantic memory init failed: {e}")
            return

        enriched = 0
        for f in self.findings:
            query = " ".join(
                str(f.get(k, "")) for k in ("name", "type", "ml_vuln_type", "evidence")
            ).strip()
            if not query:
                continue
            try:
                hits = await mem.search("methodologies", query, top_k=top_k)
            except Exception as e:
                logger.debug(f"memory search failed: {e}")
                break
            refs = []
            for h in hits or []:
                sim = float(h.get("similarity", 0) or 0)
                if sim < min_similarity:
                    continue
                meta = h.get("metadata", {}) or {}
                refs.append(
                    {
                        "title": meta.get("title", ""),
                        "url": meta.get("url", ""),
                        "source": meta.get("source", ""),
                        "category": meta.get("category", ""),
                        "known_exploited": "known-exploited"
                        in (meta.get("tags", "") or ""),
                        "similarity": round(sim, 3),
                    }
                )
            if refs:
                f["similar_writeups"] = refs
                enriched += 1
        if enriched:
            logger.info(
                f"  🔎 Context: matched {enriched}/{len(self.findings)} "
                f"finding(s) to disclosed write-ups in memory"
            )
        self._save_json("scans/enriched_findings.json", self.findings)

    def _track_engagement(self) -> Dict[str, Any]:
        """Fold this workflow run into the red-team engagement state machine.

        Populates the attack-surface inventory from recon, marks the checklist
        areas this workflow actually evaluated, records findings, and runs the
        coverage audit. Honest by design — untested areas stay pending so the
        audit reports partial coverage for a single-workflow run rather than
        claiming a complete engagement. Best-effort: never fails the scan.
        """
        try:
            from hydra.engagement import Engagement, StopReason
        except Exception as e:
            logger.debug(f"Engagement tracking unavailable: {e}")
            return {}
        try:
            eng = Engagement(
                self.target, scope_loaded=bool(self._scope and self._scope.is_loaded)
            )
            eng.inventory.ingest_recon(self.target, self.recon_data)
            for area in self.WORKFLOW_COVERAGE.get(self.workflow_name, []):
                eng.checklist.done(area, note=f"evaluated by {self.workflow_name}")
            for f in self.findings:
                eng.record_finding(f)

            cov = eng.coverage_audit()
            if cov.ready:
                eng.stop(StopReason.SUFFICIENT_COVERAGE)
            else:
                # A single workflow is a partial engagement, not a full one.
                eng.stop(
                    StopReason.EXPLICIT_LIMITATION,
                    note=f"single-workflow run ({self.workflow_name}); "
                    f"{len(cov.unmet)} coverage area(s) not evaluated",
                )
            state = eng.state()
            self._save_json(
                "scans/engagement.json",
                {
                    **state,
                    "inventory_detail": eng.inventory.to_dict(),
                    "checklist_detail": eng.checklist.to_dict(),
                },
            )
            logger.info(
                f"  📊 Engagement coverage: {state['coverage_ratio']:.0%} "
                f"({eng.checklist.counts()['done']} area(s) evaluated, "
                f"{len(cov.unmet)} still open)"
            )
            return state
        except Exception as e:
            logger.debug(f"Engagement tracking failed: {e}")
            return {}

    def _build_attack_chains(self) -> List[Dict[str, Any]]:
        """Derive attack chains from recon + findings via the attack graph.

        Feeds subdomains/hosts/endpoints and vulnerabilities into the
        AttackGraph, then extracts asset→…→high/critical-vuln paths and
        renders them in the report's chain shape. Best-effort: returns [] on
        any failure so a scan never dies over chain synthesis.
        """
        if not self.findings:
            return []
        try:
            from hydra.graph.engine import AttackGraph
        except Exception as e:
            logger.debug(f"Attack graph unavailable: {e}")
            return []
        try:
            graph = AttackGraph()
            graph.ingest_recon_results(self.target, self.recon_data)
            # Normalise each finding's host to the origin (scheme://host) so it
            # attaches to the same service node recon created (which carries the
            # subdomain→service edge), letting paths reach the vuln.
            norm = []
            for f in self.findings:
                g = dict(f)
                g["host"] = self._origin(
                    f.get("host") or f.get("matched_at") or self.target
                )
                norm.append(g)
            graph.ingest_vuln_results({"findings": norm})

            # Keep the longest path per end vuln so we don't emit a path and
            # its own suffix as two separate chains.
            best: Dict[str, Dict[str, Any]] = {}
            for cp in graph.get_critical_paths():
                steps = cp.get("path", [])
                if len(steps) < 2:
                    continue
                end = steps[-1]
                if end not in best or len(steps) > len(best[end]["chain_steps"]):
                    best[end] = {
                        "name": f"{steps[0]} → {end}",
                        "chain_steps": steps,
                        "impact": cp.get("end_severity", "medium"),
                        "confidence": round(0.4 + 0.1 * min(len(steps), 5), 2),
                    }
            chains: List[Dict[str, Any]] = list(best.values())
            # Longest / highest-impact first.
            chains.sort(
                key=lambda c: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        c["impact"], 5
                    ),
                    -len(c["chain_steps"]),
                )
            )
            self._save_json("scans/attack_graph.json", graph.to_dict())
            if chains:
                logger.info(
                    f"  🕸️  Attack graph: {len(chains)} critical path(s) "
                    f"to high/critical findings"
                )
            self._save_json("scans/attack_chains.json", chains)
            return chains
        except Exception as e:
            logger.debug(f"Attack chain synthesis failed: {e}")
            return []

    def _generate_reports(self) -> Dict[str, str]:
        """Render findings into Markdown/HTML/JSON reports under reports/."""
        try:
            from hydra.reporting import AdvancedReportEngine
        except Exception as e:
            logger.debug(f"Report engine unavailable: {e}")
            return {}
        try:
            engine = AdvancedReportEngine(output_dir=str(self.output_dir / "reports"))
            saved = engine.generate(
                target=self.target,
                scan_id=self.workflow_name,
                findings=self.findings,
                attack_chains=self._build_attack_chains(),
            )
            for fmt, path in saved.items():
                logger.info(f"  📄 {fmt}: [dim]{path}[/dim]")
            return saved
        except Exception as e:
            logger.warning(f"  ⚠️  Report generation failed: {e}")
            return {}
