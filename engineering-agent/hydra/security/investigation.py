"""InvestigationWorkflows: internal methods over the security engine state."""

import logging

logger = logging.getLogger("hydra.security")


class InvestigationWorkflows:
    async def _wf_hunt(self):
        """Autonomous per-vuln-class hunt driven by HuntEngine.

        Phase 1 (always): class-tagged nuclei — the safe, detection-grade
        workhorse. Phase 2/3 fire ONLY with ``--hunt-active`` and stay benign,
        scope-gated, and rate-limited; exploitation payloads are never sent
        (enforced in hydra/hunt/safety.py + prober.py).
        """
        from hydra.hunt import HuntEngine
        from hydra.sandbox import RateLimiter

        active = self.hunt_active
        logger.info(
            f"[bold]── Autonomous Hunt ──[/bold] class={self.hunt_class} "
            f"mode={self.hunt_mode} "
            f"active_probing={'ON' if active else 'OFF (nuclei only)'}"
        )
        if active:
            logger.warning(
                "[yellow]⚠️  --hunt-active: benign detection probing is ON "
                "(scope-gated, rate-limited, never-exploit).[/]"
            )

        engine = HuntEngine(
            mcp_client=self.mcp,
            scope_engine=self._scope,
            active_probing=active,
            # A dedicated, conservative bucket for live probes (only used when
            # active). Kept below the sandbox default so hunts stay polite.
            rate_limiter=RateLimiter(rate=20, burst=40) if active else None,
        )
        session = await engine.hunt(
            self.target, vuln_class=self.hunt_class, mode=self.hunt_mode
        )

        # Flatten per-cycle findings into the engine-wide list, de-duping the
        # nuclei ones by template id (prober findings have none).
        seen = {f.get("template_id") for f in self.findings if f.get("template_id")}
        for cycle in session.cycles:
            for f in cycle.findings:
                tid = f.get("template_id")
                if tid and tid in seen:
                    continue
                if tid:
                    seen.add(tid)
                self.findings.append(f)
        self._save_json("scans/hunt_findings.json", self.findings)
        logger.info(
            f"  Hunt complete: [{'red' if self.findings else 'green'}]"
            f"{len(self.findings)}[/] findings across {len(session.cycles)} "
            f"cycles ({session.success_rate}% cycle success)"
        )

    async def _wf_confirm(self):
        """Raise ONE operator-pointed finding's evidence using benign proofs only.

        This is the depth-first, human-invoked counterpart to the breadth-first
        ``hunt`` loop — NOT part of it. The operator names exactly one param and
        one vuln class; HYDRA re-tests it with a controlled differential + a
        deliberate repeat (→ REPRODUCED for ssti/sqli/open_redirect) or arms an
        out-of-band callback to a host the operator owns (SSRF). It never fans
        out, never escalates, and never sends an exploitation payload: every
        request still flows through SafeProber (see hydra/hunt/confirm.py).
        """
        from hydra.hunt.confirm import ConfirmationEngine
        from hydra.sandbox import RateLimiter

        param = (self.confirm_param or "").strip()
        vc = (self.confirm_class or "").strip().lower()
        # nextjs (CVE-2025-29927), sap (CVE-2025-31324), astro (CVE-2025-64525),
        # nextjs_ssrf (CVE-2025-57822), vite (CVE-2025-30208), web_cache
        # (CVE-2025-57752), react_router (CVE-2025-43865) and k8s_admission
        # (CVE-2025-1974) are per-ROUTE / per-endpoint request-header/path/
        # reachability differentials, not parameter probes — they need the
        # target URL only, never a param. The static-JS cluster (sanitizer_bypass
        # CVE-2026-41238, postmessage CVE-2025-5062, dom_clobbering CVE-2025-1647,
        # csp posture) likewise reads the target's own served assets/CSP — no param.
        # rabbitmq_oauth (CVE-2026-5721) and onelogin_oidc (CVE-2025-59363) are
        # endpoint secret-overshare checks (GET the target's own API endpoint and
        # flag an exposed credential KEY, value REDACTED) — endpoint, not param.
        # best_fit_charset (CVE-2024-4577 WorstFit) is a per-ROUTE PHP-CGI
        # Best-Fit argument-injection differential (the look-alike flag IS the
        # query) — route only, never a param.
        # dangerous_http_methods (CVE-2025-24813 Tomcat partial-PUT precondition)
        # is a per-ROUTE capability check: a bodyless OPTIONS reads the 'Allow'
        # header and flags an advertised write method (PUT) — route only, never a
        # param, and NEVER sends the write verb.
        needs_param = vc not in (
            "nextjs",
            "next",
            "sap",
            "sap_netweaver",
            "astro",
            "nextjs_ssrf",
            "next_ssrf",
            "header_reflection",
            "vite",
            "web_cache",
            "web_cache_poisoning",
            "nextjs_image",
            "image_cache",
            "react_router",
            "remix",
            "k8s_admission",
            "exposed_service",
            "ingress_nightmare",
            "ingressnightmare",
            "ingress_nginx_admission",
            "sanitizer_bypass",
            "dompurify",
            "prototype_pollution",
            "postmessage",
            "post_message",
            "postmessage_xss",
            "dom_clobbering",
            "dom_clobber",
            "bootstrap",
            "csp",
            "csp_bypass",
            "csp_nonce",
            "rabbitmq_oauth",
            "rabbitmq",
            "rabbitmq_secret",
            "onelogin_oidc",
            "onelogin",
            "oidc_secret",
            "best_fit_charset",
            "worstfit",
            "php_cgi",
            "php_cgi_argument_injection",
            "dangerous_http_methods",
            "dangerous_methods",
            "http_methods",
            "tomcat_partial_put",
            "partial_put",
        )
        if needs_param and not param:
            logger.error(
                "[red]confirm: --confirm-param is required "
                "(the single parameter to confirm).[/]"
            )
            return
        if not vc or vc == "auto":
            logger.error(
                "[red]confirm: --confirm-class must name ONE concrete "
                "class (ssrf, sqli, ssti, open_redirect, xss, nextjs, "
                "sap, astro, nextjs_ssrf, vite, web_cache, "
                "sanitizer_bypass, postmessage, dom_clobbering, csp, "
                "rabbitmq_oauth, onelogin_oidc, best_fit_charset, "
                "dangerous_http_methods) — not "
                "'auto'. Confirmation is single-target by design.[/]"
            )
            return

        logger.info(
            f"[bold]── Benign Confirmation ──[/bold] "
            f"{('param=' + repr(param)) if param else ('route=' + self.target)} "
            f"class={vc} "
            f"{'(OOB callback armed)' if self.oob_callback else ''}"
        )

        engine = ConfirmationEngine(
            scope_engine=self._scope,
            # Conservative, polite bucket — a confirmation sends only a handful
            # of benign requests (control + payload + a couple of repeats).
            rate_limiter=RateLimiter(rate=10, burst=20),
        )
        result = await engine.confirm(
            self.target,
            param,
            vc,
            oob_callback=self.oob_callback,
            auth_header=self.confirm_auth_header,
        )

        where = f"via '{param}'" if param else f"on {self.target}"
        finding = {
            "name": f"Confirmation: {vc.upper()} {where}",
            "type": vc,
            "matched_at": self.target,
            "severity": self._confirm_severity(vc, result),
            "hunt_class": vc,
            "hunt_source": "confirm",
            "evidence_level": result.evidence_level,
            "evidence": result.summary or result.note,
            "confidence_score": 0.9 if result.confirmed else 0.4,
            "reproduction_steps": result.poc,
            "confirmation": result.as_dict(),
            "note": result.note,
        }
        self.findings.append(finding)
        self._save_json("scans/confirmation.json", result.as_dict())

        if result.confirmed:
            logger.info(
                f"  [green]✅ CONFIRMED[/] — evidence now "
                f"[bold]{result.evidence_level}[/]: {result.summary}"
            )
        else:
            logger.info(
                f"  [yellow]◻ NOT auto-confirmed[/] ({result.evidence_level}): "
                f"{result.summary or result.note}"
            )

    @staticmethod
    def _confirm_severity(vc: str, result) -> str:
        """Severity for a confirmation finding — honest about evidence level.

        Nothing is 'critical': that tier requires exploitation, which HYDRA never
        performs. An un-confirmed / out-of-band-pending result stays 'info' so a
        report never overstates what was actually proven (ssrf.confirmed is always
        False here — it is proven only when the operator's listener records the
        nonce, so it honestly stays 'info' until then).
        """
        if not result.confirmed:
            return "info"
        return {
            "sqli": "high",
            "ssti": "high",
            "open_redirect": "medium",
            "ssrf": "high",
            "nextjs": "high",
            "sap": "high",
            "sap_netweaver": "high",
            "astro": "high",
            "nextjs_ssrf": "medium",
            "next_ssrf": "medium",
            "header_reflection": "medium",
            "vite": "high",
            "web_cache": "medium",
            "web_cache_poisoning": "medium",
            "nextjs_image": "medium",
            "image_cache": "medium",
            "react_router": "medium",
            "remix": "medium",
            "k8s_admission": "high",
            "exposed_service": "high",
            "ingress_nightmare": "high",
            "ingressnightmare": "high",
            "ingress_nginx_admission": "high",
            "sanitizer_bypass": "high",
            "dompurify": "high",
            "prototype_pollution": "high",
            "postmessage": "medium",
            "post_message": "medium",
            "postmessage_xss": "medium",
            "dom_clobbering": "low",
            "dom_clobber": "low",
            "bootstrap": "low",
            "csp": "low",
            "csp_bypass": "low",
            "csp_nonce": "low",
            "rabbitmq_oauth": "high",
            "rabbitmq": "high",
            "rabbitmq_secret": "high",
            "onelogin_oidc": "high",
            "onelogin": "high",
            "oidc_secret": "high",
            "best_fit_charset": "high",
            "worstfit": "high",
            "php_cgi": "high",
            "php_cgi_argument_injection": "high",
            "dangerous_http_methods": "medium",
            "dangerous_methods": "medium",
            "http_methods": "medium",
            "tomcat_partial_put": "medium",
            "partial_put": "medium",
        }.get(vc, "medium")
