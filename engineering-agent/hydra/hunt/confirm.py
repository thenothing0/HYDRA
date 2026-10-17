"""
╔══════════════════════════════════════════════════════════════╗
║  ConfirmationEngine — human-gated, single-target benign PoC  ║
║  Raises evidence toward REPRODUCED without ever exploiting.   ║
╚══════════════════════════════════════════════════════════════╝

Why this exists (and why it is NOT the autonomous hunt loop):

A triager pays for a *convincing, reproducible* proof — not a raw scanner hit.
The autonomous ``hunt`` workflow is deliberately breadth-first and benign; it
surfaces *leads*. This module is the depth-first, **operator-invoked** step that
takes ONE lead the operator explicitly points at and raises its evidence level
using **benign proofs only**:

  * a controlled differential + a deliberate repeat (the doctrine's definition of
    REPRODUCED: "triggered more than once / with a controlled differential"),
  * for SSRF, a single outbound GET to a callback host **the operator owns**
    (proves the server can be made to fetch an attacker-supplied URL — zero harm:
    no cloud-metadata, no internal pivot, no credentials).

What it will NOT do, by design (see hydra/hunt/safety.py + CLAUDE.md):
RCE command execution, UNION/boolean/blind SQL data extraction, time-based DoS,
executable XSS, path-traversal file disclosure, or SSRF against
cloud-metadata/internal hosts. Those add no proof beyond the benign signal and
are exactly what gets an operator removed from a program. Every request still
flows through :class:`hydra.hunt.prober.SafeProber` (GET-only, redirects off,
denylist-refused, scope-gated, rate-limited).

Single-target and non-autonomous: it acts on one finding the operator hands it,
and never fans out or escalates on its own.
"""

import logging
import uuid
from typing import List, Optional
from urllib.parse import urlparse, urlunparse
from hydra.hunt.safety import (
    EvidenceLevel,
    is_exploitation_payload,
    benign_probe_variants,
    assess_probe,
)
from hydra.hunt.prober import SafeProber, build_probe_url
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import _DIFFERENTIAL_CLASSES, _NO_BENIGN_PROOF

from hydra.hunt.confirmation.frameworks import FrameworkChecks
from hydra.hunt.confirmation.services import ServiceChecks
from hydra.hunt.confirmation.cache import CacheChecks
from hydra.hunt.confirmation.sources import SourceAnalysis
from hydra.hunt.confirmation.client import ClientChecks
from hydra.hunt.confirmation.secrets import SecretExposureChecks
from hydra.hunt.confirmation.http import HTTPChecks

logger = logging.getLogger("hydra.hunt.confirm")


class ConfirmationEngine(
    FrameworkChecks,
    ServiceChecks,
    CacheChecks,
    SourceAnalysis,
    ClientChecks,
    SecretExposureChecks,
    HTTPChecks,
):
    """Operator-invoked benign confirmation for a single, explicit finding."""

    def __init__(
        self,
        prober: Optional[SafeProber] = None,
        scope_engine=None,
        rate_limiter=None,
        repeats: int = 2,
    ):
        self.prober = prober
        self.scope = scope_engine
        self.rate = rate_limiter
        # Extra confirming sends required after the first hit before calling it
        # REPRODUCED. >=1 means the signal held on 2+ independent requests.
        self.repeats = max(1, repeats)

    def _get_prober(self) -> SafeProber:
        if self.prober is None:
            self.prober = SafeProber(scope_engine=self.scope, rate_limiter=self.rate)
        return self.prober

    async def confirm(
        self,
        target_url: str,
        param: str,
        vuln_class: str,
        oob_callback: str = "",
        nonce: str = "",
        auth_header: str = "",
    ) -> ConfirmationResult:
        """Raise ONE finding's evidence using benign proofs only."""
        vc = (vuln_class or "").lower()
        prober = self._get_prober()

        if vc == "ssrf":
            return await self._confirm_ssrf(
                target_url, param, oob_callback, prober, nonce
            )

        if vc in ("nextjs", "next"):
            return await self._confirm_nextjs(target_url, prober)

        if vc in ("sap", "sap_netweaver"):
            return await self._confirm_sap(target_url, prober, nonce)

        if vc in ("astro",):
            return await self._confirm_astro(target_url, prober, nonce)

        if vc in ("nextjs_ssrf", "next_ssrf", "header_reflection"):
            return await self._confirm_header_reflection(target_url, prober, nonce)

        if vc in ("vite",):
            return await self._confirm_vite(target_url, prober, nonce)

        if vc in ("web_cache", "web_cache_poisoning", "nextjs_image", "image_cache"):
            return await self._confirm_web_cache(target_url, prober, nonce)

        if vc in ("react_router", "remix"):
            return await self._confirm_react_router(target_url, prober, nonce)

        if vc in (
            "k8s_admission",
            "exposed_service",
            "ingress_nightmare",
            "ingressnightmare",
            "ingress_nginx_admission",
        ):
            return await self._confirm_k8s_admission(target_url, prober, nonce)

        if vc in ("sanitizer_bypass", "dompurify", "prototype_pollution"):
            return await self._confirm_sanitizer_bypass(target_url, prober, nonce)

        if vc in ("postmessage", "post_message", "postmessage_xss"):
            return await self._confirm_postmessage(target_url, prober, nonce)

        if vc in ("dom_clobbering", "dom_clobber", "bootstrap"):
            return await self._confirm_dom_clobbering(target_url, prober, nonce)

        if vc in ("csp", "csp_bypass", "csp_nonce"):
            return await self._confirm_csp(target_url, prober, nonce)

        if vc in ("rabbitmq_oauth", "rabbitmq", "rabbitmq_secret"):
            return await self._confirm_rabbitmq_secret(target_url, prober, nonce)

        if vc in ("onelogin_oidc", "onelogin", "oidc_secret"):
            return await self._confirm_onelogin_secret(
                target_url, prober, nonce, auth_header=auth_header
            )

        if vc in (
            "best_fit_charset",
            "worstfit",
            "php_cgi",
            "php_cgi_argument_injection",
        ):
            return await self._confirm_best_fit_charset(target_url, prober, nonce)

        if vc in (
            "dangerous_http_methods",
            "dangerous_methods",
            "http_methods",
            "tomcat_partial_put",
            "partial_put",
        ):
            return await self._confirm_dangerous_http_methods(target_url, prober, nonce)

        if vc not in _DIFFERENTIAL_CLASSES:
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class=vc,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                note=_NO_BENIGN_PROOF,
            )

        probes = benign_probe_variants(vc)
        if not probes:
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class=vc,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                note=_NO_BENIGN_PROOF,
            )

        best: Optional[ConfirmationResult] = None
        for probe in probes:
            res = await self._reproduce(target_url, param, vc, probe, prober)
            if res.confirmed:
                return res
            best = best or res
        return best

    async def _reproduce(
        self, target_url, param, vc, probe, prober
    ) -> ConfirmationResult:
        """Controlled differential + deliberate repeat for one benign probe."""
        exchanges: List[ProbeExchange] = []

        control_body = ""
        if probe.control:
            c = await prober.probe_param(target_url, param, probe.control)
            exchanges.append(
                ProbeExchange("control", c.url, c.status, "benign baseline value")
            )
            control_body = c.body if c.ok else ""

        p = await prober.probe_param(target_url, param, probe.payload)
        exchanges.append(ProbeExchange("payload", p.url, p.status, probe.note))
        hit = p.ok and assess_probe(
            probe, body=p.body, location=p.location, control_body=control_body
        )
        if not hit:
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class=vc,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=probe.note,
                exchanges=exchanges,
                summary="No benign signal for this probe/differential.",
            )

        # Deliberate repeat(s) to establish reproducibility (never a new payload).
        repeats_ok = 0
        for _ in range(self.repeats):
            r = await prober.probe_param(target_url, param, probe.payload)
            ok = r.ok and assess_probe(
                probe, body=r.body, location=r.location, control_body=control_body
            )
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    r.url,
                    r.status,
                    "signal reproduced" if ok else "signal absent on repeat",
                )
            )
            if ok:
                repeats_ok += 1
        reproduced = repeats_ok >= 1
        poc = self._poc(target_url, param, probe)

        # Reflection is a LEAD, never execution — it never graduates past
        # UNVERIFIED here, however reproducible the echo is.
        if probe.kind == "reflect":
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class=vc,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=probe.note,
                exchanges=exchanges,
                poc=poc,
                summary=(
                    "Unencoded reflection reproduced — a LEAD only. "
                    "Reflection != execution; manual review to prove XSS."
                ),
            )
        if reproduced:
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class=vc,
                confirmed=True,
                evidence_level=EvidenceLevel.REPRODUCED,
                technique=probe.note,
                exchanges=exchanges,
                poc=poc,
                summary=(
                    f"{vc.upper()} signal REPRODUCED via benign probe on "
                    f"{repeats_ok + 1} independent requests with a clean "
                    f"control differential."
                ),
            )
        return ConfirmationResult(
            target=target_url,
            param=param,
            vuln_class=vc,
            confirmed=True,
            evidence_level=probe.evidence,
            technique=probe.note,
            exchanges=exchanges,
            poc=poc,
            summary=(
                f"{vc.upper()} signal seen once with a clean control; "
                f"repeat did not re-trigger (stays {probe.evidence})."
            ),
        )

    async def _confirm_ssrf(
        self, target_url, param, oob_callback, prober, nonce
    ) -> ConfirmationResult:
        """Benign SSRF proof: one outbound GET to an operator-owned callback."""
        if not oob_callback:
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class="ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                note=(
                    "SSRF confirmation needs an EXTERNAL callback host you "
                    "control (pass --oob-callback, e.g. your interactsh / Burp "
                    "Collaborator URL). HYDRA will NOT fetch cloud-metadata or "
                    "internal hosts to 'prove' SSRF."
                ),
            )
        # Defense-in-depth: the callback itself must be a benign external host.
        if is_exploitation_payload(oob_callback):
            return ConfirmationResult(
                target=target_url,
                param=param,
                vuln_class="ssrf",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                note=(
                    "Refused: the callback resolves to an internal / loopback / "
                    "cloud-metadata host. Use an external host you own so the "
                    "proof stays benign."
                ),
            )
        nonce = nonce or uuid.uuid4().hex[:12]
        callback = self._with_nonce(oob_callback, nonce)
        r = await prober.probe_param(target_url, param, callback)
        exchanges = [
            ProbeExchange("oob-callback", r.url, r.status, f"armed nonce={nonce}")
        ]
        trigger = build_probe_url(target_url, param, callback)
        poc = "\n".join(
            [
                "# Safe SSRF proof — out-of-band callback to a host YOU control",
                "# 1) start a listener/collaborator on your callback host",
                f"# 2) trigger: curl -si '{trigger}'",
                f"# 3) a request landing on your listener carrying nonce={nonce} proves",
                "#    the server fetched an attacker-supplied URL (SSRF).",
                "#    Benign: no metadata host, internal host, or credentials requested.",
            ]
        )
        return ConfirmationResult(
            target=target_url,
            param=param,
            vuln_class="ssrf",
            confirmed=False,
            evidence_level=EvidenceLevel.INFERRED,
            technique="OOB callback",
            exchanges=exchanges,
            poc=poc,
            summary=(
                f"SSRF callback armed to your host (nonce={nonce}). "
                "Confirmation is out-of-band — check your listener."
            ),
            note=(
                "Raise to REPRODUCED once your listener records the nonce. "
                "This sends ONE benign outbound GET to a host you own."
            ),
        )

    @staticmethod
    def _with_nonce(url: str, nonce: str) -> str:
        parts = urlparse(url)
        path = (parts.path or "").rstrip("/") + "/" + nonce
        return urlunparse(parts._replace(path=path))

    @staticmethod
    def _poc(target_url, param, probe) -> str:
        lines = [f"# Safe reproduction — {probe.note or probe.kind} (benign probe)"]
        if probe.control:
            ctrl = build_probe_url(target_url, param, probe.control)
            lines.append("# control (benign baseline — signal should be ABSENT):")
            lines.append(f"curl -si '{ctrl}'")
        demo = build_probe_url(target_url, param, probe.payload)
        lines.append("# probe:")
        lines.append(f"curl -si '{demo}'")
        where = "Location header" if probe.kind == "redirect" else "body"
        lines.append(f"# expect in {where}: {', '.join(probe.signatures)}")
        return "\n".join(lines)


__all__ = ["ConfirmationEngine", "ConfirmationResult", "ProbeExchange"]


def __getattr__(name):
    # Preserve existing imports of diagnostic constants while their definitions
    # live in one place. New code should use the public engine/result API.
    from hydra.hunt.confirmation import signatures

    if name.startswith("_") and not name.startswith("__") and hasattr(signatures, name):
        return getattr(signatures, name)
    raise AttributeError(name)
