"""SecretExposureChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from urllib.parse import urlparse
from hydra.hunt.safety import (
    EvidenceLevel,
    scan_body_for_secrets,
    summarize_secret_exposures,
)
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import _ONELOGIN_APP_PATHS, _RABBITMQ_AUTH_PATHS

logger = logging.getLogger("hydra.hunt.confirm")


class SecretExposureChecks:
    async def _confirm_rabbitmq_secret(self, target_url, prober, nonce):
        """CVE-2026-5721 — RabbitMQ management OAuth client_secret leak.

        UNAUTHENTICATED GET of the management API's auth endpoint; if the broker
        overshares its OAuth config a ``client_secret``-class KEY is present in
        the body. HYDRA reports the KEY's presence (value redacted) only — it
        never reads or reuses the secret. OBSERVED on one exposure, REPRODUCED
        when a repeat GET re-exposes the same key."""
        return await self._confirm_secret_overshare(
            target_url,
            prober,
            nonce,
            vuln_class="rabbitmq_oauth",
            technique=(
                "CVE-2026-5721 RabbitMQ management plugin unauth OAuth "
                "client_secret leak (presence-only, value redacted)"
            ),
            paths=_RABBITMQ_AUTH_PATHS,
            auth_header="",
            require_auth=False,
        )

    async def _confirm_onelogin_secret(self, target_url, prober, nonce, auth_header=""):
        """CVE-2025-59363 — OneLogin OIDC app-listing client_secret overshare.

        AUTHENTICATED GET of the admin app-listing endpoint using the OPERATOR'S
        OWN in-scope API credential (``--confirm-auth-header``). If the endpoint
        overshares, each app's ``client_secret``/``api_key`` KEY is present in
        the body; HYDRA reports presence (value redacted) only. It never mints,
        guesses, reuses, or pivots with a leaked secret. Without the operator's
        own token nothing is sent."""
        return await self._confirm_secret_overshare(
            target_url,
            prober,
            nonce,
            vuln_class="onelogin_oidc",
            technique=(
                "CVE-2025-59363 OneLogin OIDC app-listing client_secret "
                "overshare (operator-token, presence-only, redacted)"
            ),
            paths=_ONELOGIN_APP_PATHS,
            auth_header=auth_header,
            require_auth=True,
        )

    async def _confirm_secret_overshare(
        self,
        target_url,
        prober,
        nonce,
        vuln_class,
        technique,
        paths,
        auth_header,
        require_auth,
    ):
        """Shared engine for P2/P5 authorized secret-overshare checks.

        GETs the target's OWN endpoint(s) — unauthenticated (RabbitMQ) or with
        the operator's OWN in-scope credential header (OneLogin) — and uses
        :func:`scan_body_for_secrets` to prove a sensitive KEY is exposed, with
        the VALUE redacted to presence + length + salted fingerprint. A
        deliberate repeat GET that re-exposes the SAME key raises evidence to
        REPRODUCED. HYDRA never reads, echoes, stores, or authenticates with the
        leaked secret, and never pivots with it.
        """
        nonce = nonce or uuid.uuid4().hex[:12]
        cred_headers = None
        if auth_header:
            name, sep, value = str(auth_header).partition(":")
            if sep and name.strip():
                cred_headers = {name.strip(): value.strip()}
        if require_auth and not cred_headers:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class=vuln_class,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=technique,
                summary="This check needs the operator's OWN in-scope API "
                "credential; pass it with --confirm-auth-header "
                "'Authorization: Bearer <your-token>'. Nothing was sent.",
                note="DETECT-ONLY: HYDRA only forwards a credential you already "
                "own against a target you are authorized to test; it never "
                "mints, guesses, or reuses a leaked secret.",
            )

        origin = self._origin(target_url)
        candidates = []
        probe_tgt = target_url if "//" in target_url else "https://" + target_url
        if urlparse(probe_tgt).path.strip("/"):
            candidates.append(target_url)  # operator pointed at an endpoint
        candidates.extend(origin + p for p in paths)
        ordered, seen = [], set()
        for u in candidates:
            if u not in seen:
                seen.add(u)
                ordered.append(u)

        exchanges: List[ProbeExchange] = []
        reached_any = False
        for idx, url in enumerate(ordered):
            resp = await prober.get(url, credential_headers=cred_headers)
            exchanges.append(
                ProbeExchange(
                    "control" if idx == 0 else "fingerprint",
                    resp.url or url,
                    resp.status,
                    "GET endpoint — detect exposed secret KEY (value redacted)",
                )
            )
            if resp.error and "refused" in resp.error:
                continue
            if not resp.ok:
                continue
            reached_any = True
            hits = scan_body_for_secrets(resp.body)
            if not hits:
                continue
            repeat = await prober.get(url, credential_headers=cred_headers)
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    repeat.url or url,
                    repeat.status,
                    "repeat GET — confirm the same secret key re-exposes",
                )
            )
            hits2 = scan_body_for_secrets(repeat.body) if repeat.ok else []
            level = EvidenceLevel.OBSERVED
            if hits2 and self._same_secret_exposed(hits, hits2):
                level = EvidenceLevel.REPRODUCED
            summary = (
                "Sensitive credential key(s) exposed at "
                + url
                + ": "
                + summarize_secret_exposures(hits)
                + ". Values are REDACTED — HYDRA proves presence only."
            )
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class=vuln_class,
                confirmed=True,
                evidence_level=level,
                technique=technique,
                exchanges=exchanges,
                summary=summary,
                poc=self._secret_overshare_poc(url, hits, auth_header),
                note="DETECT-ONLY: HYDRA GETs the endpoint and reports which "
                "secret KEY names are present plus each value's length and "
                "a salted, non-reversible fingerprint. It NEVER reads, "
                "logs, echoes, or authenticates with the secret value, and "
                "never pivots with it. Rotate the exposed credential and "
                "restrict the endpoint to authorized readers.",
            )

        if not reached_any:
            return ConfirmationResult(
                target=target_url,
                param="",
                vuln_class=vuln_class,
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                technique=technique,
                exchanges=exchanges,
                summary="Endpoint(s) did not return a readable response; cannot "
                "assess secret overshare.",
            )
        return ConfirmationResult(
            target=target_url,
            param="",
            vuln_class=vuln_class,
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=technique,
            exchanges=exchanges,
            summary="Endpoint responded but exposed no populated secret-named "
            "keys; no overshare confirmed (values redacted either way).",
        )

    @staticmethod
    def _same_secret_exposed(hits_a, hits_b) -> bool:
        """True if two exposure sets share a secret — same fingerprint (same
        value) OR the same key path when the value is too short to fingerprint.
        Lets a stable repeat raise evidence to REPRODUCED without ever comparing
        the secret values themselves."""
        fp_a = {h.fingerprint for h in hits_a if h.fingerprint}
        fp_b = {h.fingerprint for h in hits_b if h.fingerprint}
        if fp_a & fp_b:
            return True
        return bool({h.path for h in hits_a} & {h.path for h in hits_b})

    @staticmethod
    def _secret_overshare_poc(url, hits, auth_header) -> str:
        """Value-free reproduction recipe. Lists only the exposed KEY paths
        (redacted); never prints a secret value."""
        auth = ""
        if auth_header:
            hdr = str(auth_header).partition(":")[0].strip() or "Authorization"
            auth = f" -H '{hdr}: <YOUR-OWN-IN-SCOPE-TOKEN>'"
        lines = [
            "# Safe reproduction — authorized secret-overshare check (DETECT-ONLY)",
            "# (benign: a single GET; HYDRA reads only WHICH secret keys appear)",
            f"curl -s{auth} '{url}' \\",
            "  | jq -r 'paths(scalars) as $p | select(($p[-1]|tostring)"
            '|test("secret|api_?key|token|password|passphrase";"i")) '
            '| $p|join(".")\'',
            "# exposed secret key(s) — VALUES REDACTED:",
        ]
        lines += [f"#   - {h.redacted()}" for h in hits]
        lines += [
            "# NOTE: HYDRA never prints the secret value and never uses a leaked",
            "#   secret to authenticate or pivot. Rotate it and restrict the",
            "#   endpoint to authorized readers.",
        ]
        return "\n".join(lines)
