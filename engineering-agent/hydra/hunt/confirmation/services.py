"""ServiceChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from urllib.parse import urlparse
from hydra.hunt.safety import EvidenceLevel
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import (
    _K8S_ADMISSION_FINGERPRINTS,
    _K8S_HEALTHZ_PATH,
    _K8S_WEBHOOK_PATH,
    _SAP_APP_ROOT,
    _SAP_FINGERPRINTS,
    _SAP_UPLOADER_PATH,
    _VITE_BYPASS_SUFFIXES,
    _VITE_DENY_CANARIES,
)

logger = logging.getLogger("hydra.hunt.confirm")


class ServiceChecks:
    async def _confirm_sap(self, target_url, prober, nonce="") -> ConfirmationResult:
        """Benign CVE-2025-31324 proof: an unauthenticated REACHABILITY differential.

        We GET the well-known SAP NetWeaver Visual Composer metadata-uploader
        endpoint and a random sibling path under the same servlet context (the
        control). If the uploader answers as reachable-without-auth (not
        401/403, not a redirect-to-login, not 404) AND its status differs from
        the random sibling (so it is a real handler, not a catch-all), the
        pre-auth exposure CVE-2025-31324 depends on is present. HYDRA records
        REACHABILITY ONLY — it never sends the multipart POST that uploads a JSP
        webshell (that upload IS the exploit), so this stays at OBSERVED and
        never claims RCE.
        """
        origin = self._origin(target_url)
        endpoint = origin + _SAP_UPLOADER_PATH
        nonce = nonce or uuid.uuid4().hex[:12]
        control_url = origin + _SAP_APP_ROOT + nonce
        tech = "CVE-2025-31324 pre-auth reachability"
        exchanges: List[ProbeExchange] = []

        # Control: a random, certainly-nonexistent path under the same servlet
        # context — distinguishes a real handler from a catch-all that answers
        # every path alike.
        ctrl = await prober.get(control_url)
        exchanges.append(
            ProbeExchange(
                "control",
                ctrl.url,
                ctrl.status,
                f"random sibling path under {_SAP_APP_ROOT} (nonce={nonce})",
            )
        )

        probe = await prober.get(endpoint)
        exchanges.append(
            ProbeExchange(
                "payload", probe.url, probe.status, "GET metadata-uploader (no auth)"
            )
        )
        if not probe.ok:
            return ConfirmationResult(
                target=endpoint,
                param="",
                vuln_class="sap",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Endpoint request failed; cannot assess reachability.",
                note=probe.error or "no response",
            )

        # Access-gated: authentication / redirect-to-login is exactly what a
        # patched or protected NetWeaver returns — NOT the unauth exposure.
        gated = probe.status in (401, 403) or (
            300 <= probe.status < 400 and bool(probe.location)
        )
        if gated:
            return ConfirmationResult(
                target=endpoint,
                param="",
                vuln_class="sap",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"metadata-uploader is access-gated (HTTP {probe.status}"
                    + (f" → {probe.location}" if probe.location else "")
                    + ") — authentication/redirect enforced, not the "
                    "unauthenticated exposure (protected or patched)."
                ),
            )
        # SAP_CONFIRM_PLACEHOLDER
        # Absent: 404 — the Visual Composer uploader servlet is not deployed.
        if probe.status == 404:
            return ConfirmationResult(
                target=endpoint,
                param="",
                vuln_class="sap",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "metadata-uploader returns HTTP 404 — the NetWeaver "
                    "Visual Composer uploader servlet is not present here "
                    "(not deployed or path removed)."
                ),
            )

        # Catch-all guard: if the random sibling returns the SAME status we
        # cannot claim a specific reachable handler — the server answers alike.
        if ctrl.ok and ctrl.status == probe.status:
            return ConfirmationResult(
                target=endpoint,
                param="",
                vuln_class="sap",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"Both the uploader and a random sibling path return "
                    f"HTTP {probe.status} — indistinguishable from a "
                    "catch-all response; no reliable reachability "
                    "differential."
                ),
            )

        # Reachable pre-auth AND distinguishable from the control → the exposure
        # precondition for CVE-2025-31324 is present. Deliberate repeat rules out
        # a transient blip; reachability is a STATIC property, so this stays
        # OBSERVED — it never graduates to REPRODUCED like a triggered behaviour.
        stable = 0
        for _ in range(self.repeats):
            r = await prober.get(endpoint)
            ok = r.ok and r.status == probe.status
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    r.url,
                    r.status,
                    "reachable on repeat" if ok else "status changed on repeat",
                )
            )
            if ok:
                stable += 1

        fp = self._sap_fingerprint(probe)
        note = (
            "Reachability only: the unauthenticated metadata-uploader "
            "endpoint is exposed — the precondition CVE-2025-31324 exploits "
            "via a JSP webshell upload. HYDRA did NOT send the multipart POST "
            "upload (that upload IS the exploit) and did not touch the "
            "CVE-2025-42999 deserialization sink. Confirm exploitability "
            "manually within your authorization."
        )
        if not ctrl.ok:
            note = (
                "(control path could not be fetched — reachability is based "
                "on the endpoint response alone.) "
            ) + note
        if fp:
            note = f"SAP fingerprint observed ({fp}). " + note
        held = f", reachability held on {stable + 1} requests" if stable else ""
        return ConfirmationResult(
            target=endpoint,
            param="",
            vuln_class="sap",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            poc=self._sap_poc(endpoint, control_url, probe.status),
            summary=(
                f"SAP NetWeaver metadata-uploader reachable WITHOUT auth "
                f"(HTTP {probe.status}; random sibling path was HTTP "
                f"{ctrl.status}{held}). "
                f"{'SAP fingerprint present. ' if fp else ''}"
                "Pre-auth exposure precondition for CVE-2025-31324."
            ),
            note=note,
        )

    async def _confirm_vite(self, target_url, prober, nonce="") -> ConfirmationResult:
        """Benign CVE-2025-30208 proof: a server.fs.deny bypass PRESENCE differential.

        Vite's dev server blocks files matching ``server.fs.deny`` (default:
        .env, .env.*, *.{crt,pem}, **/.git/**) with HTTP 403 BEFORE it checks
        whether the file exists. On a vulnerable Vite a trailing-separator query
        trick (``?raw??`` / ``?import&raw??``) makes the deny check get skipped
        so the request reaches the file loader. HYDRA proves ONLY the PRESENCE of
        that bypass with a pure STATUS differential on a guaranteed-NONEXISTENT,
        nonce'd canary that matches a default deny pattern:

          (0) a normal non-denied path (/<nonce>.txt) establishes the not-found
              status and rules out a server that answers 403 to everything;
          (1) the denied canary (/.env.<nonce>, /<nonce>.pem) must return 403 —
              the deny filter is active and distinct from the normal status;
          (2) the SAME canary + a benign bypass suffix flips AWAY from 403 (the
              loader is reached for a file that does not exist) → the deny check
              was skipped.

        The canary NEVER names a real sensitive file (it is nonce'd), HYDRA reads
        ZERO file content, and uses NO ``../`` traversal, ``file://``, or
        ``/@fs/`` path. Status/error only — presence is static, so this caps at
        OBSERVED and never claims a secret was read.
        """
        origin = self._origin(target_url)
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = "CVE-2025-30208 Vite server.fs.deny bypass"
        exchanges: List[ProbeExchange] = []

        # (0) A normal, certainly-nonexistent, NON-denied path. Establishes the
        # "not found" status and rules out a server that 403s indiscriminately
        # (which would make the canary's 403 carry no signal).
        normal_url = f"{origin}/{nonce}.txt"
        normal = await prober.get(normal_url)
        exchanges.append(
            ProbeExchange(
                "control",
                normal.url,
                normal.status,
                f"normal non-denied nonexistent path (nonce={nonce})",
            )
        )
        if not normal.ok:
            return ConfirmationResult(
                target=origin,
                param="",
                vuln_class="vite",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline request failed; cannot assess the differential.",
                note=normal.error or "no response",
            )
        if normal.status == 403:
            return ConfirmationResult(
                target=origin,
                param="",
                vuln_class="vite",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "A normal non-denied path also returns HTTP 403 — the "
                    "server 403s indiscriminately, so a canary 403 carries "
                    "no signal. No reliable server.fs.deny differential."
                ),
            )
        # VITE_TAIL_PLACEHOLDER
        # (1)+(2) For each default-deny-pattern canary, confirm the deny filter
        # is active (403) then test whether a benign bypass suffix skips it.
        for canary in _VITE_DENY_CANARIES:
            name = canary.format(nonce=nonce)
            denied_url = f"{origin}/{name}"
            denied = await prober.get(denied_url)
            exchanges.append(
                ProbeExchange(
                    "payload",
                    denied.url,
                    denied.status,
                    "denied canary (matches a default server.fs.deny pattern)",
                )
            )
            # The deny filter must be active (403) AND distinct from the normal
            # not-found status — otherwise there is nothing to bypass here.
            if not (denied.ok and denied.status == 403 and normal.status != 403):
                continue

            for suffix in _VITE_BYPASS_SUFFIXES:
                bypass_url = denied_url + suffix
                b = await prober.get(bypass_url)
                exchanges.append(
                    ProbeExchange(
                        "payload", b.url, b.status, f"deny canary + '{suffix}'"
                    )
                )
                # A flip AWAY from 403 (the loader was reached for a nonexistent
                # file) = the deny check was skipped = the bypass is present.
                if not (b.ok and b.status != 403):
                    continue
                stable = 0
                for _ in range(self.repeats):
                    r = await prober.get(bypass_url)
                    ok = r.ok and r.status != 403
                    exchanges.append(
                        ProbeExchange(
                            "repeat",
                            r.url,
                            r.status,
                            "bypass reproduced" if ok else "deny re-applied on repeat",
                        )
                    )
                    if ok:
                        stable += 1
                held = f"; bypass held on {stable + 1} requests" if stable else ""
                return ConfirmationResult(
                    target=denied_url,
                    param="",
                    vuln_class="vite",
                    confirmed=True,
                    evidence_level=EvidenceLevel.OBSERVED,
                    technique=tech,
                    exchanges=exchanges,
                    poc=self._vite_poc(denied_url, suffix, denied.status, b.status),
                    summary=(
                        f"Vite server.fs.deny bypass present "
                        f"(CVE-2025-30208): a deny-listed canary was HTTP "
                        f"{denied.status} but HTTP {b.status} with the "
                        f"'{suffix}' suffix (deny filter skipped, file "
                        f"loader reached){held}. Canary is nonexistent and "
                        "nonce'd — no file content was read."
                    ),
                    note=(
                        "PRESENCE only: the trailing-separator trick skips the "
                        "server.fs.deny check so the request reaches the file "
                        "loader. HYDRA used a guaranteed-NONEXISTENT nonce'd "
                        "canary, read ZERO file content, and used NO ../ "
                        "traversal, file://, or /@fs/ path. To confirm a real "
                        "deny-listed file is readable, do so manually within "
                        "your authorization."
                    ),
                )

        # No canary produced an active-deny → bypass flip.
        return ConfirmationResult(
            target=origin,
            param="",
            vuln_class="vite",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique=tech,
            summary=(
                "No server.fs.deny bypass observed — either the deny filter "
                "is not active on the tested canaries (no HTTP 403 to "
                "bypass) or a benign bypass suffix did not skip it (not "
                "vulnerable / patched)."
            ),
        )

    async def _confirm_k8s_admission(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2025-1974 (IngressNightmare) proof: an EXPOSURE differential.

        The ingress-nginx admission controller (default :8443) should be
        reachable only by the in-cluster kube-apiserver over mTLS. We GET
        ``/healthz`` from outside, presenting NO client certificate; if it
        answers 200 and the admission webhook path identifies the service
        (rejects a bare GET with 405 / a content-type error / "AdmissionReview"),
        the controller is externally reachable without client-cert auth — the
        exposure precondition CVE-2025-1974 needs. HYDRA records REACHABILITY /
        POSTURE ONLY: it NEVER sends the AdmissionReview POST that injects the
        malicious Ingress object (that POST IS the RCE), so this stays at
        OBSERVED and never claims code execution.
        """
        origin = self._origin(target_url)
        nonce = nonce or uuid.uuid4().hex[:12]
        tech = (
            "CVE-2025-1974 ingress-nginx admission-controller exposure "
            "(IngressNightmare)"
        )
        exchanges: List[ProbeExchange] = []

        # Control: a random, certainly-nonexistent path — distinguishes a real
        # liveness handler from a catch-all that answers every path alike.
        control_url = f"{origin}/{nonce}-hydra-nope"
        ctrl = await prober.get(control_url)
        exchanges.append(
            ProbeExchange(
                "control",
                ctrl.url,
                ctrl.status,
                f"random nonexistent path (nonce={nonce})",
            )
        )

        # Probe 1 — /healthz liveness, presenting NO client certificate.
        hz_url = origin + _K8S_HEALTHZ_PATH
        hz = await prober.get(hz_url)
        exchanges.append(
            ProbeExchange("payload", hz.url, hz.status, "GET /healthz (no client cert)")
        )
        if not hz.ok:
            return ConfirmationResult(
                target=hz_url,
                param="",
                vuln_class="k8s_admission",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    "Admission-controller /healthz request failed — the "
                    "service may be firewalled / internal-only (the SAFE "
                    "state) or simply down. Exposure cannot be concluded."
                ),
                note=hz.error or "no response",
            )
        # K8S_REST_1

        # Access-gated healthz (auth / redirect-to-login) → access control is
        # enforced; this is NOT the open, unauthenticated admission exposure.
        gated = hz.status in (401, 403) or (
            300 <= hz.status < 400 and bool(hz.location)
        )
        if gated:
            return ConfirmationResult(
                target=hz_url,
                param="",
                vuln_class="k8s_admission",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"/healthz is access-gated (HTTP {hz.status}"
                    + (f" → {hz.location}" if hz.location else "")
                    + ") — access control enforced, not the open "
                    "admission-controller exposure."
                ),
            )

        # Probe 2 — the admission webhook path, GET ONLY (never the AdmissionReview
        # POST). We read ONLY the status + error string to fingerprint the service.
        wh_url = origin + _K8S_WEBHOOK_PATH
        wh = await prober.get(wh_url)
        exchanges.append(
            ProbeExchange(
                "fingerprint",
                wh.url,
                wh.status,
                "GET admission webhook path (no AdmissionReview POST)",
            )
        )

        fp = self._k8s_admission_fingerprint(hz, wh)

        # Catch-all guard: if the random sibling returns the SAME status as
        # /healthz AND there is no admission signature, we cannot claim a specific
        # exposed admission handler — the server answers alike.
        if ctrl.ok and ctrl.status == hz.status and not fp:
            return ConfirmationResult(
                target=hz_url,
                param="",
                vuln_class="k8s_admission",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"/healthz and a random path both return HTTP "
                    f"{hz.status} with no admission-controller signature — "
                    "indistinguishable from a catch-all; not confirmed."
                ),
            )
        # K8S_REST_2

        # Require an admission-controller IDENTITY: a bare /healthz 200 is not
        # specific to ingress-nginx, so without a signature HYDRA will not label
        # this an exposed admission controller (honest fail-to-not-confirmed).
        if hz.status != 200 or not fp:
            return ConfirmationResult(
                target=hz_url,
                param="",
                vuln_class="k8s_admission",
                confirmed=False,
                evidence_level=EvidenceLevel.OBSERVED,
                exchanges=exchanges,
                technique=tech,
                summary=(
                    f"A service responded (/healthz HTTP {hz.status}) but no "
                    "ingress-nginx admission-controller signature was "
                    "observed — this may not be the admission webhook; not "
                    "confirmed."
                ),
            )

        # Reachable + identified. A deliberate repeat rules out a transient blip;
        # reachability/posture is a STATIC property, so this stays OBSERVED — it
        # never graduates to REPRODUCED like a triggered behaviour.
        stable = 0
        for _ in range(self.repeats):
            r = await prober.get(hz_url)
            ok = r.ok and r.status == hz.status
            exchanges.append(
                ProbeExchange(
                    "repeat",
                    r.url,
                    r.status,
                    "reachable on repeat" if ok else "status changed on repeat",
                )
            )
            if ok:
                stable += 1

        held = f", reachability held on {stable + 1} requests" if stable else ""
        note = (
            "Exposure / posture only: the ingress-nginx admission controller "
            "answered an unauthenticated, client-cert-less GET from outside "
            "the cluster — the precondition CVE-2025-1974 (IngressNightmare) "
            "exploits via an AdmissionReview POST carrying a crafted Ingress "
            "object. HYDRA did NOT send that POST (it IS the RCE). Confirm "
            "exploitability manually within your authorization."
        )
        if not ctrl.ok:
            note = (
                "(control path could not be fetched — exposure is based on "
                "the /healthz + webhook responses alone.) "
            ) + note
        return ConfirmationResult(
            target=hz_url,
            param="",
            vuln_class="k8s_admission",
            confirmed=True,
            evidence_level=EvidenceLevel.OBSERVED,
            technique=tech,
            exchanges=exchanges,
            poc=self._k8s_admission_poc(
                hz_url, wh_url, control_url, hz.status, wh.status
            ),
            summary=(
                f"ingress-nginx admission controller reachable WITHOUT a "
                f"client certificate (/healthz HTTP {hz.status}; webhook "
                f"path HTTP {wh.status}{held}). Admission signature present "
                f"({fp}). External-exposure precondition for CVE-2025-1974 "
                "(IngressNightmare)."
            ),
            note=note,
        )

    @staticmethod
    def _origin(url: str) -> str:
        """scheme://netloc for a target, tolerating a bare host or a full path."""
        parts = urlparse(url if "//" in (url or "") else "https://" + (url or ""))
        scheme = parts.scheme or "https"
        netloc = parts.netloc or parts.path
        return f"{scheme}://{netloc}".rstrip("/")

    @staticmethod
    def _sap_fingerprint(resp) -> str:
        """Passive SAP fingerprint from the Server banner + body — annotation."""
        server = ""
        for k, v in (resp.headers or {}).items():
            if str(k).lower() == "server":
                server = str(v)
                break
        hay = (server + " " + (resp.body or "")).lower()
        hits = [m for m in _SAP_FINGERPRINTS if m in hay]
        return ", ".join(hits[:4])

    @staticmethod
    def _sap_poc(endpoint, control_url, status) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-31324 SAP NetWeaver metadata-uploader",
                "# (benign: an UNAUTHENTICATED GET reachability differential; no upload)",
                "# control — a random sibling path (expect 404 / not-found):",
                f"curl -si '{control_url}'",
                f"# uploader endpoint — expect reachable without auth (HTTP {status},",
                "#   NOT 401/403/redirect-to-login):",
                f"curl -si '{endpoint}'",
                "# NOTE: HYDRA never sends the multipart POST webshell upload — that",
                "#   upload IS the exploit. Reachability is the finding; confirm",
                "#   impact manually within your authorization.",
            ]
        )

    @staticmethod
    def _k8s_admission_fingerprint(hz, wh) -> str:
        """Passive ingress-nginx admission-controller signature from the two
        GET responses. Two independent signal sources, both benign:
          * banner/body markers (Server header + /healthz body + webhook body),
          * a STRUCTURAL signal — the webhook path rejecting a plain GET with
            400/405/415 is exactly how the AdmissionReview handler behaves when
            it is handed something other than a JSON AdmissionReview POST.
        Returns the joined hits; empty string means no admission identity (so the
        caller will NOT confirm — a bare /healthz 200 is not admission-specific).
        """

        def _server(resp) -> str:
            for k, v in (getattr(resp, "headers", {}) or {}).items():
                if str(k).lower() == "server":
                    return str(v)
            return ""

        hay = " ".join(
            [
                _server(hz),
                getattr(hz, "body", "") or "",
                _server(wh),
                getattr(wh, "body", "") or "",
            ]
        ).lower()
        hits = [m for m in _K8S_ADMISSION_FINGERPRINTS if m in hay]
        if getattr(wh, "status", 0) in (400, 405, 415):
            hits.append(f"webhook-rejects-GET:{wh.status}")
        return ", ".join(hits[:5])

    @staticmethod
    def _k8s_admission_poc(hz_url, wh_url, control_url, hz_status, wh_status) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-1974 ingress-nginx admission exposure",
                "#   (IngressNightmare). Benign: three GET requests, no client cert,",
                "#   no AdmissionReview POST. Proves only the external-reachability",
                "#   precondition — the admission webhook is meant to be reachable",
                "#   ONLY by the in-cluster kube-apiserver over mTLS.",
                "# control — a random sibling path (expect not-found / different):",
                f"curl -sik '{control_url}'",
                f"# liveness — expect reachable without a client cert (HTTP {hz_status}):",
                f"curl -sik '{hz_url}'",
                f"# admission webhook path, GET only — expect a webhook signature",
                f"#   (HTTP {wh_status}: 405/415/400 or an AdmissionReview banner):",
                f"curl -sik '{wh_url}'",
                "# NOTE: HYDRA never sends the AdmissionReview POST carrying a crafted",
                "#   Ingress object — that POST IS the RCE. Exposure is the finding;",
                "#   confirm exploitability manually within your authorization.",
            ]
        )

    @staticmethod
    def _vite_poc(denied_url, suffix, denied_status, bypass_status) -> str:
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-30208 Vite server.fs.deny bypass",
                "# (benign: a STATUS differential on a NONEXISTENT nonce'd canary; no read)",
                f"# denied canary — expect the deny filter active (HTTP {denied_status}):",
                f"curl -si '{denied_url}'",
                "# same canary + bypass suffix — expect a flip away from 403",
                f"#   (HTTP {bypass_status}, file loader reached):",
                f"curl -si '{denied_url}{suffix}'",
                "# NOTE: the canary is nonce'd and does NOT exist — HYDRA reads no file",
                "#   content and uses no ../ traversal, file://, or /@fs/ path. To",
                "#   confirm a real deny-listed file is readable, do so manually in scope.",
            ]
        )
