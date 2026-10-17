"""HTTPChecks: existing checks without policy or payload changes."""

import logging
import uuid
from typing import List
from urllib.parse import urlparse
from hydra.hunt.safety import EvidenceLevel, is_exploitation_payload
from hydra.hunt.confirmation.models import ProbeExchange, ConfirmationResult


from hydra.hunt.confirmation.signatures import (
    _DANGEROUS_WRITE_METHODS,
    _PARTIAL_PUT_METHOD,
    _TOMCAT_SERVER_RE,
    _WORSTFIT_FLAGS,
    _WORSTFIT_PHP_PATHS,
    _WORSTFIT_SOFT_HYPHEN,
    _WORSTFIT_VERSION_RE,
)

logger = logging.getLogger("hydra.hunt.confirm")


class HTTPChecks:
    async def _confirm_best_fit_charset(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2024-4577 proof: a Windows PHP-CGI "WorstFit" Best-Fit
        charset ARGUMENT-INJECTION precondition differential.

        On Windows, php-cgi.exe is reached through a code path that applies the
        active locale's Best-Fit mapping to the raw query string AFTER the web
        server quotes it. A benign Unicode look-alike — U+00AD SOFT HYPHEN, sent
        as the single percent-octet ``%AD`` — folds to an ASCII ``-``, so a query
        of ``?%ADv`` reaches php-cgi as the command-line flag ``-v``. HYDRA proves
        ONLY that the look-alike is Best-Fit-mapped onto a CLI flag, using the
        single READ-ONLY ``-v``/``-V`` (print version) flag:

          (0) a plain control GET of the PHP endpoint — the ``php -v`` version
              banner should be ABSENT (normal app output);
          (1) the SAME endpoint + ``?%ADv`` — if the version banner now appears
              (and it did NOT in the control) the look-alike was folded into the
              ``-v`` flag and injected onto the php-cgi command line.

        Hard benign boundary: HYDRA injects ONLY a flag from ``_WORSTFIT_FLAGS``
        ({-v, -V}, print version — read-only; no file/dir/env/code access). It
        NEVER injects ``-d`` (set a php.ini directive → the auto_prepend_file /
        php://input RCE chain), ``-s`` (source / file disclosure), ``-r`` / ``-f``
        (run code / a file) or ``-i`` (phpinfo → env & secret leak), and it NEVER
        sends the ``php://input`` POST body that completes CVE-2024-4577 RCE. The
        version banner is public fingerprint data; the FINDING is the injection
        CHANNEL, not RCE, so this caps at OBSERVED and is never 'critical'.
        """
        tech = "CVE-2024-4577 PHP-CGI Best-Fit (WorstFit) argument injection"
        nonce = nonce or uuid.uuid4().hex[:12]  # not sent; stable run id for logs
        candidates = self._worstfit_candidates(target_url)
        exchanges: List[ProbeExchange] = []
        saw_ok_control = False
        last_error = ""

        for php_url in candidates:
            # (0) Plain control — the version banner must be ABSENT here, else
            # the endpoint itself prints a PHP version and the differential is
            # void (no injection can be inferred from a pre-existing banner).
            control = await prober.get(php_url)
            exchanges.append(
                ProbeExchange(
                    "control",
                    control.url,
                    control.status,
                    "plain request (php -v version banner should be ABSENT)",
                )
            )
            if not control.ok:
                last_error = control.error or "no response"
                continue
            saw_ok_control = True
            if self._php_version_banner(control.body):
                exchanges.append(
                    ProbeExchange(
                        "control",
                        control.url,
                        control.status,
                        "endpoint already emits a PHP version banner — differential "
                        "void; skipped (no injection inferred from a pre-existing "
                        "banner)",
                    )
                )
                continue

            for flag in _WORSTFIT_FLAGS:
                probe_url = f"{php_url}?{_WORSTFIT_SOFT_HYPHEN}{flag}"
                # Defence-in-depth: a bare -v/-V look-alike carries no
                # exploitation marker, so the safety gate must pass it. If a
                # future gate change ever flips that, SKIP the probe — never
                # weaken the gate to force it through.
                if is_exploitation_payload(probe_url):
                    exchanges.append(
                        ProbeExchange(
                            "payload",
                            probe_url,
                            0,
                            "benign version-flag probe unexpectedly refused by the "
                            "safety gate — skipped (gate held, never weakened)",
                        )
                    )
                    continue
                hit = await prober.get(probe_url)
                banner = self._php_version_banner(hit.body) if hit.ok else ""
                exchanges.append(
                    ProbeExchange(
                        "payload",
                        hit.url,
                        hit.status,
                        f"look-alike '%AD{flag}' (U+00AD → '-') → '-{flag}'; "
                        + (
                            "php version banner PRESENT (flag injected)"
                            if banner
                            else "no version banner (flag not injected)"
                        ),
                    )
                )
                if not banner:
                    continue

                # Re-request to show the injection channel is stable. The
                # presence of the channel is a static property of the target, so
                # this still caps at OBSERVED — we only record how often it held.
                stable = 0
                for _ in range(self.repeats):
                    r = await prober.get(probe_url)
                    ok = r.ok and bool(self._php_version_banner(r.body))
                    exchanges.append(
                        ProbeExchange(
                            "repeat",
                            r.url,
                            r.status,
                            "banner reproduced" if ok else "banner absent on repeat",
                        )
                    )
                    if ok:
                        stable += 1
                held = f"; injection held on {stable + 1} requests" if stable else ""
                return ConfirmationResult(
                    target=php_url,
                    param="",
                    vuln_class="best_fit_charset",
                    confirmed=True,
                    evidence_level=EvidenceLevel.OBSERVED,
                    technique=tech,
                    exchanges=exchanges,
                    poc=self._worstfit_poc(php_url, flag, control.status, hit.status),
                    summary=(
                        f"PHP-CGI Best-Fit (WorstFit) argument injection present "
                        f"(CVE-2024-4577): a plain request to {php_url} showed no "
                        f"PHP version banner, but the Unicode look-alike "
                        f"'%AD{flag}' (U+00AD → '-') produced a 'php -{flag}' "
                        f"version banner (HTTP {hit.status}) — the look-alike was "
                        f"folded onto the php-cgi command line as the read-only "
                        f"-{flag} flag{held}. Only the public version flag was "
                        f"injected; no code was run."
                    ),
                    note=(
                        "PRECONDITION / injection CHANNEL only. HYDRA injected "
                        "ONLY the read-only -v/-V version flag via a benign U+00AD "
                        "look-alike. It NEVER injected -d (the allow_url_include / "
                        "auto_prepend_file=php://input RCE directive), -s "
                        "(source/file disclosure), -r/-f (run code/a file) or -i "
                        "(phpinfo), and NEVER sent the php://input POST body that "
                        "completes CVE-2024-4577. Confirm RCE manually within your "
                        "authorization — HYDRA will not."
                    ),
                )

        if not saw_ok_control:
            return ConfirmationResult(
                target=self._origin(target_url),
                param="",
                vuln_class="best_fit_charset",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline request failed; cannot assess the differential.",
                note=last_error or "no response",
            )
        return ConfirmationResult(
            target=self._origin(target_url),
            param="",
            vuln_class="best_fit_charset",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique=tech,
            summary=(
                "No PHP-CGI Best-Fit argument-injection channel observed — "
                "the look-alike '%ADv'/'%ADV' did not surface a PHP version "
                "banner (not Windows php-cgi, patched, or no PHP-CGI handler "
                "on the tested paths)."
            ),
            note=(
                "Benign version-flag probe only. HYDRA never injects -d/-s/-r/"
                "-f/-i and never sends the php://input RCE body."
            ),
        )

    @staticmethod
    def _worstfit_candidates(target_url):
        """De-duplicated list of PHP-CGI endpoints to test. Query/fragment are
        stripped so the look-alike version flag is the ONLY query segment on the
        wire. If the operator pointed us straight at a ``.php`` endpoint it is
        tested first, then the common Windows php-cgi handler paths."""
        raw = target_url or ""
        parts = urlparse(raw if "//" in raw else "https://" + raw)
        scheme = parts.scheme or "https"
        netloc = parts.netloc or parts.path
        origin = f"{scheme}://{netloc}".rstrip("/")
        out: List[str] = []
        seen = set()

        def _add(u):
            if u and u not in seen:
                seen.add(u)
                out.append(u)

        path = parts.path or ""
        if "//" in raw and path.lower().endswith(".php"):
            _add(f"{origin}{path}")
        for p in _WORSTFIT_PHP_PATHS:
            _add(f"{origin}{p}")
        return out

    @staticmethod
    def _php_version_banner(body) -> str:
        """Return the matched ``php -v``/``-V`` version-banner signature, or ""
        — the signal that a read-only version flag was injected. Matches ONLY
        strings a PHP version banner emits, never arbitrary application HTML."""
        m = _WORSTFIT_VERSION_RE.search(body or "")
        return m.group(0) if m else ""

    @staticmethod
    def _worstfit_poc(php_url, flag, baseline_status, banner_status) -> str:
        """Value-free reproduction recipe — two GETs that expose only the
        injection CHANNEL via the read-only version flag; never any RCE step."""
        return "\n".join(
            [
                "# Safe reproduction — CVE-2024-4577 PHP-CGI Best-Fit (WorstFit)",
                "#   argument injection (benign: a Unicode look-alike folds to the",
                "#   READ-ONLY -v/-V version flag; no code is run, no RCE).",
                f"# control (plain request) — a php version banner should be ABSENT "
                f"(HTTP {baseline_status}):",
                f"curl -s '{php_url}'",
                f"# look-alike '%AD' (U+00AD SOFT HYPHEN) → Best-Fit '-' → injects "
                f"the read-only '-{flag}' flag:",
                f"curl -s '{php_url}?%AD{flag}'",
                f"# expect a php version banner (e.g. 'PHP 8.x', 'Zend Engine', "
                f"'(cgi-fcgi)') in the body (HTTP {banner_status}) — proof the",
                "#   look-alike was mapped onto the php-cgi command line.",
                "# NOTE: HYDRA injects ONLY -v/-V (print version, read-only). It NEVER",
                "#   injects a directive flag (allow_url_include / "
                "auto_prepend_file=php://input RCE),",
                "#   a source-disclosure flag, a run-code/run-file flag or a phpinfo",
                "#   flag, and NEVER sends the php://input POST body that completes",
                "#   RCE. Confirm RCE manually within your authorization — HYDRA will",
                "#   not.",
            ]
        )

    async def _confirm_dangerous_http_methods(
        self, target_url, prober, nonce=""
    ) -> ConfirmationResult:
        """Benign CVE-2025-24813 proof: a dangerous WRITE method (PUT) advertised
        in the OPTIONS ``Allow`` header — the write-enabled default-servlet
        PRECONDITION for the Apache Tomcat partial-PUT RCE — observed WITHOUT ever
        sending a write.

        A bodyless, non-mutating ``OPTIONS`` (RFC 9110 §9.3.1) is sent to each
        candidate path and the response ``Allow`` header is parsed. If ``PUT`` is
        advertised, the default servlet accepts writes (``readonly=false``) — the
        precondition CVE-2025-24813 needs. A Tomcat/Coyote ``Server`` banner, when
        present, narrows it to that exact stack (annotation only).

        Hard benign boundary: HYDRA observes PUT (and any DELETE/PATCH) ONLY as
        *advertised*. It NEVER sends PUT, a partial-PUT (``Content-Range``) upload,
        the serialized-session gadget that completes the RCE, or any DELETE/PATCH.
        Advertising a write verb is a PRECONDITION/INDICATOR — a server may
        advertise PUT yet reject the write — so this caps at OBSERVED and is never
        'critical'.
        """
        tech = "CVE-2025-24813 Tomcat partial-PUT precondition (dangerous HTTP methods)"
        nonce = nonce or uuid.uuid4().hex[:12]  # not sent; stable run id for logs
        candidates = self._dangerous_method_candidates(target_url)
        exchanges: List[ProbeExchange] = []
        saw_ok_control = False
        last_error = ""

        for url in candidates:
            # Bodyless, non-mutating OPTIONS — reads the advertised method set
            # only; no body and no write verb ever go on the wire. SafeProber
            # re-runs the full gauntlet (is_exploitation_payload, scope, cap).
            resp = await prober.options(url)
            allow = self._allow_methods(resp)
            exchanges.append(
                ProbeExchange(
                    "options",
                    resp.url,
                    resp.status,
                    "bodyless OPTIONS reads the advertised Allow set; no body / no "
                    "write verb sent"
                    + (f"; Allow={sorted(allow)}" if allow else "; no Allow header"),
                )
            )
            if not resp.ok:
                last_error = resp.error or "no response"
                continue
            saw_ok_control = True
            if _PARTIAL_PUT_METHOD not in allow:
                continue  # PUT not advertised here → no partial-PUT precondition

            write_methods = [m for m in _DANGEROUS_WRITE_METHODS if m in allow]
            banner = self._server_banner(resp)
            is_tomcat = bool(_TOMCAT_SERVER_RE.search(banner))

            # Re-OPTIONS to show the advertisement is stable. The advertised
            # capability is a static property of the path, so this still caps at
            # OBSERVED — we only record how often it held.
            stable = 0
            for _ in range(self.repeats):
                r = await prober.options(url)
                ok = r.ok and _PARTIAL_PUT_METHOD in self._allow_methods(r)
                exchanges.append(
                    ProbeExchange(
                        "repeat",
                        r.url,
                        r.status,
                        "PUT still advertised" if ok else "PUT absent on repeat",
                    )
                )
                if ok:
                    stable += 1
            held = f"; advertised on {stable + 1} OPTIONS requests" if stable else ""
            tomcat_note = (
                " The Server banner identifies Tomcat/Coyote — the exact "
                "CVE-2025-24813 stack."
                if is_tomcat
                else " The Server banner is not identifiably Tomcat/Coyote, so this is "
                "a write-method-enabled precondition that may not be the specific "
                "Tomcat partial-PUT CVE."
            )
            return ConfirmationResult(
                target=url,
                param="",
                vuln_class="dangerous_http_methods",
                confirmed=True,
                evidence_level=EvidenceLevel.OBSERVED,
                technique=tech,
                exchanges=exchanges,
                poc=self._partial_put_poc(url, write_methods, banner, is_tomcat),
                summary=(
                    f"Dangerous write method advertised at {url}: a bodyless "
                    f"OPTIONS returned Allow with {write_methods} (HTTP "
                    f"{resp.status}) — PUT is advertised, the write-enabled "
                    f"default-servlet PRECONDITION for the Tomcat partial-PUT RCE "
                    f"(CVE-2025-24813){held}.{tomcat_note} HYDRA only READ the "
                    f"advertised method set; it never sent a PUT or any write."
                ),
                note=(
                    "PRECONDITION / INDICATOR only — NOT proof of RCE. A server "
                    "may advertise PUT in Allow yet reject the write, and the "
                    "partial-PUT RCE additionally needs file-based session "
                    "persistence (or an equivalent deserialization sink). HYDRA "
                    "observed the method via a safe, bodyless OPTIONS and NEVER "
                    "sent PUT / DELETE / PATCH / a partial-PUT (Content-Range) "
                    "upload / the serialized-session gadget. Confirm "
                    "exploitability manually within your authorization — HYDRA "
                    "will not."
                ),
            )

        if not saw_ok_control:
            return ConfirmationResult(
                target=self._origin(target_url),
                param="",
                vuln_class="dangerous_http_methods",
                confirmed=False,
                evidence_level=EvidenceLevel.UNVERIFIED,
                exchanges=exchanges,
                technique=tech,
                summary="Baseline OPTIONS request failed; cannot assess the "
                "advertised method set.",
                note=last_error or "no response",
            )
        return ConfirmationResult(
            target=self._origin(target_url),
            param="",
            vuln_class="dangerous_http_methods",
            confirmed=False,
            evidence_level=EvidenceLevel.OBSERVED,
            exchanges=exchanges,
            technique=tech,
            summary=(
                "No dangerous write method advertised — OPTIONS did not list "
                "PUT in Allow on the tested paths (writes disabled, patched, "
                "or no Tomcat default servlet with readonly=false here)."
            ),
            note=(
                "Benign OPTIONS-only capability read. HYDRA never sent PUT / "
                "DELETE / PATCH / a partial-PUT upload."
            ),
        )

    @staticmethod
    def _dangerous_method_candidates(target_url):
        """De-duplicated list of paths to OPTIONS. Query/fragment are stripped (a
        bodyless OPTIONS carries nothing on the wire); the operator-pointed path
        is tested first, then the context root ``/``."""
        raw = target_url or ""
        parts = urlparse(raw if "//" in raw else "https://" + raw)
        scheme = parts.scheme or "https"
        netloc = parts.netloc or parts.path
        origin = f"{scheme}://{netloc}".rstrip("/")
        out: List[str] = []
        seen = set()

        def _add(u):
            if u and u not in seen:
                seen.add(u)
                out.append(u)

        path = parts.path or ""
        if "//" in raw and path and path != "/":
            _add(f"{origin}{path}")
        _add(f"{origin}/")
        return out

    @staticmethod
    def _allow_methods(resp) -> set:
        """Case-insensitive parse of the OPTIONS ``Allow`` header into an
        UPPERCASE method-token set. Reads an advertised capability only — HYDRA
        never *sends* any method it finds here."""
        allow = ""
        for k, v in (getattr(resp, "headers", None) or {}).items():
            if k.lower() == "allow":
                allow = v or ""
                break
        return {m.strip().upper() for m in allow.split(",") if m.strip()}

    @staticmethod
    def _server_banner(resp) -> str:
        """The public ``Server`` response-header value (fingerprint), or ""."""
        for k, v in (getattr(resp, "headers", None) or {}).items():
            if k.lower() == "server":
                return v or ""
        return ""

    @staticmethod
    def _partial_put_poc(url, write_methods, server_banner, is_tomcat) -> str:
        """Value-free reproduction recipe — a single bodyless OPTIONS that READS
        the advertised Allow set. The partial-PUT write is explicitly NOT sent."""
        advertised = ", ".join(write_methods) or "PUT"
        banner_line = (
            f"# observed Server banner: {server_banner}"
            if server_banner
            else "# (no Server banner advertised)"
        )
        return "\n".join(
            [
                "# Safe reproduction — CVE-2025-24813 Tomcat partial-PUT PRECONDITION",
                "#   (benign: a bodyless, non-mutating OPTIONS reads the advertised",
                "#   Allow method set; no write verb is sent, no file is uploaded).",
                "# bodyless OPTIONS — read the advertised methods at the path:",
                f"curl -s -i -X OPTIONS '{url}'",
                f"# expect an 'Allow:' response header advertising a write method "
                f"(e.g. {advertised}) — the",
                "#   write-enabled default-servlet precondition for the partial-PUT RCE.",
                banner_line,
                (
                    "# the Server banner identifies Tomcat/Coyote — the specific "
                    "CVE-2025-24813 stack."
                    if is_tomcat
                    else "# the Server banner is not identifiably Tomcat/Coyote."
                ),
                "# NOTE: HYDRA observes PUT only as *advertised*. It NEVER sends PUT, a",
                "#   partial-PUT (Content-Range) upload, the serialized-session gadget",
                "#   that completes the RCE, or any DELETE/PATCH write. Advertising PUT",
                "#   is a PRECONDITION, not proof of RCE — confirm exploitability",
                "#   manually within your authorization. HYDRA will not.",
            ]
        )
