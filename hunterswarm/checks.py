"""Passive heuristic checks. Each returns finding dicts.

PASSIVE-ONLY, strictly enforced:
- missing security headers  -> read response headers (already fetched)
- exposed .git metadata      -> single GET to /.git/HEAD, status recorded
- verbose error pages        -> ONE benign 404 request, body inspected
- CORS posture               -> ONE OPTIONS request, headers inspected
- security.txt presence      -> single GET to /.well-known/security.txt

No exploitation, no payload delivery, no authentication bypass
attempts, no parameter fuzzing. A finding here is a *lead* for
human verification, never a confirmed vulnerability.
"""

import re
import urllib.request

from hunterswarm.recon import USER_AGENT, _polite_sleep, http_get

# ---------------------------------------------------------------- findings

def _finding(check_id, severity, title, asset, evidence, impact, remediation):
    return {
        "id": check_id,
        "severity": severity,  # info | low | medium
        "title": title,
        "asset": asset,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
    }


_MISSING_HEADER_INFO = {
    "content-security-policy": (
        "low",
        "Missing Content-Security-Policy header",
        "Without CSP the application cannot instruct browsers to block "
        "inline scripts or restrict resource origins, making successful "
        "XSS exploitation more damaging.",
        "Deploy a Content-Security-Policy header; start in report-only "
        "mode, then enforce.",
    ),
    "strict-transport-security": (
        "low",
        "Missing Strict-Transport-Security header",
        "Without HSTS, users on hostile networks can be downgraded to "
        "plaintext HTTP (SSL-stripping), exposing session cookies.",
        "Send Strict-Transport-Security with a long max-age and "
        "includeSubDomains once HTTPS is fully rolled out.",
    ),
    "x-frame-options": (
        "info",
        "Missing X-Frame-Options header",
        "The page may be embeddable in a third-party iframe (clickjacking "
        "framing). Note: frame-ancestors in CSP is the modern equivalent.",
        "Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors "
        "directive.",
    ),
    "x-content-type-options": (
        "info",
        "Missing X-Content-Type-Options header",
        "Browsers may MIME-sniff responses, which has historically enabled "
        "content-type confusion attacks on user-uploaded content.",
        "Send X-Content-Type-Options: nosniff.",
    ),
}


def check_security_headers(domain, headers):
    """Flag absent hardening headers. Pure header inspection."""
    findings = []
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    for header, (severity, title, impact, remediation) in _MISSING_HEADER_INFO.items():
        if header not in lowered:
            findings.append(
                _finding(
                    "missing-" + header,
                    severity,
                    title,
                    "https://{0}/".format(domain),
                    "Response headers did not include `{0}`.".format(header),
                    impact,
                    remediation,
                )
            )
    return findings


def check_exposed_git(domain, common_paths):
    """Observation only: /.git/HEAD reachable with git content."""
    for entry in common_paths or []:
        if (
            entry.get("path") == "/.git/HEAD"
            and entry.get("status") == 200
            and entry.get("looks_like_git")
        ):
            return [
                _finding(
                    "exposed-git-head",
                    "medium",
                    "Possible exposed .git metadata",
                    entry["url"],
                    "GET /.git/HEAD returned HTTP 200 with a body starting "
                    '"ref:" — the signature of a git HEAD file. Not read '
                    "further (passive observation only).",
                    "Exposed .git directories can leak full source history, "
                    "including secrets committed in the past. Treat as a "
                    "lead: verify manually that the objects directory is "
                    "actually reachable before reporting.",
                    "Block /.git at the web server / CDN layer and audit "
                    "the deployment pipeline that published it.",
                )
            ]
    return []


_ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"\.php on line \d+",
    r"Fatal error:",
    r"at java\.",
    r"at System\.",
    r"Stack trace:",
    r"QueryException",
    r"PG::\w+Error",
    r"ORA-\d{5}",
    r"Uncaught \w+Error",
]


def check_verbose_errors(domain):
    """ONE benign 404; inspect the error page for stack traces."""
    probe_path = "/hunterswarm-benign-404-probe"
    url = "https://{0}{1}".format(domain, probe_path)
    status, _, body = http_get(url)
    if not body:
        return []
    text = body[:20000].decode("utf-8", "replace")
    hits = [p for p in _ERROR_PATTERNS if re.search(p, text)]
    if hits and status in (200, 404, 500):
        snippet = "\n".join(text.splitlines()[:12])
        return [
            _finding(
                "verbose-error-page",
                "low",
                "Verbose error page discloses internals",
                url,
                "A benign 404 request returned a page matching stack-trace "
                "signatures ({0}). First lines:\n{1}".format(
                    ", ".join(hits[:3]), snippet[:800]
                ),
                "Stack traces disclose frameworks, file paths, and library "
                "versions, which help an attacker tailor further (manual) "
                "testing.",
                "Replace debug error pages with generic ones in production; "
                "log details server-side instead.",
            )
        ]
    return []


def check_cors(domain):
    """ONE OPTIONS request; inspect ACAO/ACAC headers. No exploit."""
    _polite_sleep()
    origin = "https://hunterswarm-probe.invalid"
    req = urllib.request.Request(
        "https://{0}/".format(domain),
        method="OPTIONS",
        headers={
            "User-Agent": USER_AGENT,
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == origin:
        if acac == "true":
            return [
                _finding(
                    "cors-arbitrary-origin-credentials",
                    "medium",
                    "CORS reflects arbitrary origin with credentials",
                    "https://{0}/".format(domain),
                    "OPTIONS with Origin: {0} returned "
                    "Access-Control-Allow-Origin: {0} and "
                    "Access-Control-Allow-Credentials: true.".format(origin),
                    "Any website could make credentialed cross-origin "
                    "requests as the victim user. Verify manually whether "
                    "sensitive endpoints honor these headers.",
                    "Reflect only allowlisted origins; never combine "
                    "reflected origins with Allow-Credentials: true.",
                )
            ]
        return [
            _finding(
                "cors-reflects-origin",
                "low",
                "CORS reflects arbitrary origin (no credentials)",
                "https://{0}/".format(domain),
                "OPTIONS with Origin: {0} echoed it back in "
                "Access-Control-Allow-Origin (without credentials).".format(origin),
                "Lower risk without credentials, but over-permissive CORS "
                "widens the attack surface for chained issues.",
                "Restrict Access-Control-Allow-Origin to trusted origins.",
            )
        ]
    if acao == "*":
        return [
            _finding(
                "cors-wildcard",
                "info",
                "CORS allows any origin (wildcard, no credentials)",
                "https://{0}/".format(domain),
                "Access-Control-Allow-Origin: * observed.",
                "Wildcard without credentials is usually benign but worth "
                "noting for API assets.",
                "Prefer explicit origin allowlists for APIs handling "
                "sensitive data.",
            )
        ]
    return []


def check_security_txt(domain, common_paths):
    """Note presence/absence of /.well-known/security.txt."""
    for entry in common_paths or []:
        if entry.get("path") == "/.well-known/security.txt":
            if entry.get("status") == 200:
                return [
                    _finding(
                        "security-txt-present",
                        "info",
                        "security.txt present (positive)",
                        entry["url"],
                        "GET /.well-known/security.txt returned HTTP 200.",
                        "A published security.txt signals a mature disclosure "
                        "process — useful context for a hunter.",
                        "No action needed.",
                    )
                ]
            return [
                _finding(
                    "security-txt-missing",
                    "info",
                    "No security.txt published",
                    "https://{0}/.well-known/security.txt".format(domain),
                    "GET /.well-known/security.txt did not return HTTP 200 "
                    "(status: {0}).".format(entry.get("status")),
                    "Without a contact file, good-faith researchers may "
                    "struggle to report issues responsibly.",
                    "Publish /.well-known/security.txt per RFC 9116.",
                )
            ]
    return []


def run_checks(domain, headers, homepage_status, common_paths):
    """Run all passive checks. Returns a list of finding dicts."""
    findings = []
    findings.extend(check_security_headers(domain, headers))
    findings.extend(check_exposed_git(domain, common_paths))
    findings.extend(check_verbose_errors(domain))
    findings.extend(check_cors(domain))
    findings.extend(check_security_txt(domain, common_paths))
    return findings
