"""HackerOne-style markdown report drafting.

PASSIVE-ONLY: findings describe passively observed facts. Every
report carries a DRAFT banner — a human must verify each finding and
stay inside program scope before submitting anything.
"""

from datetime import datetime, timezone

_VERSION = "0.1.0"  # keep in sync with hunterswarm/__init__.py

BANNER = (
    "> **DRAFT — human verification required before submission.**\n"
    ">\n"
    "> This report was generated from *passive observation only* "
    "(public DNS, certificate-transparency logs, and single benign HTTP "
    "requests). Nothing was port-scanned, brute-forced, fuzzed, or "
    "exploited. Every finding below is a **lead, not a confirmed "
    "vulnerability**: verify it manually, confirm it is in scope for the "
    "target program, and follow responsible disclosure.\n"
)

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_tag(severity):
    return "[{0}]".format(str(severity).upper())


def finding_to_markdown(finding, index):
    """One finding -> HackerOne-style markdown section."""
    sev = finding.get("severity", "info")
    parts = [
        "### {0}. {1} {2}".format(index, _sev_tag(sev), finding.get("title", "Untitled")),
        "",
        "- **Finding ID:** `{0}`".format(finding.get("id", "n/a")),
        "- **Asset:** `{0}`".format(finding.get("asset", "n/a")),
        "- **Severity (estimated, passive observation):** {0}".format(sev),
        "",
        "**Evidence (as observed):**",
        "",
        "```",
        str(finding.get("evidence", "n/a")).strip(),
        "```",
        "",
        "**Impact:**",
        "",
        str(finding.get("impact", "n/a")).strip(),
        "",
        "**Remediation:**",
        "",
        str(finding.get("remediation", "n/a")).strip(),
        "",
        "**Reproduction (passive):** no exploit performed. Re-observe with a "
        "single benign request as described in Evidence, then verify manually "
        "within program scope.",
        "",
        "---",
        "",
    ]
    return "\n".join(parts)


def _summary_table(findings):
    counts = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    rows = ["| Severity | Count |", "| --- | --- |"]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            rows.append("| {0} | {1} |".format(sev, counts[sev]))
    if not any(counts.get(s) for s in ("critical", "high", "medium", "low", "info")):
        rows.append("| — | 0 |")
    return "\n".join(rows)


def generate_report(domain, recon, findings):
    """Full markdown report: banner, recon summary, findings, appendix."""
    recon = recon or {}
    findings = sorted(
        findings or [], key=lambda f: _SEV_RANK.get(f.get("severity", "info"), 9)
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    subdomains = recon.get("subdomains", []) or []
    technologies = recon.get("technologies", []) or []
    api_paths = recon.get("api_paths", []) or []
    common_paths = recon.get("common_paths", []) or []
    js_urls = recon.get("js_urls", []) or []

    lines = [
        "# hunterswarm recon report — {0}".format(domain),
        "",
        BANNER,
        "",
        "- **Target:** `{0}`".format(domain),
        "- **Generated:** {0}".format(now),
        "- **Method:** passive only (crt.sh, DNS, single benign HTTP requests)",
        "",
        "## Recon summary",
        "",
        "- Subdomains discovered (crt.sh): **{0}**".format(len(subdomains)),
        "- Resolved IPs: {0}".format(
            ", ".join("`{0}`".format(ip) for ip in recon.get("ips", []) or []) or "—"
        ),
        "- Technologies fingerprinted: {0}".format(
            ", ".join(technologies) or "none detected"
        ),
        "- Homepage status: `{0}`".format(recon.get("homepage_status", "n/a")),
        "- JavaScript files referenced: {0} (fetched first {1})".format(
            len(js_urls), min(len(js_urls), 5)
        ),
        "- Candidate API endpoints extracted: **{0}**".format(len(api_paths)),
        "- Findings: **{0}**".format(len(findings)),
        "",
        "### Finding counts",
        "",
        _summary_table(findings),
        "",
    ]

    if findings:
        lines += ["## Findings", ""]
        for i, finding in enumerate(findings, 1):
            lines.append(finding_to_markdown(finding, i))
    else:
        lines += [
            "## Findings",
            "",
            "No passive findings. This does **not** mean the target is "
            "secure — passive recon only sees the surface.",
            "",
        ]

    lines += ["## Appendix — recon details", ""]

    lines += ["### Subdomains", ""]
    if subdomains:
        lines += ["- `{0}`".format(s) for s in subdomains[:100]]
        if len(subdomains) > 100:
            lines.append("- …and {0} more".format(len(subdomains) - 100))
    else:
        lines.append("None discovered via crt.sh.")
    lines.append("")

    lines += ["### Candidate API endpoints (from JS)", ""]
    if api_paths:
        lines += ["- `{0}`".format(p) for p in api_paths[:100]]
        if len(api_paths) > 100:
            lines.append("- …and {0} more".format(len(api_paths) - 100))
    else:
        lines.append("None extracted.")
    lines.append("")

    lines += ["### Well-known paths probed", "", "| Path | Status |", "| --- | --- |"]
    for entry in common_paths:
        status = entry.get("status")
        lines.append(
            "| `{0}` | {1} |".format(entry.get("path"), status if status else "no response")
        )
    lines.append("")

    robots = recon.get("robots_txt")
    if robots:
        lines += [
            "### robots.txt (first 20 lines)",
            "",
            "```",
            "\n".join(robots.splitlines()[:20]),
            "```",
            "",
        ]

    sitemap_urls = recon.get("sitemap_urls") or []
    if sitemap_urls:
        lines += [
            "### sitemap.xml URLs (first 20)",
            "",
        ]
        lines += ["- {0}".format(u) for u in sitemap_urls[:20]]
        lines.append("")

    lines += [
        "---",
        "",
        "*Generated by [hunterswarm](https://github.com/eliem08/hunterswarm) "
        "v{0} — passive recon only. Verify everything before submitting.*".format(
            _VERSION
        ),
    ]
    return "\n".join(lines)
