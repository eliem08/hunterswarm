"""API surface discovery from passively fetched resources.

PASSIVE-ONLY: fetches JavaScript files the site itself references and
a small curated list of well-known paths, recording status codes and
matching endpoint patterns. Nothing is fuzzed, brute-forced, or
exploited — a 200 on a well-known path is recorded as an observation.
"""

import re

from hunterswarm.recon import http_get, http_get_capped

# Well-known paths worth a single benign GET each.
COMMON_PATHS = [
    "/.well-known/security.txt",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
    "/.git/HEAD",
]

JS_FETCH_LIMIT = 5       # max JS files to fetch per run
JS_MAX_BYTES = 200_000   # per-file cap

_API_RES = [
    # '/api/...', '/rest/...', '/v1/...' style paths in quotes
    re.compile(r"""["']((?:/api/|/rest/|/v\d+/)[A-Za-z0-9_\-./{}:?=&%$]*)["']"""),
    # fetch("...") / fetch('...')
    re.compile(r"""\bfetch\(\s*["']([^"']+)["']"""),
    # axios.get("...") etc.
    re.compile(r"""\baxios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']"""),
    # anything mentioning graphql
    re.compile(r"""["']([^"']*graphql[^"']*)["']""", re.IGNORECASE),
]


def extract_api_paths(js_text):
    """Regex-extract candidate API paths/endpoints from JS source."""
    found = set()
    for rx in _API_RES:
        for match in rx.finditer(js_text or ""):
            path = match.group(1).strip()
            if not path or len(path) > 300:
                continue
            if path.startswith(("data:", "javascript:", "blob:", "#")):
                continue
            if path.startswith("/") or path.startswith(("http://", "https://")):
                found.add(path)
    return sorted(found)


def fetch_js_files(js_urls, limit=JS_FETCH_LIMIT, max_bytes=JS_MAX_BYTES):
    """Fetch up to `limit` JS files (capped size). Returns [(url, text|None)]."""
    out = []
    for url in (js_urls or [])[:limit]:
        status, _, body = http_get_capped(url, max_bytes=max_bytes)
        text = body.decode("utf-8", "replace") if body else None
        out.append((url, text if status == 200 else None))
    return out


def discover_api_paths(js_urls):
    """Fetch referenced JS and extract candidate API endpoints."""
    paths = set()
    for url, text in fetch_js_files(js_urls):
        if text:
            paths.update(extract_api_paths(text))
    return sorted(paths)


def discover_common_paths(domain):
    """Single benign GET per well-known path; record status only.

    For /.git/HEAD a 200 whose body starts with 'ref:' is noted as an
    observation (possible exposed VCS metadata) — it is NOT cloned or
    read further.
    """
    results = []
    for path in COMMON_PATHS:
        url = "https://{0}{1}".format(domain, path)
        status, _, body = http_get(url)
        entry = {"path": path, "url": url, "status": status}
        if path == "/.git/HEAD" and status == 200 and body:
            head = body[:200].decode("utf-8", "replace")
            entry["looks_like_git"] = head.startswith("ref:")
        results.append(entry)
    return results
