"""Passive enumeration: subdomains, DNS, robots.txt, sitemap, homepage.

PASSIVE-ONLY: uses certificate-transparency logs (crt.sh), standard
DNS resolution, and single benign GET requests to publicly served
files. No scanning, no brute-force, no exploitation. Requests are
rate-limited (0.5s) and carry an identifying User-Agent.
"""

import json
import re
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

USER_AGENT = (
    "hunterswarm/0.1.0 (passive security recon; "
    "https://github.com/eliem08/hunterswarm)"
)
TIMEOUT = 10
POLITE_DELAY = 0.5  # seconds between requests — be a good citizen

_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
)


def _polite_sleep():
    time.sleep(POLITE_DELAY)


def http_get(url, timeout=TIMEOUT):
    """Single benign GET.

    Returns (status:int|None, headers:dict, body:bytes|None).
    Never raises: network failures yield (None, {}, None).
    """
    _polite_sleep()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = None
        return e.code, dict(e.headers.items()), body
    except Exception:
        return None, {}, None


def http_get_capped(url, max_bytes=200_000, timeout=TIMEOUT):
    """GET with a cap on response body size (for JS files)."""
    _polite_sleep()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            chunks, remaining = [], max_bytes
            while remaining > 0:
                chunk = resp.read(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return resp.status, dict(resp.headers.items()), b"".join(chunks)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), None
    except Exception:
        return None, {}, None


def enumerate_subdomains(domain, max_subdomains=50):
    """Subdomains from crt.sh certificate-transparency logs."""
    url = "https://crt.sh/?q=%25.{0}&output=json".format(domain)
    status, _, body = http_get(url)
    subs = set()
    if status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            data = []
        for entry in data:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if name and name.endswith(domain.lower()) and "@" not in name:
                    subs.add(name)
    subs.discard(domain.lower())
    return sorted(subs)[:max_subdomains]


def resolve_dns(hostname):
    """A/AAAA records via standard resolution. Returns sorted IP list."""
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, socket.timeout, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def fetch_homepage(domain):
    """Returns (status, headers, html_text)."""
    status, headers, body = http_get("https://{0}/".format(domain))
    html = body.decode("utf-8", "replace") if body else ""
    return status, headers, html


def fetch_robots_txt(domain):
    """Raw robots.txt text or None."""
    status, _, body = http_get("https://{0}/robots.txt".format(domain))
    if status == 200 and body:
        return body.decode("utf-8", "replace")
    return None


def parse_sitemap_urls(xml_text):
    """Extract <loc> URLs from a sitemap XML document."""
    if not xml_text:
        return []
    return [
        loc.strip()
        for loc in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", xml_text)
        if loc.strip()
    ]


def fetch_sitemap_urls(domain):
    status, _, body = http_get("https://{0}/sitemap.xml".format(domain))
    if status == 200 and body:
        return parse_sitemap_urls(body.decode("utf-8", "replace"))
    return []


def extract_js_urls(page_url, html):
    """Absolute JS file URLs referenced by <script src=...> tags."""
    urls = []
    for src in _SCRIPT_SRC_RE.findall(html or ""):
        src = src.strip()
        if not src or src.startswith(("data:", "javascript:", "blob:")):
            continue
        urls.append(urljoin(page_url, src))
    # dedupe, preserve order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def run_recon(domain, max_subdomains=50, progress=None):
    """Fetch-only recon pass. Returns a plain dict (no findings)."""
    domain = domain.strip().lower()

    def say(msg):
        if progress:
            progress(msg)

    say("enumerating subdomains via crt.sh ...")
    subdomains = enumerate_subdomains(domain, max_subdomains)
    say("found {0} subdomains".format(len(subdomains)))

    say("resolving DNS ...")
    ips = resolve_dns(domain)

    say("fetching homepage ...")
    home_status, home_headers, html = fetch_homepage(domain)

    say("fetching robots.txt and sitemap.xml ...")
    robots_txt = fetch_robots_txt(domain)
    sitemap_urls = fetch_sitemap_urls(domain)

    say("collecting JavaScript URLs ...")
    js_urls = extract_js_urls("https://{0}/".format(domain), html)

    return {
        "domain": domain,
        "subdomains": subdomains,
        "ips": ips,
        "homepage_status": home_status,
        "homepage_headers": home_headers,
        "homepage_html": html,
        "robots_txt": robots_txt,
        "sitemap_urls": sitemap_urls,
        "js_urls": js_urls,
    }


def run_pipeline(domain, max_subdomains=50, progress=None):
    """Full passive pipeline: recon + fingerprint + surface + checks."""
    # Local imports keep module load order flexible; no cycles.
    from hunterswarm import fingerprint as fp
    from hunterswarm import surface as sf
    from hunterswarm import checks as ck

    recon = run_recon(domain, max_subdomains, progress)

    def say(msg):
        if progress:
            progress(msg)

    say("fingerprinting technologies ...")
    technologies = fp.fingerprint(recon["homepage_headers"], recon["homepage_html"])

    say("discovering API surface ...")
    api_paths = sf.discover_api_paths(recon["js_urls"])
    common_paths = sf.discover_common_paths(domain)

    say("running passive checks ...")
    findings = ck.run_checks(
        domain,
        recon["homepage_headers"],
        recon["homepage_status"],
        common_paths,
    )

    # Strip raw HTML before returning — keeps saved JSON small.
    recon_out = dict(recon)
    recon_out.pop("homepage_html", None)
    recon_out["technologies"] = technologies
    recon_out["api_paths"] = api_paths
    recon_out["common_paths"] = common_paths

    return {"domain": domain, "recon": recon_out, "findings": findings}
