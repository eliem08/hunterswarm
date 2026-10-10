# hunterswarm

**Passive recon for bug-bounty hunters: scope in, HackerOne-ready report draft out.**

hunterswarm does the boring-first-half of the hunter loop for you: subdomain
enumeration via certificate-transparency logs, DNS resolution, technology
fingerprinting, JavaScript harvesting, API-endpoint extraction, and a set of
strictly passive heuristic checks — then drafts a HackerOne-style markdown
report you verify and submit yourself.

**Passive-only, by design.** No port scanning, no brute-forcing, no fuzzing,
no exploitation, no payload delivery. Every technique is read-only
observation of publicly served data. See [SAFETY.md](SAFETY.md) for the full
contract — and why staying passive keeps you inside program rules while you
triage.

## Quickstart

Zero dependencies — Python 3.9+ standard library only.

```bash
git clone https://github.com/eliem08/hunterswarm.git
cd hunterswarm
python -m hunterswarm recon example.com -o report.md
```

Live run (requests are polite: 0.5s apart, identifying User-Agent):

```
hunterswarm v0.1.0 — passive recon on example.com
passive-only: crt.sh + DNS + single benign HTTP requests

  [hunterswarm] enumerating subdomains via crt.sh ...
  [hunterswarm] found 0 subdomains
  [hunterswarm] resolving DNS ...
  [hunterswarm] fetching homepage ...
  [hunterswarm] fetching robots.txt and sitemap.xml ...
  [hunterswarm] collecting JavaScript URLs ...
  [hunterswarm] fingerprinting technologies ...
  [hunterswarm] discovering API surface ...
  [hunterswarm] running passive checks ...

---- summary ----
subdomains : 0
technologies: Cloudflare
api paths  : 0
findings   : 5 (info=3, low=2)
wrote report: report.md
```

*(Real run. crt.sh was returning HTTP 502 that day, so the subdomain
list came back empty — hunterswarm degrades gracefully instead of
crashing. The `Cloudflare` label came from this sandbox's egress-proxy
headers, a good reminder that fingerprints are heuristic.)*

Regenerate a report from saved JSON without re-running recon:

```bash
python -m hunterswarm recon example.com --save-json findings.json -o report.md
python -m hunterswarm report findings.json -o report-v2.md
```

## What it actually does

| Stage | Technique | Source |
|---|---|---|
| Subdomains | crt.sh certificate-transparency search | public CT logs |
| DNS | A/AAAA via OS resolver | public DNS |
| Tech fingerprint | headers (`Server`, `X-Powered-By`…) + HTML markers (`wp-content`, `__NEXT_DATA__`…) | homepage only |
| JS harvesting | `<script src>` URLs from homepage, first 5 files, 200KB cap | site-referenced files |
| API surface | regex over JS: `/api/…`, `fetch("…")`, `axios.*("…")`, GraphQL refs | fetched JS |
| Well-known paths | one GET each: `security.txt`, `api/docs`, `swagger.json`, `openapi.json`, `.git/HEAD` | status codes only |
| Checks | missing security headers, exposed `.git/HEAD`, verbose 404 page, CORS via one OPTIONS, `security.txt` presence | passive observations |

## Check catalogue (v1)

| ID | Severity | What it observes |
|---|---|---|
| `missing-content-security-policy` | low | CSP header absent |
| `missing-strict-transport-security` | low | HSTS header absent |
| `missing-x-frame-options` | info | X-Frame-Options absent |
| `missing-x-content-type-options` | info | nosniff absent |
| `exposed-git-head` | medium | `/.git/HEAD` returns 200 with git content |
| `verbose-error-page` | low | benign 404 leaks stack traces |
| `cors-arbitrary-origin-credentials` | medium | OPTIONS reflects origin + `Allow-Credentials` |
| `cors-reflects-origin` | low | OPTIONS reflects origin, no credentials |
| `cors-wildcard` | info | `Access-Control-Allow-Origin: *` |
| `security-txt-present` / `security-txt-missing` | info | disclosure contact posture |

Every finding is emitted as a **lead**: estimated severity, evidence as
observed, impact, remediation — and a banner reminding you to verify
manually before submitting anything.

## Example report excerpt

Real output from `python -m hunterswarm recon example.com`:

```markdown
> **DRAFT — human verification required before submission.**
>
> This report was generated from *passive observation only* ...

## Findings

### 1. [LOW] Missing Content-Security-Policy header

- **Finding ID:** `missing-content-security-policy`
- **Asset:** `https://example.com/`
- **Severity (estimated, passive observation):** low

**Evidence (as observed):**
```
Response headers did not include `content-security-policy`.
```
```

## How it complements (not replaces) human testing

hunterswarm answers *"what's out there?"* in ~30 seconds so you can spend
your time on *"what's actually broken?"*. It will never find logic bugs,
auth bypasses, or IDORs — those need a human with creativity and
authorization. Think of it as triage infrastructure: the recon half of
the loop, automated; the judgment half, yours.

## Module map

- `hunterswarm/recon.py` — crt.sh, DNS, robots/sitemap, homepage fetch, pipeline
- `hunterswarm/fingerprint.py` — header + HTML tech detection
- `hunterswarm/surface.py` — JS fetching, API-path regexes, well-known paths
- `hunterswarm/checks.py` — the five passive check families
- `hunterswarm/report.py` — HackerOne-style markdown drafting
- `hunterswarm/cli.py` — `recon` / `report` commands

## Limitations

- Sees only what's publicly served over HTTPS; no JS rendering (SPA
  content behind client-side routing is missed).
- crt.sh coverage depends on certificate issuance; internal-only hosts
  won't appear.
- Fingerprinting is heuristic — absence of a label proves nothing.
- Findings are leads with *estimated* severity, not confirmed vulns.

## Roadmap

- Nuclei-template export for confirmed leads (opt-in, still passive input)
- Program-scope ingestion (HackerOne/Bugcrowd scope files → target lists)
- Sitemap-index recursion and `robots.txt` disallow-list surfacing
- Optional authenticated-header mode for your *own* staging assets

## License

MIT © 2026 Ilyass Emssaad
