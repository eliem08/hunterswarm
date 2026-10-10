# SAFETY.md — the passive-only contract

hunterswarm is **strictly passive recon**. This file defines what that means,
and the line the tool will not cross. Every module docstring restates it.

## Allowed (what v1 does)

- **Certificate-transparency lookup** — query crt.sh for subdomains of the
  target domain. Public log, read-only.
- **DNS resolution** — standard A/AAAA lookups via the OS resolver.
- **Single benign GETs** — the homepage, `robots.txt`, `sitemap.xml`,
  JavaScript files *the site itself references*, and five well-known paths
  (`/.well-known/security.txt`, `/api/docs`, `/swagger.json`,
  `/openapi.json`, `/.git/HEAD`). Status codes recorded; bodies only
  pattern-matched, never executed or followed recursively.
- **One benign 404** — a single request to a nonexistent path to observe
  whether the error page leaks stack traces.
- **One OPTIONS request** — to observe CORS headers. No cross-origin
  request is ever actually made.

All requests are rate-limited (0.5s between requests), carry an
identifying `User-Agent`, and are capped (first 5 JS files, 200KB each,
10s timeouts, 50 subdomains by default).

## Forbidden (what hunterswarm will never do)

- Port scanning, service enumeration, banner grabbing beyond the
  homepage's own headers.
- Directory/file brute-forcing or fuzzing of any kind.
- Authentication attempts, credential stuffing, session manipulation.
- Payload delivery: no XSS/SQLi/command-injection probes, no crafted
  exploit input of any kind.
- Exploitation or privilege escalation, even "read-only" proof-of-concepts
  that alter server state.
- Social engineering or phishing support tooling.

## Your responsibilities

1. **Scope.** Only run hunterswarm against domains you are authorized to
   assess (a bug-bounty program scope, your own assets, or an explicit
   engagement). Passive or not, unauthorized assessment can violate a
   program's rules or the law.
2. **Verify before submitting.** Every report is stamped DRAFT. A passive
   observation is a *lead*, not a confirmed vulnerability. Reproduce
   manually, within scope, before writing it up.
3. **Disclose responsibly.** Follow the target program's disclosure policy;
   default to private disclosure with reasonable remediation time.

If a feature request would require crossing into active testing, it does
not belong in hunterswarm core. Active testing is a human decision, made
with authorization, outside this tool.
