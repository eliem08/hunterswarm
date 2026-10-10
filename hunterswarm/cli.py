"""Command line interface.

PASSIVE-ONLY: `recon` performs read-only observation (crt.sh, DNS,
single benign HTTP requests). It never scans ports, brute-forces, or
exploits anything. See SAFETY.md.
"""

import argparse
import json
import re
import sys

from hunterswarm import __version__
from hunterswarm.recon import run_pipeline
from hunterswarm.report import generate_report

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$")


def _valid_domain(domain):
    return bool(_DOMAIN_RE.match(domain.strip().lower()))


def _progress(msg):
    print("  [hunterswarm] {0}".format(msg), flush=True)


def cmd_recon(args):
    domain = args.domain.strip().lower()
    if not _valid_domain(domain):
        print("error: '{0}' is not a valid domain name".format(args.domain),
              file=sys.stderr)
        return 2

    print("hunterswarm v{0} — passive recon on {1}".format(__version__, domain))
    print("passive-only: crt.sh + DNS + single benign HTTP requests\n")

    result = run_pipeline(
        domain, max_subdomains=args.max_subdomains, progress=_progress
    )
    findings = result["findings"]
    recon = result["recon"]

    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print("\n---- summary ----")
    print("subdomains : {0}".format(len(recon["subdomains"])))
    print("technologies: {0}".format(", ".join(recon["technologies"]) or "none"))
    print("api paths  : {0}".format(len(recon["api_paths"])))
    print("findings   : {0} ({1})".format(
        len(findings),
        ", ".join("{0}={1}".format(k, v) for k, v in sorted(sev_counts.items()))
        or "none",
    ))

    report_md = generate_report(domain, recon, findings)

    if args.save_json:
        serializable = {
            "domain": domain,
            "recon": recon,
            "findings": findings,
        }
        with open(args.save_json, "w", encoding="utf-8") as fh:
            json.dump(serializable, fh, indent=2)
        print("saved JSON : {0}".format(args.save_json))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_md)
        print("wrote report: {0}".format(args.output))
    else:
        print("\n" + report_md)
    return 0


def cmd_report(args):
    with open(args.findings_json, encoding="utf-8") as fh:
        data = json.load(fh)
    report_md = generate_report(
        data.get("domain", "unknown"),
        data.get("recon", {}),
        data.get("findings", []),
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report_md)
        print("wrote report: {0}".format(args.output))
    else:
        print(report_md)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hunterswarm",
        description=(
            "Passive recon for bug-bounty hunters: scope in, "
            "HackerOne-ready report draft out. Passive only — "
            "no scanning, no exploitation. See SAFETY.md."
        ),
    )
    parser.add_argument("--version", action="version", version="hunterswarm " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("recon", help="run passive recon against a domain")
    r.add_argument("domain", help="target domain, e.g. example.com")
    r.add_argument("-o", "--output", default=None,
                   help="write markdown report to FILE (default: stdout)")
    r.add_argument("--max-subdomains", type=int, default=50,
                   help="cap crt.sh subdomain results (default: 50)")
    r.add_argument("--save-json", default=None, metavar="FILE",
                   help="save raw recon+findings JSON for later re-reporting")
    r.set_defaults(func=cmd_recon)

    rp = sub.add_parser("report",
                        help="regenerate a markdown report from a findings JSON file")
    rp.add_argument("findings_json", help="JSON saved via recon --save-json")
    rp.add_argument("-o", "--output", default=None,
                    help="write markdown report to FILE (default: stdout)")
    rp.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
