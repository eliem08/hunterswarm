"""hunterswarm — passive recon for bug-bounty hunters.

Scope in, HackerOne-ready report draft out.

PASSIVE-ONLY: every module in this package performs read-only,
non-intrusive observation of publicly available data (certificate
transparency logs, DNS, and single benign HTTP requests). No port
scanning, no brute-forcing, no exploitation, no active vulnerability
probing. See SAFETY.md.
"""

__version__ = "0.1.0"
__author__ = "Ilyass Emssaad"

from hunterswarm.recon import run_pipeline, run_recon
from hunterswarm.report import generate_report

__all__ = ["run_pipeline", "run_recon", "generate_report", "__version__"]
