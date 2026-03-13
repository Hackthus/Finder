#!/usr/bin/env python3
"""
main.py - OSINT Reconnaissance Tool
Entry point for the CLI.

Usage:
    python main.py -d example.com
    python main.py -d example.com --proxy http://127.0.0.1:8080
    python main.py -d example.com --skip-social --output ./reports
    python main.py -d example.com --module emails
    python main.py -d example.com --module subdomains
    python main.py -d example.com --module social
"""

import argparse
import sys
import time
from datetime import datetime

from utils import banner, build_session, save_results, info, success, warning, error
from email_finder   import find_emails
from subdomain_enum import enumerate_subdomains
from social_finder  import find_social_profiles


# ─────────────────────────────────────────────
#  CLI argument parser
# ─────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="osint_tool",
        description="OSINT Reconnaissance Tool – Red Team & Bug Bounty Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -d example.com
  python main.py -d example.com --module emails
  python main.py -d example.com --module subdomains
  python main.py -d example.com --proxy http://127.0.0.1:8080
  python main.py -d example.com --output ./results --timeout 20
        """,
    )

    parser.add_argument(
        "-d", "--domain", required=True,
        help="Target domain (e.g. example.com)"
    )
    parser.add_argument(
        "--module", choices=["emails", "subdomains", "social"], default=None,
        help="Run only a specific module (default: run all)"
    )
    parser.add_argument(
        "--proxy", default=None,
        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--output", default="results",
        help="Output directory for saved reports (default: ./results)"
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Request timeout in seconds (default: 15)"
    )
    parser.add_argument(
        "--skip-social", action="store_true",
        help="Skip social media discovery (faster runs)"
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Do not save results to disk"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
#  Validation helpers
# ─────────────────────────────────────────────
def validate_domain(domain: str) -> str:
    """Normalise and sanity-check the supplied domain."""
    domain = domain.strip().lower()
    # Strip scheme if accidentally included
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Remove trailing slashes
    domain = domain.rstrip("/")

    if "." not in domain or len(domain) < 4:
        error(f"Invalid domain: {domain}")
        sys.exit(1)

    return domain


# ─────────────────────────────────────────────
#  Progress / timing helpers
# ─────────────────────────────────────────────
def _elapsed(start: float) -> str:
    secs = int(time.time() - start)
    m, s = divmod(secs, 60)
    return f"{m}m {s}s" if m else f"{s}s"


# ─────────────────────────────────────────────
#  Main orchestrator
# ─────────────────────────────────────────────
def main():
    banner()
    args   = parse_args()
    domain = validate_domain(args.domain)
    start  = time.time()

    info(f"Target  : {domain}")
    info(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.proxy:
        info(f"Proxy   : {args.proxy}")
    print()

    # Build a shared HTTP session
    session = build_session(proxy=args.proxy, timeout=args.timeout)

    # ── Collect results ──────────────────────
    results: dict = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "emails": [],
        "subdomains": [],
        "social_profiles": {},
    }

    run_all = args.module is None

    # E-mails
    if run_all or args.module == "emails":
        try:
            emails = find_emails(domain, session)
            results["emails"] = sorted(emails)
        except KeyboardInterrupt:
            warning("Email discovery interrupted.")
        except Exception as exc:
            error(f"Email discovery crashed: {exc}")

    # Subdomains
    if run_all or args.module == "subdomains":
        try:
            subs = enumerate_subdomains(domain, session)
            results["subdomains"] = sorted(subs)
        except KeyboardInterrupt:
            warning("Subdomain enumeration interrupted.")
        except Exception as exc:
            error(f"Subdomain enumeration crashed: {exc}")

    # Social profiles
    if (run_all or args.module == "social") and not args.skip_social:
        try:
            profiles = find_social_profiles(domain, session)
            results["social_profiles"] = profiles
        except KeyboardInterrupt:
            warning("Social media discovery interrupted.")
        except Exception as exc:
            error(f"Social media discovery crashed: {exc}")
    elif args.skip_social:
        info("Social media discovery skipped (--skip-social).")

    # ── Summary ──────────────────────────────
    print(f"\n{'═'*50}")
    print(f"  SCAN COMPLETE  –  elapsed: {_elapsed(start)}")
    print(f"{'═'*50}")
    print(f"  Emails found       : {len(results['emails'])}")
    print(f"  Subdomains found   : {len(results['subdomains'])}")
    social_count = sum(len(v) for v in results["social_profiles"].values())
    print(f"  Social links found : {social_count}")
    print(f"{'═'*50}\n")

    # ── Persist to disk ───────────────────────
    if not args.no_save:
        save_results(domain, results, output_dir=args.output)


# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        warning("Scan aborted by user (Ctrl-C).")
        sys.exit(0)
