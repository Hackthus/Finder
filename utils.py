"""
utils.py - Shared utilities for the OSINT Tool
Handles HTTP requests, rate limiting, proxy support, output formatting, and result saving.
"""

import json
import time
import random
import re
import os
from datetime import datetime
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ─────────────────────────────────────────────
#  Console colours (no external dependency)
# ─────────────────────────────────────────────
class Colors:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def banner():
    """Print the tool banner."""
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════╗
║           OSINT Reconnaissance Tool               ║
║      Red Team & Bug Bounty Edition v1.0           ║
╚═══════════════════════════════════════════════════╝
{Colors.RESET}""")


def info(msg: str):    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")
def success(msg: str): print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def warning(msg: str): print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def error(msg: str):   print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
def section(title: str):
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'═'*50}")
    print(f"  {title}")
    print(f"{'═'*50}{Colors.RESET}")


# ─────────────────────────────────────────────
#  HTTP Session factory
# ─────────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def build_session(proxy: Optional[str] = None, timeout: int = 15) -> requests.Session:
    """
    Build a requests Session with:
    - Automatic retries (3x with backoff)
    - Optional HTTP/HTTPS proxy
    - Sane timeouts
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    retry = Retry(total=3, backoff_factor=1,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    if proxy:
        proxies = {"http": proxy, "https": proxy}
        session.proxies.update(proxies)
        info(f"Proxy set: {proxy}")

    session.timeout = timeout
    return session


def rate_limit(min_s: float = 1.0, max_s: float = 3.0):
    """Sleep a random amount between requests to avoid triggering rate limits."""
    time.sleep(random.uniform(min_s, max_s))


# ─────────────────────────────────────────────
#  Email helpers
# ─────────────────────────────────────────────
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def extract_emails(text: str, domain: str) -> set:
    """Extract and filter e-mail addresses belonging to *domain* from raw text."""
    found = EMAIL_RE.findall(text)
    return {e.lower() for e in found if domain.lower() in e.lower()}


# ─────────────────────────────────────────────
#  Output / persistence
# ─────────────────────────────────────────────
def save_results(domain: str, results: dict, output_dir: str = "results"):
    """Persist results to both JSON and plain-text files."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")
    base        = os.path.join(output_dir, f"{safe_domain}_{timestamp}")

    # ── JSON ──────────────────────────────────
    json_path = f"{base}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=4, default=list)
    success(f"JSON saved → {json_path}")

    # ── TXT ───────────────────────────────────
    txt_path = f"{base}.txt"
    with open(txt_path, "w") as f:
        f.write(f"OSINT Report for {domain}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n\n")

        for section_name, items in results.items():
            f.write(f"[{section_name.upper()}]\n")
            if isinstance(items, (list, set)):
                for item in sorted(items):
                    f.write(f"  {item}\n")
            elif isinstance(items, dict):
                for k, v in items.items():
                    f.write(f"  {k}: {v}\n")
            else:
                f.write(f"  {items}\n")
            f.write("\n")
    success(f"TXT saved  → {txt_path}")
    return json_path, txt_path
