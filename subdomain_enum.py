"""
subdomain_enum.py - Subdomain enumeration module
Discovers subdomains through:
  1. crt.sh  – Certificate Transparency log API
  2. HackerTarget  – free subdomain lookup API
  3. DNS brute-force with a built-in wordlist
"""

import socket
import threading
import requests
from typing import Set
from queue import Queue, Empty
from utils import (
    build_session, rate_limit,
    info, success, warning, error, section
)


# ─────────────────────────────────────────────
#  Built-in wordlist  (extend as needed)
# ─────────────────────────────────────────────
WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "admin", "portal", "test", "app", "beta", "static", "cdn", "git",
    "gitlab", "github", "jenkins", "jira", "confluence", "wiki", "docs",
    "support", "help", "status", "monitor", "dashboard", "panel",
    "cpanel", "whm", "plesk", "mysql", "db", "database", "backup",
    "internal", "intranet", "corp", "office", "vpn2", "citrix",
    "exchange", "owa", "autodiscover", "autoconfig", "meet", "video",
    "calendar", "auth", "sso", "login", "register", "account",
    "payment", "pay", "billing", "invoice", "assets", "images",
    "uploads", "media", "download", "files", "cloud", "s3", "storage",
    "v1", "v2", "v3", "old", "new", "prod", "production", "uat",
    "sandbox", "preview", "demo", "lab", "research", "data", "analytics",
]


# ─────────────────────────────────────────────
#  crt.sh – Certificate Transparency
# ─────────────────────────────────────────────
def crtsh_enum(domain: str, session: requests.Session) -> Set[str]:
    """Query crt.sh for all certificates that include *domain*."""
    subdomains: Set[str] = set()
    info("  Querying crt.sh (Certificate Transparency) …")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = session.get(url, timeout=20)
        r.raise_for_status()
        for entry in r.json():
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lower()
                # Remove wildcard prefix and validate
                if sub.startswith("*."):
                    sub = sub[2:]
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
        success(f"  crt.sh found {len(subdomains)} subdomains")
    except Exception as exc:
        error(f"  crt.sh error: {exc}")
    return subdomains


# ─────────────────────────────────────────────
#  HackerTarget API
# ─────────────────────────────────────────────
def hackertarget_enum(domain: str, session: requests.Session) -> Set[str]:
    """Use the free HackerTarget hostsearch API."""
    subdomains: Set[str] = set()
    info("  Querying HackerTarget API …")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = session.get(url, timeout=20)
        r.raise_for_status()
        for line in r.text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
        success(f"  HackerTarget found {len(subdomains)} subdomains")
    except Exception as exc:
        error(f"  HackerTarget error: {exc}")
    return subdomains


# ─────────────────────────────────────────────
#  DNS brute-force
# ─────────────────────────────────────────────
_DNS_TIMEOUT = 3      # seconds per DNS query
_DNS_THREADS = 20     # parallel resolver threads


def _resolve_worker(domain: str, q: Queue, found: Set[str], lock: threading.Lock):
    """Thread worker: dequeue a prefix, attempt DNS resolution."""
    while True:
        try:
            prefix = q.get_nowait()
        except Empty:
            break
        target = f"{prefix}.{domain}"
        try:
            socket.setdefaulttimeout(_DNS_TIMEOUT)
            results = socket.getaddrinfo(target, None)
            if results:
                with lock:
                    found.add(target)
        except (socket.gaierror, socket.herror, socket.timeout):
            pass
        finally:
            q.task_done()


def dns_bruteforce(domain: str) -> Set[str]:
    """Brute-force subdomains using the built-in wordlist and parallel threads."""
    info(f"  DNS brute-force ({len(WORDLIST)} words, {_DNS_THREADS} threads) …")
    found: Set[str] = set()
    lock = threading.Lock()
    q: Queue = Queue()
    for word in WORDLIST:
        q.put(word)

    threads = []
    for _ in range(_DNS_THREADS):
        t = threading.Thread(target=_resolve_worker,
                             args=(domain, q, found, lock),
                             daemon=True)
        t.start()
        threads.append(t)

    q.join()
    for t in threads:
        t.join(timeout=1)

    success(f"  Brute-force resolved {len(found)} subdomains")
    return found


# ─────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────
def enumerate_subdomains(domain: str, session: requests.Session) -> Set[str]:
    """
    Run all subdomain enumeration methods and return a merged, sorted set.
    """
    section("SUBDOMAIN ENUMERATION")
    all_subs: Set[str] = set()

    all_subs |= crtsh_enum(domain, session)
    rate_limit(1.0, 2.0)
    all_subs |= hackertarget_enum(domain, session)
    rate_limit(1.0, 2.0)
    all_subs |= dns_bruteforce(domain)

    # Filter out entries that don't actually belong to the target domain
    all_subs = {s for s in all_subs if domain in s}

    if all_subs:
        success(f"Total unique subdomains found: {len(all_subs)}")
        for sub in sorted(all_subs):
            print(f"    {sub}")
    else:
        warning("No subdomains discovered.")

    return all_subs
