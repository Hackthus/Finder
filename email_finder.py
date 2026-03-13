"""
email_finder.py - Email discovery module
Finds e-mail addresses associated with a target domain via:
  1. Direct scraping of the domain's public pages
  2. crt.sh certificate data (often contains admin contacts)
  3. Bing/DuckDuckGo search-result scraping
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import Set, Optional
from utils import (
    build_session, extract_emails, rate_limit,
    info, success, warning, error, section
)


# ─────────────────────────────────────────────
#  Page-scraping helpers
# ─────────────────────────────────────────────
_CONTACT_PATHS = [
    "", "/contact", "/contact-us", "/about", "/about-us",
    "/team", "/staff", "/support", "/help", "/privacy",
    "/imprint", "/impressum",
]


def _scrape_url(session: requests.Session, url: str, domain: str) -> Set[str]:
    """Fetch *url* and return any e-mails belonging to *domain*."""
    try:
        r = session.get(url, timeout=session.timeout)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        # Also look inside mailto: links
        mailto = {
            a["href"].replace("mailto:", "").split("?")[0].lower()
            for a in soup.find_all("a", href=re.compile(r"^mailto:", re.I))
        }
        text_emails = extract_emails(r.text, domain)
        return text_emails | {e for e in mailto if domain.lower() in e}
    except Exception as exc:
        error(f"  Scrape failed for {url}: {exc}")
        return set()


def scrape_website(domain: str, session: requests.Session) -> Set[str]:
    """Scrape common pages on both http and https variants of the domain."""
    emails: Set[str] = set()
    info("  Scraping website pages …")
    for scheme in ("https://", "http://"):
        for path in _CONTACT_PATHS:
            url = f"{scheme}{domain}{path}"
            found = _scrape_url(session, url, domain)
            if found:
                success(f"    Found {len(found)} email(s) at {url}")
                emails |= found
            rate_limit(0.5, 1.5)
    return emails


# ─────────────────────────────────────────────
#  Bing search scraping
# ─────────────────────────────────────────────
def search_bing(domain: str, session: requests.Session) -> Set[str]:
    """
    Query Bing for e-mail addresses related to the domain.
    Uses a series of search queries and scrapes result snippets.
    """
    emails: Set[str] = set()
    queries = [
        f'"@{domain}"',
        f'site:{domain} email',
        f'"{domain}" contact email',
        f'intext:"@{domain}"',
    ]
    info("  Querying Bing for emails …")
    for q in queries:
        try:
            url = "https://www.bing.com/search"
            r = session.get(url, params={"q": q, "count": 50}, timeout=session.timeout)
            found = extract_emails(r.text, domain)
            if found:
                success(f"    Bing [{q}] → {len(found)} email(s)")
                emails |= found
            rate_limit(2.0, 4.0)
        except Exception as exc:
            error(f"  Bing search error: {exc}")
    return emails


# ─────────────────────────────────────────────
#  DuckDuckGo HTML search scraping
# ─────────────────────────────────────────────
def search_duckduckgo(domain: str, session: requests.Session) -> Set[str]:
    """Scrape DuckDuckGo HTML results for e-mails."""
    emails: Set[str] = set()
    queries = [f'"@{domain}"', f'"{domain}" email contact']
    info("  Querying DuckDuckGo for emails …")
    for q in queries:
        try:
            r = session.get(
                "https://html.duckduckgo.com/html/",
                params={"q": q},
                timeout=session.timeout,
            )
            found = extract_emails(r.text, domain)
            if found:
                success(f"    DDG [{q}] → {len(found)} email(s)")
                emails |= found
            rate_limit(2.0, 5.0)
        except Exception as exc:
            error(f"  DuckDuckGo search error: {exc}")
    return emails


# ─────────────────────────────────────────────
#  Public API  (Hunter.io style guessing – no key needed)
# ─────────────────────────────────────────────
_COMMON_PREFIXES = [
    "info", "contact", "admin", "support", "hello", "sales",
    "security", "abuse", "webmaster", "noreply", "no-reply",
    "mail", "team", "help", "press", "careers", "jobs",
]

def generate_common_emails(domain: str) -> Set[str]:
    """Generate a list of commonly-used mailbox names for the domain."""
    return {f"{prefix}@{domain}" for prefix in _COMMON_PREFIXES}


# ─────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────
def find_emails(domain: str, session: requests.Session) -> Set[str]:
    """
    Orchestrate all e-mail discovery methods.
    Returns a deduplicated set of e-mail addresses.
    """
    section("EMAIL DISCOVERY")
    all_emails: Set[str] = set()

    all_emails |= scrape_website(domain, session)
    all_emails |= search_bing(domain, session)
    all_emails |= search_duckduckgo(domain, session)

    common = generate_common_emails(domain)
    info(f"  Added {len(common)} common pattern emails (unverified)")
    all_emails |= common

    # ── Summary ───────────────────────────────
    if all_emails:
        success(f"Total unique emails found: {len(all_emails)}")
        for email in sorted(all_emails):
            print(f"    {email}")
    else:
        warning("No emails discovered.")

    return all_emails
