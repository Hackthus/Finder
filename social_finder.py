"""
social_finder.py - Social media profile discovery module
Searches for profiles and mentions of the target on:
  LinkedIn, Twitter/X, Facebook, GitHub, YouTube, Instagram, Reddit
Uses Google dorking patterns + direct URL probing.
"""

import re
import requests
from bs4 import BeautifulSoup
from typing import Dict, List
from urllib.parse import quote_plus
from utils import (
    build_session, rate_limit,
    info, success, warning, error, section
)


# ─────────────────────────────────────────────
#  Platform definitions
# ─────────────────────────────────────────────
PLATFORMS = {
    "LinkedIn": {
        "dorks": [
            'site:linkedin.com/company "{company}"',
            'site:linkedin.com "{domain}"',
        ],
        "url_patterns": [
            "https://www.linkedin.com/company/{slug}",
        ],
    },
    "Twitter/X": {
        "dorks": [
            'site:twitter.com "{company}"',
            'site:x.com "{company}"',
        ],
        "url_patterns": [
            "https://twitter.com/{slug}",
            "https://x.com/{slug}",
        ],
    },
    "GitHub": {
        "dorks": [
            'site:github.com "{company}"',
            'site:github.com "{domain}"',
        ],
        "url_patterns": [
            "https://github.com/{slug}",
        ],
    },
    "Facebook": {
        "dorks": [
            'site:facebook.com "{company}"',
        ],
        "url_patterns": [
            "https://www.facebook.com/{slug}",
        ],
    },
    "YouTube": {
        "dorks": [
            'site:youtube.com "{company}"',
        ],
        "url_patterns": [],
    },
    "Instagram": {
        "dorks": [
            'site:instagram.com "{company}"',
        ],
        "url_patterns": [
            "https://www.instagram.com/{slug}",
        ],
    },
    "Reddit": {
        "dorks": [
            'site:reddit.com "{company}"',
            'site:reddit.com/r "{domain}"',
        ],
        "url_patterns": [
            "https://www.reddit.com/r/{slug}",
        ],
    },
}


# ─────────────────────────────────────────────
#  Slug generation from domain name
# ─────────────────────────────────────────────
def _domain_to_slugs(domain: str) -> List[str]:
    """
    Generate likely usernames/slugs from a domain name.
    e.g.  example.com  →  ['example', 'examplecom']
    """
    base = domain.split(".")[0]
    slugs = [base, domain.replace(".", ""), domain.replace(".", "-")]
    return list(dict.fromkeys(slugs))   # deduplicate, preserve order


def _domain_to_company(domain: str) -> str:
    """Best-guess company name from domain."""
    return domain.split(".")[0].replace("-", " ").replace("_", " ").title()


# ─────────────────────────────────────────────
#  DuckDuckGo search scraping
# ─────────────────────────────────────────────
_URL_RE = re.compile(r'href="(https?://[^"]+)"')

def _ddg_search(query: str, session: requests.Session) -> List[str]:
    """Scrape DuckDuckGo HTML results and return raw URLs found."""
    try:
        r = session.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            timeout=session.timeout,
        )
        soup = BeautifulSoup(r.text, "html.parser")
        urls = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                urls.append(href)
        return urls
    except Exception as exc:
        error(f"  DDG search error [{query[:50]}]: {exc}")
        return []


# ─────────────────────────────────────────────
#  Direct URL probe
# ─────────────────────────────────────────────
def _probe_url(url: str, session: requests.Session) -> bool:
    """Return True if the URL returns a 200 response."""
    try:
        r = session.head(url, timeout=8, allow_redirects=True)
        return r.status_code == 200
    except Exception:
        return False


# ─────────────────────────────────────────────
#  GitHub-specific API lookup
# ─────────────────────────────────────────────
def _github_api_search(domain: str, company: str,
                        session: requests.Session) -> List[str]:
    """Use the public GitHub search API (no auth, limited rate)."""
    results = []
    queries = [domain, company]
    for q in queries:
        try:
            r = session.get(
                "https://api.github.com/search/users",
                params={"q": f'"{q}" in:login,name,email', "per_page": 5},
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    results.append(item.get("html_url", ""))
            rate_limit(2.0, 4.0)
        except Exception as exc:
            error(f"  GitHub API error: {exc}")
    return [u for u in results if u]


# ─────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────
def find_social_profiles(domain: str, session: requests.Session) -> Dict[str, List[str]]:
    """
    Discover social media profiles for *domain*.
    Returns a dict: {platform_name: [list_of_profile_urls]}
    """
    section("SOCIAL MEDIA DISCOVERY")
    company = _domain_to_company(domain)
    slugs   = _domain_to_slugs(domain)

    info(f"  Target domain  : {domain}")
    info(f"  Inferred company: {company}")
    info(f"  Candidate slugs : {', '.join(slugs)}")

    all_results: Dict[str, List[str]] = {}

    for platform, config in PLATFORMS.items():
        info(f"\n  [{platform}]")
        platform_urls: List[str] = []

        # ── 1. Dork-based search ────────────────
        for dork_template in config["dorks"]:
            dork = dork_template.format(company=company, domain=domain)
            urls = _ddg_search(dork, session)
            for url in urls:
                # Only keep links that point to this platform
                if any(kw in url for kw in [
                    "linkedin.com", "twitter.com", "x.com", "github.com",
                    "facebook.com", "youtube.com", "instagram.com", "reddit.com"
                ]):
                    if url not in platform_urls:
                        platform_urls.append(url)
            rate_limit(3.0, 6.0)

        # ── 2. Direct URL probe ─────────────────
        for url_pattern in config["url_patterns"]:
            for slug in slugs:
                url = url_pattern.format(slug=slug)
                if _probe_url(url, session):
                    success(f"    ✓ Direct profile found: {url}")
                    if url not in platform_urls:
                        platform_urls.append(url)
                rate_limit(0.5, 1.5)

        # ── 3. GitHub API (extra depth) ─────────
        if platform == "GitHub":
            gh_urls = _github_api_search(domain, company, session)
            for u in gh_urls:
                if u not in platform_urls:
                    platform_urls.append(u)

        if platform_urls:
            success(f"    Found {len(platform_urls)} result(s)")
            for u in platform_urls[:10]:   # cap display at 10
                print(f"      {u}")
        else:
            warning(f"    No results for {platform}")

        if platform_urls:
            all_results[platform] = platform_urls

    return all_results
