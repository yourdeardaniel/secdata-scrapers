"""
Ethical scraping compliance utilities.

Three responsibilities:
  1. robots.txt enforcement before fetching any URL
  2. Hard per-domain rate limit floors that config cannot bypass
  3. Audit logging — every URL accessed recorded with timestamp

The check_url() function is the single entry point used by safe_get().
Calling it has the side effect of enforcing rate limits via time.sleep,
so callers don't need to track delays themselves.
"""
import os
import time
import urllib.robotparser
from datetime import datetime, timezone
from threading import Lock
from typing import Optional
from urllib.parse import urlparse

USER_AGENT = (
    "secdata-scraper/1.0 "
    "(+https://github.com/yourdeardaniel/secdata-scrapers research)"
)

# ── Audit log ─────────────────────────────────────────────────────
_audit_lock = Lock()
_audit_path: Optional[str] = None


def init_audit_log(path: str = "./data/audit/scrape_audit.log") -> None:
    """Open the audit log. Safe to call multiple times."""
    global _audit_path
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    _audit_path = path
    _write_audit("SESSION_START", "scraper", "",
                 datetime.now(timezone.utc).isoformat())


def _write_audit(event: str, source: str, url: str, note: str = "") -> None:
    if not _audit_path:
        return
    ts = datetime.now(timezone.utc).isoformat()
    # Tab-separated, sanitize to one line
    line = "\t".join((
        ts, event, source,
        url.replace("\t", " ").replace("\n", " ")[:500],
        note.replace("\t", " ").replace("\n", " ")[:300],
    )) + "\n"
    with _audit_lock:
        try:
            with open(_audit_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass  # don't let logging failures crash a scrape


def audit_scraped(source: str, url: str) -> None:
    _write_audit("SCRAPED", source, url)


def audit_skipped(source: str, url: str, reason: str) -> None:
    _write_audit("SKIPPED", source, url, reason)


def audit_error(source: str, url: str, error: str) -> None:
    _write_audit("ERROR", source, url, str(error)[:200])


# ── robots.txt cache ──────────────────────────────────────────────
_robots_cache: dict = {}
_robots_lock = Lock()


def can_fetch(url: str) -> bool:
    """
    Check robots.txt for the given URL.
    Caches per-domain. Defaults to True if robots.txt unreachable.

    Hosts in API_ENDPOINT_ALLOWLIST bypass robots.txt because they are
    authorized via API keys/ToS rather than crawler conventions.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False

    # Bypass robots.txt for known-authorized API endpoints
    if parsed.netloc in API_ENDPOINT_ALLOWLIST:
        return True

    domain = f"{parsed.scheme}://{parsed.netloc}"

    with _robots_lock:
        if domain in _robots_cache:
            rp = _robots_cache[domain]
        else:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(f"{domain}/robots.txt")
            try:
                rp.read()
                _robots_cache[domain] = rp
            except Exception:
                # If robots.txt unreachable, allow with warning in audit log
                _robots_cache[domain] = None
                _write_audit(
                    "ROBOTS_UNREACHABLE", "compliance",
                    f"{domain}/robots.txt", "treating as allowed"
                )
                return True

    if rp is None:
        return True
    try:
        return rp.can_fetch(USER_AGENT, url)
    except Exception:
        return True


# ── Per-domain minimum delay floors ───────────────────────────────
# These cannot be lowered by config. They protect sources from
# misconfigured scrapers and respect known-published rate limits.
MINIMUM_DELAYS = {
    "api.github.com":           0.8,
    "github.com":               1.0,
    "raw.githubusercontent.com":0.5,
    "hackerone.com":            2.0,
    "api.hackerone.com":        2.0,
    "nvd.nist.gov":             6.0,
    "services.nvd.nist.gov":    6.0,
    "api.osv.dev":              0.5,
    "bugs.chromium.org":        1.5,
    "bugzilla.mozilla.org":     1.5,
    "api.msrc.microsoft.com":   1.0,
    "eprint.iacr.org":          3.0,
    "arxiv.org":                3.0,
    "export.arxiv.org":         3.0,
    "kb.cert.org":              1.0,
    "archive.org":              2.0,
    "web.archive.org":          2.0,
    "api.stackexchange.com":    1.0,
    "thedfirreport.com":        3.0,
    "blog.quarkslab.com":       2.0,
    "blog.orange.tw":           2.0,
    "www.synacktiv.com":        2.0,
    "research.nccgroup.com":    1.5,
    "googleprojectzero.blogspot.com": 2.0,
    "blog.trailofbits.com":     1.5,
}

# Known-authorized API endpoints — hosts that provide an official API
# governed by API keys/ToS rather than robots.txt. These bypass robots.txt
# but still respect per-domain rate limits in MINIMUM_DELAYS.
API_ENDPOINT_ALLOWLIST = {
    "services.nvd.nist.gov",   # NVD CVE API (api keys at nvd.nist.gov)
    "api.github.com",          # GitHub API (PAT-authorized)
    "api.osv.dev",             # OSV vulnerability API (public, free)
    "otx.alienvault.com",      # AlienVault OTX (API key-authorized)
    "api.stackexchange.com",   # Stack Exchange API (key-authorized)
    "export.arxiv.org",        # arXiv API (formally documented as OK)
    "api.msrc.microsoft.com",  # MSRC API (public, documented)
}

DEFAULT_MIN_DELAY = 0.5

_last_request: dict = {}
_rate_lock = Lock()


def enforce_rate_limit(url: str, configured_delay: float = 1.0) -> None:
    """
    Block until enough time has elapsed since the last request to this domain.
    Uses max(configured_delay, hard_minimum_for_domain).
    """
    domain = urlparse(url).netloc
    min_delay = MINIMUM_DELAYS.get(domain, DEFAULT_MIN_DELAY)
    delay = max(configured_delay, min_delay)

    with _rate_lock:
        last = _last_request.get(domain, 0.0)
        elapsed = time.time() - last
        wait = delay - elapsed
        if wait > 0:
            time.sleep(wait)
        _last_request[domain] = time.time()


# ── Domain blocklist ──────────────────────────────────────────────
BLOCKED_DOMAINS = {
    # Paywalled / ToS-restricted
    "ieeexplore.ieee.org",
    "dl.acm.org",
    "springer.com",
    "sciencedirect.com",
    "wiley.com",
    # Anti-scraping policies we respect
    "twitter.com",
    "x.com",
    "linkedin.com",
    "facebook.com",
    # Criminal / black market
    "raidforums.com",
    "breachforums.com",
    "nulled.to",
    "cracked.io",
}


def is_blocked(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return any(
        domain == b or domain.endswith("." + b)
        for b in BLOCKED_DOMAINS
    )


# ── Single-call compliance check ──────────────────────────────────
def check_url(url: str, source: str = "scraper",
              configured_delay: float = 1.0) -> bool:
    """
    Run all compliance checks for a URL, then enforce rate limit.
    Used by safe_get() before every HTTP request.
    Returns True if safe to proceed.
    """
    if not url or not url.startswith(("http://", "https://")):
        return False

    if is_blocked(url):
        audit_skipped(source, url, "blocked_domain")
        return False

    if not can_fetch(url):
        audit_skipped(source, url, "robots_disallowed")
        return False

    enforce_rate_limit(url, configured_delay)
    return True
