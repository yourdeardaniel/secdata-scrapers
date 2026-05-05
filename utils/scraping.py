"""
Shared scraping helpers used by all scrapers.

Moved here from being duplicated across 7+ scraper files because:
  1. Consistency — every scraper now uses the same retry policy,
     timeout values, and error handling.
  2. Compliance integration — safe_get now invokes compliance.check_url
     on every request, enforcing robots.txt and rate limits automatically.
  3. Maintainability — bug fixes propagate to every scraper at once.
  4. Testability — these are the only functions doing I/O, so testing
     them tests the full data path.
"""
import io
import os
import re
import subprocess
import time
from typing import Optional

import requests
from bs4 import BeautifulSoup

from .compliance import check_url, USER_AGENT


# Single shared HTTP session — keeps connections alive across requests
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": USER_AGENT,
    "Accept-Encoding": "gzip, deflate",
})

# Retry status codes that warrant backoff
RETRY_STATUSES = {429, 500, 502, 503, 504}


def safe_get(
    url: str,
    *,
    source: str = "unknown",
    delay: float = 1.0,
    timeout: int = 20,
    retries: int = 3,
    params: dict = None,
    headers: dict = None,
    **session_kwargs,
) -> Optional[requests.Response]:
    """
    HTTP GET with built-in compliance checking, retry, and backoff.

    Uses the shared SESSION (no per-request socket setup).
    Honors robots.txt via compliance.check_url.
    Enforces per-domain minimum delays.
    Logs every request to the audit log.

    Accepts the same params/headers/etc as requests.Session.get(),
    so it's a near-drop-in replacement for SESSION.get(url, ...).

    Returns None on permanent failure (404, blocked, repeated 5xx).
    """
    if not check_url(url, source, delay):
        return None

    request_kwargs = {
        "timeout": timeout,
        "allow_redirects": True,
        **session_kwargs,
    }
    if params is not None:
        request_kwargs["params"] = params
    if headers is not None:
        request_kwargs["headers"] = headers

    for attempt in range(retries):
        try:
            r = SESSION.get(url, **request_kwargs)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                return None
            if r.status_code in RETRY_STATUSES:
                # Exponential backoff for transient errors
                wait = min(60, 5 * (2 ** attempt))
                time.sleep(wait)
                continue
            # Other 4xx — don't retry, treat as permanent failure
            return None
        except requests.exceptions.Timeout:
            time.sleep(5 * (attempt + 1))
        except requests.exceptions.ConnectionError:
            time.sleep(5 * (attempt + 1))
        except Exception:
            return None
    return None





def safe_post(
    url: str,
    *,
    source: str = "unknown",
    delay: float = 1.0,
    timeout: int = 30,
    retries: int = 3,
    json: dict = None,
    data=None,
    headers: dict = None,
    **session_kwargs,
) -> Optional[requests.Response]:
    """
    HTTP POST with the same compliance + retry semantics as safe_get.

    Used for GraphQL APIs and any source that requires POST.
    Honors robots.txt the same way GET does, and applies rate limits.
    """
    if not check_url(url, source, delay):
        return None

    request_kwargs = {
        "timeout": timeout,
        "allow_redirects": True,
        **session_kwargs,
    }
    if json is not None:
        request_kwargs["json"] = json
    if data is not None:
        request_kwargs["data"] = data
    if headers is not None:
        request_kwargs["headers"] = headers

    for attempt in range(retries):
        try:
            r = SESSION.post(url, **request_kwargs)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                return None
            if r.status_code in RETRY_STATUSES:
                wait = min(60, 5 * (2 ** attempt))
                time.sleep(wait)
                continue
            return None
        except requests.exceptions.Timeout:
            time.sleep(5 * (attempt + 1))
        except requests.exceptions.ConnectionError:
            time.sleep(5 * (attempt + 1))
        except Exception:
            return None
    return None


def clone_repo(url: str, dest: str, *, timeout: int = 300, depth: int = 1) -> bool:
    """
    Shallow-clone a Git repository for content extraction.

    If dest already contains a .git directory, fetches updates instead of cloning.
    Uses --filter=blob:limit=2m to skip large binary files (LFS objects, etc).
    Returns True on success.
    """
    os.makedirs(dest, exist_ok=True)

    if os.path.exists(os.path.join(dest, ".git")):
        # Already cloned — pull latest
        try:
            result = subprocess.run(
                ["git", "-C", dest, "pull", "--quiet", "--ff-only"],
                capture_output=True, timeout=120, text=True,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return True  # repo exists, just couldn't update — still usable

    try:
        result = subprocess.run(
            ["git", "clone",
             f"--depth={depth}",
             "--filter=blob:limit=2m",
             "--single-branch",
             url, dest],
            capture_output=True, timeout=timeout, text=True,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


# File extensions worth reading from cloned repos
TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".asciidoc", ".adoc"}

# Files we never want to extract even if their extension matches
SKIP_FILENAMES = {
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
    "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
}

SKIP_DIRS = {
    ".git", ".github", "__pycache__", "node_modules",
    "i18n", "translations", ".vscode", ".idea",
    "vendor", "third_party",
}


def extract_md_files(
    repo_dir: str,
    source_name: str,
    url_base: str,
    label: str = "",
    *,
    max_file_bytes: int = 400_000,
    min_text_len: int = 150,
    max_text_chars: int = 7000,
) -> list:
    """
    Walk a cloned repo and extract documentation files as raw documents.

    Skips:
      - Hidden directories and common non-content directories
      - Files larger than max_file_bytes (cuts off generated docs)
      - Files shorter than min_text_len (low signal)
      - Boilerplate files like CONTRIBUTING.md, LICENSE
    """
    docs = []
    for root, dirs, files in os.walk(repo_dir):
        # Prune directories in place
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in SKIP_DIRS
        ]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            if fname in SKIP_FILENAMES:
                continue

            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > max_file_bytes:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except (OSError, IOError):
                continue

            if len(text) < min_text_len:
                continue

            rel_path = os.path.relpath(fpath, repo_dir)
            title = (
                fname.rsplit(".", 1)[0]
                .replace("-", " ")
                .replace("_", " ")
                .strip()
            )
            prefix = f"{label}: " if label else ""

            docs.append({
                "source": source_name,
                "file":   rel_path,
                "title":  title,
                "url":    url_base,
                "text":   f"{prefix}{title}\n\n{text[:max_text_chars]}",
            })
    return docs


def parse_html(content) -> BeautifulSoup:
    """Parse HTML using lxml if available, else built-in html.parser."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    try:
        return BeautifulSoup(content, "lxml")
    except Exception:
        return BeautifulSoup(content, "html.parser")


def extract_pdf_text(content_bytes: bytes, max_pages: int = 50) -> str:
    """
    Extract text from a PDF byte-string.
    Returns empty string on failure (some PDFs are images, encrypted, etc.).
    """
    try:
        import pdfplumber
    except ImportError:
        return ""

    try:
        with pdfplumber.open(io.BytesIO(content_bytes)) as pdf:
            parts = []
            for page in pdf.pages[:max_pages]:
                t = page.extract_text()
                if t:
                    parts.append(t)
            return "\n".join(
                line for line in "\n".join(parts).split("\n")
                if len(line.strip()) > 2
            )
    except Exception:
        return ""
