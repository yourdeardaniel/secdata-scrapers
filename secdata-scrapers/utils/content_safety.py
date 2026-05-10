"""
Content safety pre-filter — runs at scrape time, before raw documents
are written to disk. Catches content that should not be in a public
dataset regardless of how the converter handles it.

This is a lightweight heuristic filter, not a comprehensive safety system.
The converter prompt and LM quality filter are the main safety layers.
This layer catches the obvious cases so they never reach the LLM.

Three categories of content are blocked:
  1. Operational attack content targeting named real infrastructure
  2. Content with no security research value (pure IOC dumps without context)
  3. Accidentally captured sensitive data (credentials, PII)
"""
from __future__ import annotations

import re

# ── Patterns that suggest operational attack targeting ────────────
# These flag content that names a specific real target alongside
# attack methodology — as opposed to generic technique explanation.
OPERATIONAL_PATTERNS = [
    # Specific IP + attack pattern (not in educational context)
    r"attack\s+(?:this\s+)?(?:ip|address|server|host)[\s:]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    # Named real org + exploitation steps (not CVE description)
    r"(?:how to|step[s]? to|exploit)\s+(?:hack|compromise|take down|ddos)\s+\w+(?:\.com|\.org|\.gov|\.net)",
    # Doxxing patterns
    r"(?:home address|personal (?:phone|email|address)|real name|lives at|works at)\s+of\s+\w+",
]

# ── Credential / PII patterns ────────────────────────────────────
# These catch accidentally scraped sensitive data.
CREDENTIAL_PATTERNS = [
    r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*]{6,}",
    r"(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"ghp_[A-Za-z0-9]{36}",          # GitHub personal access token
    r"sk-[A-Za-z0-9]{48}",           # OpenAI API key
    r"AKIA[0-9A-Z]{16}",             # AWS access key
    r"(?:eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",  # JWT
]

# ── PII patterns ─────────────────────────────────────────────────
PII_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",        # SSN
    r"\b(?:\d{4}[- ]?){3}\d{4}\b",   # Credit card
    r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",  # Phone
]

_compiled_operational   = [re.compile(p, re.IGNORECASE) for p in OPERATIONAL_PATTERNS]
_compiled_credentials   = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]
_compiled_pii           = [re.compile(p) for p in PII_PATTERNS]


def scrub_credentials(text: str) -> str:
    """
    Replace detected credentials and PII with placeholder strings.
    Called before writing any document to disk.
    Does not block the document — just removes the sensitive data.
    """
    for pattern in _compiled_credentials:
        text = pattern.sub("[CREDENTIAL_REDACTED]", text)
    for pattern in _compiled_pii:
        text = pattern.sub("[PII_REDACTED]", text)
    return text


def is_operational_attack_content(text: str) -> bool:
    """
    Returns True if the text appears to be operational attack assistance
    targeting a specific real system, rather than educational content.
    Conservative — only blocks clear matches.
    """
    if len(text) < 100:
        return False
    for pattern in _compiled_operational:
        if pattern.search(text):
            return True
    return False


def pre_filter_document(doc: dict) -> tuple[bool, str, dict]:
    """
    Run pre-filter checks on a raw document before writing to disk.

    Returns:
      (keep: bool, reason: str, doc: dict)
      keep=False means discard. doc is modified in-place to scrub credentials.
    """
    text = doc.get("text", "")

    # Empty or trivially short
    if len(text) < 50:
        return False, "too_short", doc

    # Operational attack targeting
    if is_operational_attack_content(text):
        return False, "operational_attack_content", doc

    # Scrub credentials and PII in place before writing
    scrubbed = scrub_credentials(text)
    if "[CREDENTIAL_REDACTED]" in scrubbed or "[PII_REDACTED]" in scrubbed:
        doc = {**doc, "text": scrubbed, "_had_credentials_scrubbed": True}

    return True, "ok", doc
