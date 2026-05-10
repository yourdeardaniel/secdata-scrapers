"""
Utility module — re-exports from sub-modules for convenient imports.

Most scrapers only need:
    from utils import safe_get, clone_repo, extract_md_files, append_jsonl, \
                      load_checkpoint, save_checkpoint, ensure_dirs

Anything related to compliance, audit, or content safety is handled
automatically inside safe_get and append_jsonl. Scrapers don't need
to invoke them directly.
"""
from .storage import (
    ensure_dirs,
    append_jsonl,
    load_jsonl,
    save_jsonl,
    count_lines,
    load_checkpoint,
    save_checkpoint,
    stable_doc_id,
)
from .compliance import (
    init_audit_log,
    check_url,
    audit_scraped,
    audit_skipped,
    audit_error,
    USER_AGENT,
)
from .content_safety import (
    pre_filter_document,
    scrub_credentials,
)
from .scraping import (
    safe_get,
    safe_post,
    clone_repo,
    extract_md_files,
    parse_html,
    extract_pdf_text,
    SESSION,
)

__all__ = [
    # storage
    "ensure_dirs", "append_jsonl", "load_jsonl", "save_jsonl",
    "count_lines", "load_checkpoint", "save_checkpoint", "stable_doc_id",
    # compliance
    "init_audit_log", "check_url", "audit_scraped", "audit_skipped",
    "audit_error", "USER_AGENT",
    # content safety
    "pre_filter_document", "scrub_credentials",
    # scraping
    "safe_get", "safe_post", "clone_repo", "extract_md_files", "parse_html",
    "extract_pdf_text", "SESSION",
]
