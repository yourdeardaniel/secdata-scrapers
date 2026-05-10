"""
Storage utilities with integrated safety pre-filtering.
All raw documents pass through content_safety.pre_filter_document
before being written to disk.
"""
import json, os, hashlib
from .content_safety import pre_filter_document
from .compliance import audit_scraped, audit_skipped

def ensure_dirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def append_jsonl(path, docs: list):
    """Write docs to JSONL, applying safety pre-filter to each."""
    if not docs: return
    kept = skipped = 0
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for doc in docs:
            keep, reason, doc = pre_filter_document(doc)
            if not keep:
                audit_skipped(doc.get("source","unknown"),
                              doc.get("url",""),
                              f"pre_filter:{reason}")
                skipped += 1
                continue
            audit_scraped(doc.get("source","unknown"), doc.get("url",""))
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
            kept += 1
    return kept, skipped

def load_jsonl(path) -> list:
    if not os.path.exists(path): return []
    docs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try: docs.append(json.loads(line))
                except json.JSONDecodeError: pass
    return docs

def save_jsonl(path, docs: list):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")

def count_lines(path) -> int:
    if not os.path.exists(path): return 0
    with open(path, "rb") as f:
        return sum(1 for _ in f)

def load_checkpoint(path) -> dict:
    if not os.path.exists(path): return {}
    try:
        with open(path, "r") as f: return json.load(f)
    except Exception: return {}

def save_checkpoint(path, data: dict):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f: json.dump(data, f)

def stable_doc_id(doc: dict) -> str:
    """Deterministic document ID — safe across Python restarts."""
    return (doc.get("url") or doc.get("id") or doc.get("file","") or
            "txt:" + hashlib.md5(
                doc.get("text","")[:200].encode("utf-8")).hexdigest()[:16])
