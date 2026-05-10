import time
import requests
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_post

GRAPHQL_URL = "https://hackerone.com/graphql"

QUERY = """
query HacktivityQuery($cursor: String) {
  hacktivity_items(first: 50 after: $cursor order_by: { field: popular direction: DESC }
    where: { report: { disclosed_at: { _is_null: false } } }) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on HacktivityItem {
        report {
          id title vulnerability_information severity_rating
          weakness { name }
          team { name }
        }
      }
    }
  }
}
"""

def fetch_page(cursor):
    for attempt in range(3):
        try:
            r = safe_post(GRAPHQL_URL,
                source="hackerone",
                json={"query": QUERY, "variables": {"cursor": cursor}}, timeout=20)
            if r is None:
                time.sleep(10 * (attempt + 1))
                continue
            return r.json()
        except Exception as e:
            time.sleep(10 * (attempt + 1))
    return None

def parse_node(node):
    report = node.get("report")
    if not report:
        return None
    vuln_info = report.get("vulnerability_information", "") or ""
    if len(vuln_info) < 80:
        return None
    rid = report.get("id", "")
    title = report.get("title", "") or ""
    severity = report.get("severity_rating", "") or ""
    weakness = (report.get("weakness") or {}).get("name", "")
    team = (report.get("team") or {}).get("name", "")
    parts = [f"HackerOne Bug Bounty Report: {title}"]
    if team: parts.append(f"Program: {team}")
    if severity: parts.append(f"Severity: {severity}")
    if weakness: parts.append(f"Vulnerability type: {weakness}")
    parts.append(f"\nVulnerability Details:\n{vuln_info[:5000]}")
    return {"source": "hackerone", "id": str(rid),
            "url": f"https://hackerone.com/reports/{rid}",
            "severity": severity, "weakness": weakness,
            "text": "\n".join(parts)}

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["hackerone"]
    if not c.get("enabled", True):
        print("[hackerone] Disabled."); return
    max_pages = c.get("pages", 100)
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    cursor = cp.get("hackerone_cursor", None)
    done_ids = set(cp.get("hackerone_done_ids", []))
    with tqdm(total=max_pages * 50, initial=len(done_ids), desc="HackerOne") as pbar:
        for page in range(max_pages):
            data = fetch_page(cursor)
            if not data:
                break
            items_data = (data.get("data") or {}).get("hacktivity_items") or {}
            nodes = items_data.get("nodes", []) or []
            page_info = items_data.get("pageInfo") or {}
            batch = []
            for node in nodes:
                parsed = parse_node(node)
                if not parsed or parsed["id"] in done_ids:
                    continue
                batch.append(parsed)
                done_ids.add(parsed["id"])
                pbar.update(1)
            if batch:
                append_jsonl(raw_file, batch)
            cursor = page_info.get("endCursor")
            cp["hackerone_cursor"] = cursor
            cp["hackerone_done_ids"] = list(done_ids)
            save_checkpoint(checkpoint_file, cp)
            if not page_info.get("hasNextPage") or not cursor:
                break
            time.sleep(delay)
    print(f"[hackerone] Done. {len(done_ids)}")
