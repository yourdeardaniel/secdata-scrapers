import time, requests
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get


def list_ecosystem(ecosystem, page_token=None):
    payload = {"ecosystem": ecosystem}
    if page_token:
        payload["page_token"] = page_token
    try:
        r = SESSION.post("https://api.osv.dev/v1/query", json=payload, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def get_detail(osv_id):
    try:
        r = safe_get(f"https://api.osv.dev/v1/vulns/{osv_id}", timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def parse_vuln(vuln):
    osv_id = vuln.get("id", "")
    summary = vuln.get("summary", "") or ""
    details = vuln.get("details", "") or ""
    if not details and not summary:
        return None
    if len(details) + len(summary) < 40:
        return None
    aliases = vuln.get("aliases", []) or []
    severity = vuln.get("severity", []) or []
    cvss = ""
    for s in severity:
        if s.get("type") in ("CVSS_V3", "CVSS_V4", "CVSS_V2"):
            cvss = str(s.get("score", ""))
            break
    affected = vuln.get("affected", []) or []
    packages = []
    for a in affected[:5]:
        pkg = a.get("package") or {}
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        if name:
            packages.append(f"{name} ({eco})")
    refs = [r.get("url","") for r in (vuln.get("references") or [])[:3]
            if r.get("type") in ("ADVISORY","ARTICLE","REPORT","WEB","FIX")]
    parts = [f"OSV Advisory: {osv_id}"]
    if aliases: parts.append(f"Aliases: {', '.join(aliases[:5])}")
    if packages: parts.append(f"Affected packages: {', '.join(packages)}")
    if cvss: parts.append(f"CVSS Score: {cvss}")
    if summary: parts.append(f"\nSummary: {summary}")
    if details: parts.append(f"\nDetails:\n{details[:3000]}")
    if refs: parts.append(f"\nReferences: {'; '.join(refs)}")
    return {"source": "osv", "id": osv_id,
            "url": f"https://osv.dev/vulnerability/{osv_id}",
            "text": "\n".join(parts)}

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["osv"]
    if not c.get("enabled", True):
        print("[osv] Disabled."); return
    ecosystems = c.get("ecosystems", [])
    delay = c.get("delay_seconds", 0.3)
    cp = load_checkpoint(checkpoint_file)
    done_ecosys = set(cp.get("osv_done_ecosystems", []))
    done_ids = set(cp.get("osv_done_ids", []))
    for ecosystem in [e for e in ecosystems if e not in done_ecosys]:
        page_token = None
        count = 0
        print(f"[osv] {ecosystem}...")
        while True:
            data = list_ecosystem(ecosystem, page_token)
            if not data:
                break
            vulns = data.get("vulns", []) or []
            if not vulns:
                break
            batch = []
            for v in tqdm(vulns, desc=f"  {ecosystem}", leave=False):
                vid = v.get("id", "")
                if not vid or vid in done_ids:
                    continue
                detail = get_detail(vid)
                parsed = parse_vuln(detail or v)
                if parsed:
                    batch.append(parsed)
                done_ids.add(vid)
                count += 1
                time.sleep(delay)
            if batch:
                append_jsonl(raw_file, batch)
            page_token = data.get("next_page_token")
            if not page_token:
                break
            cp["osv_done_ids"] = list(done_ids)
            save_checkpoint(checkpoint_file, cp)
        done_ecosys.add(ecosystem)
        cp["osv_done_ecosystems"] = list(done_ecosys)
        cp["osv_done_ids"] = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        print(f"[osv] {ecosystem}: {count}")
    print(f"[osv] Done. {len(done_ids)}")
