import time, requests
from datetime import datetime, timedelta
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD API enforces a 120-day maximum date range per query.
# Requesting more than 120 days returns HTTP 404 with a message about range limits.
NVD_MAX_RANGE_DAYS = 119  # keep slightly under the limit for safety


def fetch_page(params, api_key=None):
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(3):
        try:
            r = safe_get(NVD_BASE, source="nvd", params=params, headers=headers, timeout=30)
            if r is None:
                # safe_get returned None — robots.txt block or hard failure.
                # Don't retry; the block will repeat. Caller should move on.
                return None
            if r.status_code in (403, 503):
                time.sleep(30); continue
            if r.status_code == 404:
                # NVD returns 404 for invalid params (e.g. date range too wide).
                # Don't retry; surface failure to caller.
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            time.sleep(10 * (attempt + 1))
    return None


def parse_cve(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None
    desc = next((d.get("value","") for d in cve.get("descriptions",[])
                 if d.get("lang") == "en"), "")
    if not desc or len(desc) < 30:
        return None
    metrics = cve.get("metrics", {})
    cvss_score = severity = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_score = str(data.get("baseScore", ""))
            severity = entries[0].get("baseSeverity", data.get("baseSeverity", ""))
            break
    cwes = [d["value"] for w in cve.get("weaknesses",[])
            for d in w.get("description",[]) if d.get("lang")=="en" and d.get("value","").startswith("CWE-")]
    refs = [r.get("url","") for r in cve.get("references",[])[:3] if r.get("url")]
    published = cve.get("published","")[:10]
    parts = [f"CVE: {cve_id}", f"Published: {published}", f"Description: {desc}"]
    if cvss_score:
        parts.append(f"CVSS Score: {cvss_score}" + (f" ({severity})" if severity else ""))
    if cwes:
        parts.append(f"CWE: {', '.join(cwes[:5])}")
    if refs:
        parts.append(f"References: {'; '.join(refs)}")
    return {"source": "nvd", "id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "severity": severity, "cvss_score": cvss_score,
            "published": published, "text": "\n".join(parts)}


def iter_date_chunks(year, chunk_days=NVD_MAX_RANGE_DAYS):
    """
    Yield (start_iso, end_iso) tuples spanning a calendar year,
    each at most chunk_days long. NVD requires this because the
    API rejects date ranges longer than 120 days.
    """
    start = datetime(year, 1, 1)
    end_of_year = datetime(year, 12, 31, 23, 59, 59, 999000)
    while start <= end_of_year:
        chunk_end = min(start + timedelta(days=chunk_days), end_of_year)
        yield (start.strftime("%Y-%m-%dT%H:%M:%S.000"),
               chunk_end.strftime("%Y-%m-%dT%H:%M:%S.999"))
        start = chunk_end + timedelta(seconds=1)


def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["nvd"]
    if not c.get("enabled", True):
        print("[nvd] Disabled."); return
    api_key = cfg["api"].get("nvd_api_key", "")
    delay = 0.6 if api_key else c.get("delay_seconds", 6.0)
    per_page = min(c.get("results_per_page", 2000), 2000)
    cp = load_checkpoint(checkpoint_file)
    done_years = set(cp.get("nvd_done_years", []))
    for year in range(c.get("start_year", 2010), c.get("end_year", datetime.now().year) + 1):
        if str(year) in done_years:
            continue
        year_count = 0
        print(f"[nvd] Year {year}...")
        for pub_start, pub_end in iter_date_chunks(year):
            start_index = 0
            while True:
                data = fetch_page({
                    "pubStartDate": pub_start,
                    "pubEndDate":   pub_end,
                    "startIndex":   start_index,
                    "resultsPerPage": per_page,
                }, api_key if api_key else None)
                if not data:
                    break
                total = data.get("totalResults", 0)
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break
                batch = [p for v in vulns for p in [parse_cve(v)] if p]
                if batch:
                    append_jsonl(raw_file, batch)
                    year_count += len(batch)
                start_index += len(vulns)
                if start_index >= total:
                    break
                time.sleep(delay)
            time.sleep(delay)
        print(f"[nvd] Year {year}: {year_count}")
        done_years.add(str(year))
        cp["nvd_done_years"] = list(done_years)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)
    print("[nvd] Done.")
