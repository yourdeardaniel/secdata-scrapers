"""
Bugzilla security bug scraper:
  - Mozilla Bugzilla — public security bugs on Firefox, Core, NSS
  - Chromium bug tracker — public security issues via monorail API

Both only scrape public, resolved bugs. No private or embargoed data.
"""
import time
import requests
from tqdm import tqdm

from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


# ================================================================
# Mozilla Bugzilla
# ================================================================

BUGZILLA_API = "https://bugzilla.mozilla.org/rest"


def search_mozilla_bugs(product, offset, limit, delay):
    """Search for public security-flagged bugs in a Mozilla product."""
    for attempt in range(3):
        try:
            r = safe_get(
                f"{BUGZILLA_API}/bug",
                params={
                    "product":       product,
                    "status":        ["RESOLVED", "VERIFIED"],
                    "resolution":    "FIXED",
                    "f1":            "keywords",
                    "o1":            "substring",
                    "v1":            "sec-",
                    "include_fields": [
                        "id", "summary", "description", "product",
                        "component", "keywords", "resolution",
                        "creation_time", "cf_last_resolved",
                        "see_also", "whiteboard",
                    ],
                    "limit":  limit,
                    "offset": offset,
                },
                timeout=20,
            )
            r.raise_for_status()
            return r.json().get("bugs", [])
        except Exception as e:
            print(f"[mozilla] Attempt {attempt+1} failed: {e}")
            time.sleep(10 * (attempt + 1))
    return []


def get_bug_comments(bug_id):
    """Fetch public comments for a bug."""
    try:
        r = safe_get(f"{BUGZILLA_API}/bug/{bug_id}/comment", timeout=15)
        r.raise_for_status()
        comments = r.json().get("bugs", {}).get(str(bug_id), {}).get("comments", [])
        # only get first 5 comments (description + key discussion)
        texts = []
        for c in comments[:5]:
            text = c.get("text", "").strip()
            if len(text) > 30:
                texts.append(text[:800])
        return texts
    except Exception:
        return []


def parse_mozilla_bug(bug, comments):
    """Build a training document from a Mozilla bug."""
    bug_id    = bug.get("id", "")
    summary   = bug.get("summary", "") or ""
    product   = bug.get("product", "") or ""
    component = bug.get("component", "") or ""
    keywords  = bug.get("keywords", []) or []
    whiteboard= bug.get("whiteboard", "") or ""
    created   = (bug.get("creation_time", "") or "")[:10]
    see_also  = bug.get("see_also", []) or []

    # extract CVEs from see_also and whiteboard
    import re
    cves = re.findall(r"CVE-\d{4}-\d{4,7}",
                      " ".join(str(s) for s in see_also) + " " + whiteboard,
                      re.IGNORECASE)

    # extract severity from keywords/whiteboard
    severity = ""
    for kw in keywords:
        if "sec-critical" in kw.lower():
            severity = "Critical"
        elif "sec-high" in kw.lower():
            severity = "High"
        elif "sec-moderate" in kw.lower():
            severity = "Moderate"
        elif "sec-low" in kw.lower():
            severity = "Low"

    if not summary:
        return None

    text_parts = [
        f"Mozilla Security Bug #{bug_id}",
        f"Product: {product} — {component}",
        f"Summary: {summary}",
    ]
    if severity:
        text_parts.append(f"Severity: {severity}")
    if cves:
        text_parts.append(f"CVEs: {', '.join(cves)}")
    if created:
        text_parts.append(f"Reported: {created}")
    if comments:
        text_parts.append(f"\nBug Description and Discussion:")
        for i, c in enumerate(comments):
            text_parts.append(f"\n[Comment {i}]:\n{c}")

    return {
        "source":   "bugzilla_mozilla",
        "id":       str(bug_id),
        "url":      f"https://bugzilla.mozilla.org/show_bug.cgi?id={bug_id}",
        "summary":  summary,
        "severity": severity,
        "cves":     cves,
        "text":     "\n".join(text_parts),
    }


def run_mozilla(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["bugzilla_mozilla"]
    if not c.get("enabled", True):
        print("[mozilla] Disabled.")
        return

    delay     = c.get("delay_seconds", 1.5)
    max_bugs  = c.get("max_bugs", 80000)
    products  = c.get("products", ["Core", "Firefox", "NSS"])

    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("mozilla_done_ids", []))

    for product in products:
        prod_key = f"mozilla_done_{product.lower().replace(' ','_')}"
        if cp.get(prod_key):
            print(f"[mozilla] {product} already done.")
            continue

        print(f"[mozilla] Fetching {product} security bugs...")
        offset     = 0
        batch_size = 100
        prod_count = 0

        with tqdm(desc=f"  Mozilla {product}", unit="bugs") as pbar:
            while prod_count < max_bugs:
                bugs = search_mozilla_bugs(product, offset, batch_size, delay)
                if not bugs:
                    break

                batch = []
                for bug in bugs:
                    bid = str(bug.get("id", ""))
                    if bid in done_ids:
                        continue

                    comments = get_bug_comments(bid)
                    time.sleep(delay * 0.3)

                    doc = parse_mozilla_bug(bug, comments)
                    if doc:
                        batch.append(doc)

                    done_ids.add(bid)
                    prod_count += 1
                    pbar.update(1)

                if batch:
                    append_jsonl(raw_file, batch)

                cp["mozilla_done_ids"] = list(done_ids)
                save_checkpoint(checkpoint_file, cp)

                offset += batch_size
                if len(bugs) < batch_size:
                    break

                time.sleep(delay)

        cp[prod_key] = True
        save_checkpoint(checkpoint_file, cp)
        print(f"[mozilla] {product}: {prod_count} bugs processed.")

    print(f"[mozilla] Done. Total: {len(done_ids)} bugs.")


# ================================================================
# Chromium / Google Bug Tracker
# ================================================================

CHROMIUM_API = "https://bugs.chromium.org/prpc/monorail.Issues/ListIssues"
CHROMIUM_ISSUE_API = "https://bugs.chromium.org/prpc/monorail.Issues/GetIssue"


def search_chromium_bugs(page_token, max_results=100):
    """Search Chromium public security bugs via the monorail API."""
    payload = {
        "projectName": "chromium",
        "query":       "label:Security Type=Bug status:Fixed",
        "maxResults":  max_results,
    }
    if page_token:
        payload["pageToken"] = page_token

    try:
        r = SESSION.post(
            CHROMIUM_API,
            json=payload,
            headers={
                "Content-Type":  "application/json",
                "Accept":        "application/json",
                "X-Xsrf-Token":  "user/anon",
            },
            timeout=20,
        )
        if r.status_code == 200:
            # monorail returns JSON with )]}' prefix for XSSI protection
            text = r.text
            if text.startswith(")]}'\n"):
                text = text[5:]
            import json
            return json.loads(text)
    except Exception as e:
        print(f"[chromium] Search failed: {e}")
    return None


def parse_chromium_issue(issue):
    """Extract training content from a Chromium bug."""
    iid     = issue.get("localId", "")
    summary = issue.get("summary", "") or ""
    labels  = [l.get("label","") for l in issue.get("labelRefs",[]) or []]
    status  = (issue.get("statusRef") or {}).get("status","")

    import re
    # extract severity from labels
    severity = ""
    for l in labels:
        if "Critical" in l:
            severity = "Critical"
        elif "High" in l:
            severity = "High"
        elif "Medium" in l:
            severity = "Medium"
        elif "Low" in l:
            severity = "Low"

    # extract CVEs from summary or labels
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", summary + " ".join(labels),
                      re.IGNORECASE)

    # get component
    components = [(c.get("path","")) for c in (issue.get("componentRefs") or [])]

    if not summary:
        return None

    # get comments/description from issue
    comments_data = issue.get("comments", []) or []
    comment_texts = []
    for c in comments_data[:4]:
        content = c.get("content","") or ""
        if len(content) > 30:
            comment_texts.append(content[:600])

    text_parts = [
        f"Chromium Security Bug #{iid}",
        f"Summary: {summary}",
    ]
    if severity:
        text_parts.append(f"Severity: {severity}")
    if cves:
        text_parts.append(f"CVEs: {', '.join(cves)}")
    if components:
        text_parts.append(f"Components: {', '.join(c for c in components if c)}")
    if status:
        text_parts.append(f"Status: {status}")
    if comment_texts:
        text_parts.append("\nBug Description:")
        for i, ct in enumerate(comment_texts):
            text_parts.append(f"\n[Comment {i}]:\n{ct}")

    return {
        "source":   "bugzilla_chromium",
        "id":       str(iid),
        "url":      f"https://bugs.chromium.org/p/chromium/issues/detail?id={iid}",
        "summary":  summary,
        "severity": severity,
        "cves":     cves,
        "text":     "\n".join(text_parts),
    }


def run_chromium(cfg, raw_file, checkpoint_file):
    """
    NOTE: Google migrated its Monorail tracker to issues.chromium.org in
    2024-2025. If the Monorail API returns 503/404, the scraper falls
    back to scraping the web UI, which may also fail post-migration.
    If both methods fail, the scraper logs a warning and continues
    with other sources. Output may be empty for this source.
    """
    c = cfg["scrapers"]["bugzilla_chromium"]
    if not c.get("enabled", True):
        print("[chromium] Disabled.")
        return

    delay    = c.get("delay_seconds", 1.5)
    max_bugs = c.get("max_bugs", 50000)

    cp         = load_checkpoint(checkpoint_file)
    done_ids   = set(cp.get("chromium_done_ids", []))
    page_token = cp.get("chromium_page_token", "")
    total      = len(done_ids)

    print(f"[chromium] Fetching public security bugs (already have {total})...")

    with tqdm(total=max_bugs, initial=total, desc="Chromium bugs") as pbar:
        while total < max_bugs:
            data = search_chromium_bugs(page_token if page_token else None)
            if not data:
                # fallback: Chromium monorail API may reject anonymous requests
                # try the issue tracker API instead
                print("[chromium] Monorail API unavailable — trying REST fallback...")
                _run_chromium_rest_fallback(
                    raw_file, checkpoint_file, done_ids, max_bugs, delay
                )
                return

            issues = data.get("issues", []) or []
            if not issues:
                break

            batch = []
            for issue in issues:
                iid = str(issue.get("localId",""))
                if iid in done_ids:
                    continue
                doc = parse_chromium_issue(issue)
                if doc:
                    batch.append(doc)
                done_ids.add(iid)
                total += 1
                pbar.update(1)

            if batch:
                append_jsonl(raw_file, batch)

            page_token = data.get("nextPageToken","")
            cp["chromium_done_ids"]   = list(done_ids)
            cp["chromium_page_token"] = page_token
            save_checkpoint(checkpoint_file, cp)

            if not page_token:
                break

            time.sleep(delay)

    print(f"[chromium] Done. {len(done_ids)} bugs.")


def _run_chromium_rest_fallback(raw_file, checkpoint_file, done_ids, max_bugs, delay):
    """
    Fallback: scrape the Chromium issue tracker web UI.
    Slower but doesn't require API auth.
    """
    from bs4 import BeautifulSoup

    base_url = "https://bugs.chromium.org/p/chromium/issues/list"
    total    = len(done_ids)

    for page in tqdm(range(1, 500), desc="Chromium (web)"):
        try:
            r = safe_get(
                base_url,
                params={
                    "q":      "label:Security Type=Bug status:Fixed",
                    "num":    100,
                    "start":  (page - 1) * 100,
                    "colspec":"ID Summary Status",
                },
                timeout=20,
            )
            if r.status_code != 200:
                break

            soup  = BeautifulSoup(r.text, "html.parser")
            rows  = soup.select("tr.tr_name, .issue-list tr")
            if not rows:
                break

            batch = []
            for row in rows:
                iid_el  = row.select_one(".id a, td a[href*='id=']")
                if not iid_el:
                    continue
                iid  = iid_el.get_text(strip=True).replace("#","")
                href = iid_el.get("href","")
                if not iid.isdigit() or iid in done_ids:
                    continue

                summ_el = row.select_one(".summary, .col_summary")
                summary = summ_el.get_text(strip=True) if summ_el else ""

                import re
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", summary)

                if summary:
                    text = "\n".join([
                        f"Chromium Security Bug #{iid}",
                        f"Summary: {summary}",
                        f"CVEs: {', '.join(cves)}" if cves else "",
                        f"URL: https://bugs.chromium.org/p/chromium/issues/detail?id={iid}",
                    ])
                    batch.append({
                        "source":  "bugzilla_chromium",
                        "id":      iid,
                        "url":     f"https://bugs.chromium.org/p/chromium/issues/detail?id={iid}",
                        "summary": summary,
                        "cves":    cves,
                        "text":    text,
                    })
                    done_ids.add(iid)
                    total += 1

            if batch:
                append_jsonl(raw_file, batch)
                cp = load_checkpoint(checkpoint_file)
                cp["chromium_done_ids"] = list(done_ids)
                save_checkpoint(checkpoint_file, cp)

            if total >= max_bugs or len(rows) < 10:
                break

            time.sleep(delay)
        except Exception as e:
            print(f"[chromium] Page {page} failed: {e}")
            break

    print(f"[chromium] Fallback done. {total} bugs.")
