import time, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

SE_API = "https://api.stackexchange.com/2.3"

def strip_html(html):
    return BeautifulSoup(html or "", "html.parser").get_text("\n", strip=True)

def fetch_questions(site, min_score, page):
    try:
        r = safe_get(f"{SE_API}/questions",
            params={"site": site, "sort": "votes", "order": "desc",
                    "pagesize": 100, "page": page, "min": min_score,
                    "filter": "withbody"}, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def fetch_answers(site, qid, min_score):
    try:
        r = safe_get(f"{SE_API}/questions/{qid}/answers",
            params={"site": site, "sort": "votes", "order": "desc",
                    "pagesize": 1, "min": min_score, "filter": "withbody"}, timeout=15)
        r.raise_for_status()
        items = r.json().get("items", [])
        return items[0] if items else None
    except Exception:
        return None

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["stackexchange"]
    if not c.get("enabled", True):
        print("[stackexchange] Disabled."); return
    sites = c.get("sites", ["security"])
    min_q = c.get("min_score", 3)
    min_a = c.get("min_answer_score", 2)
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    done_sites = set(cp.get("se_done_sites", []))
    for site in [s for s in sites if s not in done_sites]:
        page_key = f"se_{site}_page"
        start_page = cp.get(page_key, 1)
        total = 0
        print(f"[stackexchange] {site} (from page {start_page})")
        page = start_page
        while True:
            data = fetch_questions(site, min_q, page)
            if not data:
                break
            quota = data.get("quota_remaining", 9999)
            items = data.get("items", [])
            if not items:
                break
            batch = []
            for q in items:
                qid = q.get("question_id")
                title = q.get("title", "")
                body = strip_html(q.get("body", ""))
                tags = q.get("tags", [])
                qscore = q.get("score", 0)
                link = q.get("link", "")
                ans = fetch_answers(site, qid, min_a)
                time.sleep(0.5)
                if not ans:
                    continue
                ans_body = strip_html(ans.get("body", ""))
                if len(ans_body) < 80:
                    continue
                text = "\n".join(filter(None, [
                    f"Site: {site}.stackexchange.com",
                    f"Tags: {', '.join(tags)}",
                    f"Scores: Q={qscore} A={ans.get('score',0)}",
                    f"\nQuestion: {title}",
                    body[:800],
                    f"\nAnswer:\n{ans_body[:3500]}",
                ]))
                batch.append({"source": "stackexchange", "site": site,
                              "id": str(qid), "url": link, "title": title,
                              "tags": tags, "text": text,
            "license": "CC-BY-SA-4.0"})
                total += 1
            if batch:
                append_jsonl(raw_file, batch)
            cp[page_key] = page
            save_checkpoint(checkpoint_file, cp)
            page += 1
            if quota < 20:
                print(f"[stackexchange] Quota low ({quota}), stopping {site}.")
                break
            backoff = data.get("backoff", 0)
            if backoff:
                time.sleep(backoff + 1)
            else:
                time.sleep(delay)
            if not data.get("has_more", False):
                break
        done_sites.add(site)
        cp["se_done_sites"] = list(done_sites)
        save_checkpoint(checkpoint_file, cp)
        print(f"[stackexchange] {site}: {total} pairs.")
    print("[stackexchange] Done.")
