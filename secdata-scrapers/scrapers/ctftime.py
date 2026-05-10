import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

BASE = "https://ctftime.org"
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})

def get_writeup_urls(pages, delay):
    urls = set()
    for page in tqdm(range(1, pages + 1), desc="CTFtime index"):
        try:
            r = safe_get(f"{BASE}/writeups/", params={"page": page}, timeout=15)
            if r.status_code == 404:
                break
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            found = 0
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if href.startswith("/writeup/") and href.count("/") == 2:
                    urls.add(BASE + href)
                    found += 1
            if found == 0:
                break
        except Exception:
            pass
        time.sleep(delay)
    return list(urls)

def scrape_writeup(url):
    try:
        r = safe_get(url, timeout=15)
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        title_el = soup.select_one("h2")
        title = title_el.get_text(strip=True) if title_el else ""
        cat_el = soup.select_one("span.label")
        category = cat_el.get_text(strip=True) if cat_el else ""
        content_el = (soup.select_one("div.writeup-content") or
                      soup.select_one("article") or
                      soup.select_one("div#content-wrap"))
        if not content_el:
            return None
        code_blocks = [c.get_text() for c in content_el.select("pre, code")]
        text = content_el.get_text(separator="\n", strip=True)
        if len(text) < 100:
            return None
        return {"source": "ctftime", "url": url, "title": title,
                "category": category, "code_blocks": code_blocks[:10],
                "text": text[:8000]}
    except Exception:
        return None

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["ctftime"]
    if not c.get("enabled", True):
        print("[ctftime] Disabled."); return
    delay = c.get("delay_seconds", 0.8)
    cp = load_checkpoint(checkpoint_file)
    done_urls = set(cp.get("ctftime_done", []))
    all_urls = get_writeup_urls(c.get("pages", 100), delay)
    remaining = [u for u in all_urls if u not in done_urls]
    print(f"[ctftime] {len(all_urls)} URLs, {len(remaining)} remaining.")
    batch = []
    for url in tqdm(remaining, desc="CTFtime"):
        doc = scrape_writeup(url)
        if doc:
            batch.append(doc)
        done_urls.add(url)
        if len(batch) >= 200:
            append_jsonl(raw_file, batch)
            cp["ctftime_done"] = list(done_urls)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
    cp["ctftime_done"] = list(done_urls)
    save_checkpoint(checkpoint_file, cp)
    print(f"[ctftime] Done. {len(done_urls)}")
