import time, feedparser, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get


def extract_text(html):
    return BeautifulSoup(html or "", "html.parser").get_text(separator="\n", strip=True)

def get_entry_text(entry):
    if hasattr(entry, "content") and entry.content:
        for c in entry.content:
            val = c.get("value", "")
            if val and len(val) > 100:
                return extract_text(val)
    if hasattr(entry, "summary") and entry.summary:
        t = extract_text(entry.summary)
        if len(t) > 100:
            return t
    return ""

def fetch_full_article(url):
    try:
        r = safe_get(url, timeout=15)
        if r.status_code != 200:
            return ""
        for sel in ["article", "main", ".post-content", ".entry-content", "#content"]:
            el = BeautifulSoup(r.text, "html.parser").select_one(sel)
            if el:
                t = el.get_text(separator="\n", strip=True)
                if len(t) > 300:
                    return t
    except Exception:
        pass
    return ""

def parse_feed(feed_url, delay):
    try:
        feed = feedparser.parse(feed_url)
    except Exception:
        return []
    source_name = getattr(getattr(feed, "feed", None), "title", None) or feed_url
    articles = []
    for entry in feed.entries:
        url = entry.get("link", "")
        title = entry.get("title", "")
        date = entry.get("published", entry.get("updated", ""))
        text = get_entry_text(entry)
        if len(text) < 400 and url:
            text = fetch_full_article(url)
            time.sleep(delay)
        if len(text) > 300:
            articles.append({"source": "rss", "feed": source_name,
                              "url": url, "title": title, "date": date,
                              "text": text[:6000]})
    return articles

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["rss_feeds"]
    if not c.get("enabled", True):
        print("[rss] Disabled."); return
    feeds = c.get("feeds", [])
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    done_feeds = set(cp.get("rss_done_feeds", []))
    done_urls = set(cp.get("rss_done_urls", []))
    remaining = [f for f in feeds if f not in done_feeds]
    print(f"[rss] Processing {len(remaining)} feeds...")
    for feed_url in tqdm(remaining, desc="RSS feeds"):
        articles = parse_feed(feed_url, delay)
        new = [a for a in articles if a["url"] not in done_urls]
        if new:
            append_jsonl(raw_file, new)
            for a in new:
                done_urls.add(a["url"])
        done_feeds.add(feed_url)
        cp["rss_done_feeds"] = list(done_feeds)
        cp["rss_done_urls"] = list(done_urls)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)
    print(f"[rss] Done. {len(done_urls)}")
