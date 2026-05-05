import time, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

ARXIV_API = "http://export.arxiv.org/api/query"

def search(query, start, max_results):
    params = {"search_query": f"cat:cs.CR AND ({query})",
              "start": start, "max_results": max_results,
              "sortBy": "submittedDate", "sortOrder": "descending"}
    for attempt in range(3):
        try:
            r = safe_get(ARXIV_API, params=params, timeout=30)
            r.raise_for_status()
            return r.text
        except Exception:
            time.sleep(10)
    return None

def parse_xml(xml_text):
    soup = BeautifulSoup(xml_text, "html.parser")
    results = []
    for entry in soup.find_all("entry"):
        id_el = entry.find("id")
        arxiv_id = id_el.text.strip() if id_el else ""
        title_el = entry.find("title")
        title = title_el.text.strip().replace("\n", " ") if title_el else ""
        summary_el = entry.find("summary")
        summary = summary_el.text.strip() if summary_el else ""
        if len(summary) < 80:
            continue
        authors = [a.find("name").text for a in entry.find_all("author") if a.find("name")]
        pub_el = entry.find("published")
        published = pub_el.text[:10] if pub_el else ""
        cats = [c.get("term", "") for c in entry.find_all("category")]
        results.append({"arxiv_id": arxiv_id, "title": title, "summary": summary,
                        "authors": authors, "published": published, "cats": cats})
    return results

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["arxiv"]
    if not c.get("enabled", True):
        print("[arxiv] Disabled."); return
    max_papers = c.get("max_papers", 5000)
    delay = c.get("delay_seconds", 3.0)
    terms = c.get("search_terms", [])
    per_term = max(1, max_papers // max(len(terms), 1))
    cp = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("arxiv_done_ids", []))
    done_terms = set(cp.get("arxiv_done_terms", []))
    for term in [t for t in terms if t not in done_terms]:
        start = count = 0
        print(f"[arxiv] '{term}'")
        while count < per_term:
            xml = search(term, start, 50)
            if not xml:
                break
            entries = parse_xml(xml)
            if not entries:
                break
            new = [e for e in entries if e["arxiv_id"] not in done_ids]
            if new:
                docs = [{"source": "arxiv", "id": e["arxiv_id"],
                         "url": e["arxiv_id"], "title": e["title"],
                         "published": e["published"],
                         "text": "\n".join([
                             f"Title: {e['title']}",
                             f"Authors: {', '.join(e['authors'][:5])}",
                             f"Published: {e['published']}",
                             f"Categories: {', '.join(e['cats'])}",
                             f"\nAbstract:\n{e['summary']}",
                         ])} for e in new]
                append_jsonl(raw_file, docs)
                for e in new:
                    done_ids.add(e["arxiv_id"])
                count += len(new)
            if len(entries) < 50:
                break
            start += 50
            time.sleep(delay)
        done_terms.add(term)
        cp["arxiv_done_ids"] = list(done_ids)
        cp["arxiv_done_terms"] = list(done_terms)
        save_checkpoint(checkpoint_file, cp)
        print(f"[arxiv] '{term}': {count}")
        time.sleep(delay)
    print(f"[arxiv] Done. {len(done_ids)}")
