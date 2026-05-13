"""
Academic papers — full text scraper:
  - arXiv: downloads full PDFs not just abstracts
  - IEEE S&P: public proceedings PDFs
  - USENIX Security: open access PDFs
  - ACM CCS: open access PDFs
  - NDSS: fully open access PDFs
"""
import io
from datetime import datetime
import os
import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


def extract_pdf_text(content_bytes, max_pages=40):
    """Extract text from PDF bytes, robust to malformed pages."""
    try:
        import pdfplumber
        import logging
        # Silence noisy pdfminer warnings about font metadata, encoding etc.
        logging.getLogger("pdfminer").setLevel(logging.ERROR)
        logging.getLogger("pdfplumber").setLevel(logging.ERROR)
    except ImportError:
        return ""

    parts = []
    try:
        with pdfplumber.open(io.BytesIO(content_bytes)) as pdf:
            for page in pdf.pages[:max_pages]:
                # Per-page try/except — one malformed page won't kill the rest
                try:
                    t = page.extract_text()
                    if t:
                        parts.append(t)
                except Exception:
                    continue
    except Exception:
        return ""

    text = "\n".join(parts)
    text = "\n".join(line for line in text.split("\n") if len(line.strip()) > 2)
    return text


# ================================================================
# arXiv — full PDF text
# ================================================================

ARXIV_API = "http://export.arxiv.org/api/query"

# arXiv's official rate limit guidance is "no more than 1 request per 3
# seconds." In practice their gateway also gates aggressively when it sees
# a generic python-requests User-Agent, so we send a descriptive one and
# back off heavily on 429.
ARXIV_HEADERS = {
    "User-Agent": "secdata-scrapers/1.0 (https://github.com/yourdeardaniel/secdata-scrapers; research)",
    "Accept":     "application/atom+xml",
}


def search_arxiv(query, start, max_results, max_attempts=5):
    """
    Query the arXiv API. Handles 429 rate limits with exponential backoff
    and 503 transient errors with linear backoff. Returns XML text or None.
    """
    params = {
        "search_query": f"cat:cs.CR AND ({query})",
        "start":        start,
        "max_results":  max_results,
        "sortBy":       "submittedDate",
        "sortOrder":    "descending",
    }
    backoff = 30  # seconds, doubles on each 429
    for attempt in range(1, max_attempts + 1):
        try:
            r = SESSION.get(ARXIV_API, params=params,
                            headers=ARXIV_HEADERS, timeout=30)
            if r.status_code == 429:
                print(f"[arxiv_full] 429 (attempt {attempt}/{max_attempts}), "
                      f"sleeping {backoff}s...")
                time.sleep(backoff)
                backoff = min(backoff * 2, 600)  # cap at 10 minutes
                continue
            if r.status_code == 503:
                print(f"[arxiv_full] 503 transient, sleeping 60s...")
                time.sleep(60)
                continue
            r.raise_for_status()
            return r.text
        except requests.exceptions.RequestException as e:
            print(f"[arxiv_full] Request failed (attempt {attempt}): {e}")
            time.sleep(10 * attempt)
        except Exception as e:
            print(f"[arxiv_full] Unexpected error: {e}")
            return None
    print(f"[arxiv_full] Giving up after {max_attempts} attempts.")
    return None


def parse_arxiv_entries(xml_text):
    soup    = BeautifulSoup(xml_text, "html.parser")
    entries = soup.find_all("entry")
    results = []

    for entry in entries:
        id_el     = entry.find("id")
        arxiv_id  = id_el.text.strip() if id_el else ""

        title_el  = entry.find("title")
        title     = title_el.text.strip().replace("\n", " ") if title_el else ""

        summary_el= entry.find("summary")
        abstract  = summary_el.text.strip() if summary_el else ""

        authors   = [a.find("name").text
                     for a in entry.find_all("author") if a.find("name")]

        pub_el    = entry.find("published")
        published = pub_el.text[:10] if pub_el else ""

        cats      = [c.get("term", "") for c in entry.find_all("category")]

        # build PDF URL from arXiv ID
        # arXiv IDs look like http://arxiv.org/abs/2301.12345v1
        paper_id  = arxiv_id.split("/abs/")[-1].split("v")[0]
        pdf_url   = f"https://arxiv.org/pdf/{paper_id}.pdf"

        results.append({
            "arxiv_id":  arxiv_id,
            "paper_id":  paper_id,
            "title":     title,
            "abstract":  abstract,
            "authors":   authors,
            "published": published,
            "cats":      cats,
            "pdf_url":   pdf_url,
        })

    return results


def run_arxiv_fulltext(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["arxiv_fulltext"]
    if not c.get("enabled", True):
        print("[arxiv_full] Disabled.")
        return

    # arXiv strongly recommends at least 3 seconds between calls; enforce it
    # regardless of what the config says.
    max_papers   = c.get("max_papers", 15000)
    delay = max(c.get("delay_seconds", 3.0), 3.0)
    download_pdf = c.get("download_pdfs", True)
    terms        = c.get("search_terms", [])
    per_term     = max(1, max_papers // max(len(terms), 1))

    cp         = load_checkpoint(checkpoint_file)
    done_ids   = set(cp.get("arxiv_full_done", []))
    done_terms = set(cp.get("arxiv_full_terms", []))

    remaining = [t for t in terms if t not in done_terms]
    print(f"[arxiv_full] {per_term} papers per term, {len(remaining)} terms.")

    for term in remaining:
        start = 0
        count = 0
        consecutive_failures = 0
        print(f"[arxiv_full] '{term}'")

        while count < per_term:
            xml = search_arxiv(term, start, 50)
            if not xml:
                consecutive_failures += 1
                if consecutive_failures >= 2:
                    # API is unhappy; bail on this term but DON'T mark done,
                    # so a future run can retry it.
                    print(f"[arxiv_full] '{term}' aborted after repeated failures.")
                    break
                time.sleep(30)
                continue
            consecutive_failures = 0

            entries = parse_arxiv_entries(xml)
            if not entries:
                break

            for entry in entries:
                if entry["arxiv_id"] in done_ids:
                    continue

                text_parts = [
                    f"Title: {entry['title']}",
                    f"Authors: {', '.join(entry['authors'][:5])}",
                    f"Published: {entry['published']}",
                    f"Categories: {', '.join(entry['cats'])}",
                    f"\nAbstract:\n{entry['abstract']}",
                ]

                # download and extract full PDF text
                if download_pdf and entry["pdf_url"]:
                    r = safe_get(entry["pdf_url"], timeout=60, stream=True)
                    if r:
                        pdf_text = extract_pdf_text(r.content)
                        if pdf_text and len(pdf_text) > 500:
                            # remove abstract (already have it) and
                            # skip reference section at the end
                            lines = pdf_text.split("\n")
                            # trim reference section
                            for i, line in enumerate(lines):
                                if line.strip().lower() in ("references",
                                                             "bibliography",
                                                             "acknowledgments",
                                                             "acknowledgements"):
                                    lines = lines[:i]
                                    break
                            full_text = "\n".join(lines)
                            text_parts.append(f"\nFull Paper:\n{full_text[:12000]}")
                    time.sleep(delay)

                doc = {
                    "source":    "arxiv_fulltext",
                    "id":        entry["arxiv_id"],
                    "url":       entry["arxiv_id"],
                    "title":     entry["title"],
                    "published": entry["published"],
                    "text":      "\n".join(text_parts),
                }
                append_jsonl(raw_file, [doc])
                done_ids.add(entry["arxiv_id"])
                count += 1

            if len(entries) < 50:
                break
            start += 50
            time.sleep(delay)

        # Only mark term complete if we actually got something OR processed
        # all available papers (empty result). Failed terms can retry later.
        if count > 0 or consecutive_failures == 0:
            done_terms.add(term)
        cp["arxiv_full_done"]  = list(done_ids)
        cp["arxiv_full_terms"] = list(done_terms)
        save_checkpoint(checkpoint_file, cp)
        print(f"[arxiv_full] '{term}': {count} papers.")
        time.sleep(delay)

    print(f"[arxiv_full] Done. Total: {len(done_ids)}")


# ================================================================
# USENIX Security — open access proceedings
# ================================================================

def run_usenix(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["usenix_security"]
    if not c.get("enabled", True):
        print("[usenix] Disabled.")
        return

    delay     = c.get("delay_seconds", 2.0)
    start_yr  = c.get("start_year", 2010)
    end_yr    = c.get("end_year", datetime.now().year)

    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("usenix_done", []))

    for year in range(start_yr, end_yr + 1):
        year_key = str(year)
        if year_key in cp.get("usenix_done_years", []):
            continue

        print(f"[usenix] Year {year}...")
        # USENIX proceedings index
        index_urls = [
            f"https://www.usenix.org/conference/usenixsecurity{str(year)[2:]}/technical-sessions",
            f"https://www.usenix.org/conference/usenixsecurity{year}/technical-sessions",
        ]

        paper_links = []
        for iurl in index_urls:
            r = safe_get(iurl)
            if not r:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if "/presentation/" in href or "/paper/" in href:
                    full = ("https://www.usenix.org" + href
                            if href.startswith("/") else href)
                    if full not in paper_links:
                        paper_links.append(full)
            time.sleep(delay)

        year_count = 0
        for paper_url in tqdm(paper_links, desc=f"  USENIX {year}"):
            if paper_url in done_ids:
                continue

            r = safe_get(paper_url)
            if not r:
                done_ids.add(paper_url)
                continue

            soup    = BeautifulSoup(r.text, "html.parser")
            title_e = soup.select_one("h1, .paper-title")
            title   = title_e.get_text(strip=True) if title_e else ""

            abstract_e = soup.select_one(".field-name-body, .abstract, #abstract")
            abstract   = abstract_e.get_text("\n", strip=True) if abstract_e else ""

            # find PDF link
            pdf_url = None
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if href.lower().endswith(".pdf"):
                    pdf_url = ("https://www.usenix.org" + href
                               if href.startswith("/") else href)
                    break

            pdf_text = ""
            if pdf_url:
                pr = safe_get(pdf_url, timeout=60)
                if pr:
                    pdf_text = extract_pdf_text(pr.content)
                time.sleep(delay)

            if not abstract and not pdf_text:
                done_ids.add(paper_url)
                continue

            text_parts = [f"USENIX Security {year}: {title}"]
            if abstract:
                text_parts.append(f"\nAbstract:\n{abstract}")
            if pdf_text:
                # trim references
                lines = pdf_text.split("\n")
                for i, line in enumerate(lines):
                    if line.strip().lower() in ("references", "bibliography"):
                        lines = lines[:i]
                        break
                text_parts.append(f"\nFull Paper:\n{chr(10).join(lines)[:12000]}")

            append_jsonl(raw_file, [{
                "source":    "usenix_security",
                "year":      year,
                "title":     title,
                "url":       paper_url,
                "text":      "\n".join(text_parts),
            }])
            done_ids.add(paper_url)
            year_count += 1
            time.sleep(delay)

        done_yrs = cp.get("usenix_done_years", [])
        done_yrs.append(year_key)
        cp["usenix_done_years"] = done_yrs
        cp["usenix_done"]       = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        print(f"[usenix] Year {year}: {year_count} papers.")

    print("[usenix] Done.")


# ================================================================
# NDSS — fully open access
# ================================================================

def run_ndss(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["ndss"]
    if not c.get("enabled", True):
        print("[ndss] Disabled.")
        return

    delay    = c.get("delay_seconds", 2.0)
    start_yr = c.get("start_year", 2010)
    end_yr   = c.get("end_year", datetime.now().year)

    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("ndss_done", []))

    for year in range(start_yr, end_yr + 1):
        if str(year) in cp.get("ndss_done_years", []):
            continue

        print(f"[ndss] Year {year}...")
        index_url = f"https://www.ndss-symposium.org/ndss{year}/"
        r = safe_get(index_url)
        if not r:
            continue

        soup       = BeautifulSoup(r.text, "html.parser")
        paper_urls = []
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "ndss-symposium.org/ndss-paper/" in href:
                if href not in paper_urls:
                    paper_urls.append(href)

        year_count = 0
        for purl in tqdm(paper_urls, desc=f"  NDSS {year}"):
            if purl in done_ids:
                continue

            r2 = safe_get(purl)
            if not r2:
                done_ids.add(purl)
                continue

            soup2    = BeautifulSoup(r2.text, "html.parser")
            title_e  = soup2.select_one("h1, .entry-title")
            title    = title_e.get_text(strip=True) if title_e else ""
            abs_e    = soup2.select_one(".abstract, .entry-content p")
            abstract = abs_e.get_text("\n", strip=True) if abs_e else ""

            pdf_url = None
            for a in soup2.select("a[href]"):
                if a.get("href","").lower().endswith(".pdf"):
                    pdf_url = a["href"]
                    break

            pdf_text = ""
            if pdf_url:
                pr = safe_get(pdf_url, timeout=60)
                if pr:
                    pdf_text = extract_pdf_text(pr.content)
                time.sleep(delay)

            if not abstract and not pdf_text:
                done_ids.add(purl)
                continue

            parts = [f"NDSS {year}: {title}"]
            if abstract:
                parts.append(f"\nAbstract:\n{abstract}")
            if pdf_text:
                lines = pdf_text.split("\n")
                for i, line in enumerate(lines):
                    if line.strip().lower() in ("references", "bibliography"):
                        lines = lines[:i]
                        break
                parts.append(f"\nFull Paper:\n{chr(10).join(lines)[:12000]}")

            append_jsonl(raw_file, [{
                "source": "ndss", "year": year, "title": title,
                "url": purl, "text": "\n".join(parts),
            }])
            done_ids.add(purl)
            year_count += 1
            time.sleep(delay)

        yrs = cp.get("ndss_done_years", [])
        yrs.append(str(year))
        cp["ndss_done_years"] = yrs
        cp["ndss_done"]       = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        print(f"[ndss] Year {year}: {year_count} papers.")

    print("[ndss] Done.")


# ================================================================
# IEEE S&P — open access papers
# ================================================================

def run_ieee_sp(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["ieee_sp"]
    if not c.get("enabled", True):
        print("[ieee_sp] Disabled.")
        return

    delay    = c.get("delay_seconds", 3.0)
    start_yr = c.get("start_year", 2015)
    end_yr   = c.get("end_year", datetime.now().year)

    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("ieee_sp_done", []))

    for year in range(start_yr, end_yr + 1):
        if str(year) in cp.get("ieee_sp_done_years", []):
            continue

        print(f"[ieee_sp] Year {year}...")
        # IEEE S&P papers are on computer.org/csdl
        # Many are also on authors' personal pages or arXiv — we search both
        search_url = (
            f"https://www.computer.org/csdl/proceedings-article/sp/{year}"
        )
        r = safe_get(search_url)
        year_count = 0

        if r:
            soup = BeautifulSoup(r.text, "html.parser")
            paper_links = []
            for a in soup.select("a[href]"):
                href = a.get("href","")
                if f"/sp/{year}/" in href and href not in paper_links:
                    full = ("https://www.computer.org" + href
                            if href.startswith("/") else href)
                    paper_links.append(full)

            for purl in tqdm(paper_links[:200], desc=f"  IEEE S&P {year}"):
                if purl in done_ids:
                    continue
                r2 = safe_get(purl)
                if not r2:
                    done_ids.add(purl)
                    continue

                soup2   = BeautifulSoup(r2.text, "html.parser")
                title_e = soup2.select_one("h1, .title")
                title   = title_e.get_text(strip=True) if title_e else ""
                abs_e   = soup2.select_one(".abstract, [itemprop='description']")
                abstract= abs_e.get_text("\n",strip=True) if abs_e else ""

                if len(abstract) > 100:
                    append_jsonl(raw_file, [{
                        "source":"ieee_sp","year":year,"title":title,
                        "url":purl,
                        "text":f"IEEE S&P {year}: {title}\n\nAbstract:\n{abstract}",
                    }])
                    year_count += 1

                done_ids.add(purl)
                time.sleep(delay)

        yrs = cp.get("ieee_sp_done_years", [])
        yrs.append(str(year))
        cp["ieee_sp_done_years"] = yrs
        cp["ieee_sp_done"]       = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        print(f"[ieee_sp] Year {year}: {year_count} papers.")
        time.sleep(delay)

    print("[ieee_sp] Done.")


# ================================================================
# ACM CCS
# ================================================================

def run_acm_ccs(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["acm_ccs"]
    if not c.get("enabled", True):
        print("[acm_ccs] Disabled.")
        return

    delay    = c.get("delay_seconds", 3.0)
    start_yr = c.get("start_year", 2015)
    end_yr   = c.get("end_year", datetime.now().year)

    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("acm_ccs_done", []))

    for year in range(start_yr, end_yr + 1):
        if str(year) in cp.get("acm_ccs_done_years", []):
            continue

        print(f"[acm_ccs] Year {year}...")
        # ACM DL proceedings page for CCS
        proc_url = f"https://dl.acm.org/doi/proceedings/10.1145/{_ccs_doi(year)}"
        r = safe_get(proc_url)
        year_count = 0

        if r:
            soup  = BeautifulSoup(r.text, "html.parser")
            links = []
            for a in soup.select("a[href]"):
                href = a.get("href","")
                if "/doi/10.1145/" in href and "/proceedings" not in href:
                    full = ("https://dl.acm.org" + href
                            if href.startswith("/") else href)
                    if full not in links:
                        links.append(full)

            for purl in tqdm(links[:200], desc=f"  ACM CCS {year}"):
                if purl in done_ids:
                    continue
                r2 = safe_get(purl)
                if not r2:
                    done_ids.add(purl)
                    continue

                soup2   = BeautifulSoup(r2.text, "html.parser")
                title_e = soup2.select_one("h1.citation__title, .title")
                title   = title_e.get_text(strip=True) if title_e else ""
                abs_e   = soup2.select_one(".abstractSection p, .abstract")
                abstract= abs_e.get_text("\n",strip=True) if abs_e else ""

                if len(abstract) > 100:
                    append_jsonl(raw_file, [{
                        "source":"acm_ccs","year":year,"title":title,
                        "url":purl,
                        "text":f"ACM CCS {year}: {title}\n\nAbstract:\n{abstract}",
                    }])
                    year_count += 1

                done_ids.add(purl)
                time.sleep(delay)

        yrs = cp.get("acm_ccs_done_years", [])
        yrs.append(str(year))
        cp["acm_ccs_done_years"] = yrs
        cp["acm_ccs_done"]       = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        print(f"[acm_ccs] Year {year}: {year_count} papers.")
        time.sleep(delay)

    print("[acm_ccs] Done.")


def _ccs_doi(year):
    """Map year to ACM CCS proceedings DOI suffix."""
    doi_map = {
        2015: "2810103", 2016: "2976749", 2017: "3133956",
        2018: "3243734", 2019: "3319535", 2020: "3372297",
        2021: "3460120", 2022: "3548606", 2023: "3576915",
        2024: "3658644",
    }
    return doi_map.get(year, str(year))
