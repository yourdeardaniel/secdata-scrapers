import io, os, time, requests, xml.etree.ElementTree as ET
from datetime import datetime
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})

def extract_pdf_text(content_bytes, max_pages=30):
    try:
        import pdfplumber
        parts = []
        with pdfplumber.open(io.BytesIO(content_bytes)) as pdf:
            for page in pdf.pages[:max_pages]:
                t = page.extract_text()
                if t:
                    parts.append(t)
        return "\n".join(parts)
    except Exception:
        return ""

# ── Packetstorm ──────────────────────────────────────────────────
PACKETSTORM_BASE = "https://packetstormsecurity.com"
PACKETSTORM_CATS = {"advisories": "/files/tags/advisory/",
                    "exploits": "/files/tags/exploit/",
                    "whitepapers": "/files/tags/paper/"}

def run_packetstorm(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["packetstorm"]
    if not c.get("enabled", True): print("[packetstorm] Disabled."); return
    max_pages = c.get("max_pages", 200)
    categories = c.get("categories", ["advisories","exploits","whitepapers"])
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    done_urls = set(cp.get("packetstorm_done", []))
    for cat in categories:
        cat_path = PACKETSTORM_CATS.get(cat, "")
        if not cat_path: continue
        item_urls = []
        for page in tqdm(range(1, max_pages + 1), desc=f"  PS listing {cat}"):
            url = (PACKETSTORM_BASE + cat_path if page == 1
                   else f"{PACKETSTORM_BASE}{cat_path}page{page}/")
            r = safe_get(url)
            if not r: break
            soup = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("dl dt a[href]"):
                href = a.get("href", "")
                if href.startswith("/files/") and href.endswith("/"):
                    full = PACKETSTORM_BASE + href
                    if full not in item_urls:
                        item_urls.append(full); found = True
            if not found: break
            time.sleep(delay)
        batch = []
        for url in tqdm([u for u in item_urls if u not in done_urls], desc=f"  PS {cat}"):
            r = safe_get(url)
            if not r: done_urls.add(url); continue
            soup = BeautifulSoup(r.text, "html.parser")
            title_e = soup.select_one("h1") or soup.select_one("h2")
            title = title_e.get_text(strip=True) if title_e else ""
            content_e = (soup.select_one("div#main") or soup.select_one("article") or soup.select_one(".detail"))
            text = content_e.get_text("\n", strip=True) if content_e else ""
            if len(text) > 100:
                batch.append({"source": "packetstorm", "category": cat, "title": title,
                               "url": url, "text": f"Packetstorm {cat.title()}: {title}\n\n{text[:6000]}"})
            done_urls.add(url)
            if len(batch) >= 100:
                append_jsonl(raw_file, batch)
                cp["packetstorm_done"] = list(done_urls)
                save_checkpoint(checkpoint_file, cp)
                batch = []
            time.sleep(delay)
        if batch:
            append_jsonl(raw_file, batch)
            cp["packetstorm_done"] = list(done_urls)
            save_checkpoint(checkpoint_file, cp)
    print(f"[packetstorm] Done. {len(done_urls)}")

# ── Phrack ───────────────────────────────────────────────────────
def run_phrack(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["phrack"]
    if not c.get("enabled", True): print("[phrack] Disabled."); return
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    done_urls = set(cp.get("phrack_done", []))
    done_issues = set(cp.get("phrack_done_issues", []))
    BASE = "https://phrack.org"
    for issue in range(1, 71):
        if str(issue) in done_issues: continue
        r = safe_get(f"{BASE}/issues/{issue}/")
        if not r: done_issues.add(str(issue)); continue
        soup = BeautifulSoup(r.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if f"/issues/{issue}/" in href and href != f"/issues/{issue}/":
                full = BASE + href if href.startswith("/") else href
                if full not in links: links.append(full)
        batch = []
        for aurl in links:
            if aurl in done_urls: continue
            ar = safe_get(aurl)
            if not ar: done_urls.add(aurl); continue
            asoup = BeautifulSoup(ar.text, "html.parser")
            pre = asoup.find("pre")
            text = pre.get_text() if pre else asoup.get_text("\n", strip=True)
            title_e = asoup.find("title")
            title = title_e.get_text(strip=True) if title_e else ""
            if len(text) > 200:
                batch.append({"source": "phrack", "issue": str(issue),
                               "title": title, "url": aurl,
                               "text": f"Phrack Issue {issue}: {title}\n\n{text[:6000]}"})
            done_urls.add(aurl)
            time.sleep(delay)
        if batch: append_jsonl(raw_file, batch)
        done_issues.add(str(issue))
        cp["phrack_done"] = list(done_urls)
        cp["phrack_done_issues"] = list(done_issues)
        save_checkpoint(checkpoint_file, cp)
    print(f"[phrack] Done. {len(done_urls)}")

# ── SANS ISC ─────────────────────────────────────────────────────
def run_sans_isc(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["sans_isc"]
    if not c.get("enabled", True): print("[sans_isc] Disabled."); return
    max_pages = c.get("max_pages", 200)
    delay = c.get("delay_seconds", 1.0)
    BASE = "https://isc.sans.edu"
    cp = load_checkpoint(checkpoint_file)
    done_urls = set(cp.get("sans_isc_done", []))
    diary_urls = []
    for page in tqdm(range(1, max_pages + 1), desc="SANS ISC listing"):
        url = f"{BASE}/diary.html" if page == 1 else f"{BASE}/diary.html?page={page}"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/diary/" in href:
                full = BASE + href if href.startswith("/") else href
                if full not in diary_urls:
                    diary_urls.append(full); found = True
        if not found: break
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in diary_urls if u not in done_urls], desc="SANS ISC"):
        r = safe_get(url)
        if not r: done_urls.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, .diarytitle")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("div.diary, div#diarydetail, article")
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 150:
            batch.append({"source": "sans_isc", "title": title, "url": url,
                           "text": f"SANS ISC Diary: {title}\n\n{text[:5000]}"})
        done_urls.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["sans_isc_done"] = list(done_urls)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["sans_isc_done"] = list(done_urls)
        save_checkpoint(checkpoint_file, cp)
    print(f"[sans_isc] Done. {len(done_urls)}")

# ── MITRE CAPEC ──────────────────────────────────────────────────
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

def run_mitre_capec(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["mitre_capec"]
    if not c.get("enabled", True): print("[capec] Disabled."); return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("capec_done"): print("[capec] Already done."); return
    print("[capec] Downloading CAPEC XML...")
    r = safe_get(CAPEC_URL, timeout=60)
    if not r: print("[capec] Download failed."); return
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError as e:
        print(f"[capec] XML parse error: {e}"); return
    ns_match = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
    ns = {"capec": ns_match} if ns_match else {}
    def find(el, tag):
        return el.findall(f"capec:{tag}", ns) if ns else el.findall(tag)
    def text_of(el):
        return " ".join(el.itertext()).strip() if el is not None else ""
    patterns = root.findall(".//capec:Attack_Pattern", ns) or root.findall(".//Attack_Pattern")
    results = []
    for ap in patterns:
        capec_id = ap.get("ID","")
        name = ap.get("Name","")
        if ap.get("Status","") in ("Deprecated","Obsolete"): continue
        desc_els = ap.findall("capec:Description", ns) or ap.findall("Description")
        desc = text_of(desc_els[0]) if desc_els else ""
        if not desc: continue
        steps = [text_of(s) for el in (ap.findall(".//capec:Attack_Step", ns) or ap.findall(".//Attack_Step"))
                 for s in [el.find("capec:Step_Description", ns) or el.find("Step_Description")] if s is not None]
        mits = [text_of(m) for m in (ap.findall(".//capec:Mitigation", ns) or ap.findall(".//Mitigation"))]
        cwes = [el.get("CWE_ID","") for el in (ap.findall(".//capec:Related_Weakness", ns) or ap.findall(".//Related_Weakness"))]
        parts = [f"MITRE CAPEC-{capec_id}: {name}", f"\nDescription:\n{desc}"]
        if steps: parts.append("\nAttack steps:\n" + "\n".join(f"  {i+1}. {s}" for i,s in enumerate(steps[:5])))
        if mits: parts.append("\nMitigations:\n" + "\n".join(f"  - {m[:200]}" for m in mits[:3]))
        if cwes: parts.append(f"\nRelated CWEs: {', '.join(cwes[:10])}")
        results.append({"source": "capec", "id": f"CAPEC-{capec_id}", "name": name,
                         "url": f"https://capec.mitre.org/data/definitions/{capec_id}.html",
                         "text": "\n".join(parts)})
    if results: append_jsonl(raw_file, results)
    cp["capec_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[capec] Done. {len(results)}")

# ── Malpedia ─────────────────────────────────────────────────────
def run_malpedia(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["malpedia"]
    if not c.get("enabled", True): print("[malpedia] Disabled."); return
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("malpedia_done", []))
    try:
        r = SESSION.get("https://malpedia.caad.fkie.fraunhofer.de/api/list/families", timeout=20)
        r.raise_for_status()
        families = r.json()
    except Exception as e:
        print(f"[malpedia] Failed: {e}"); return
    batch = []
    for fkey in tqdm([f for f in families if f not in done], desc="Malpedia"):
        try:
            r2 = SESSION.get(f"https://malpedia.caad.fkie.fraunhofer.de/api/get/family/{fkey}", timeout=15)
            r2.raise_for_status()
            data = r2.json()
            name = data.get("common_name", fkey) or fkey
            desc = data.get("description", "") or ""
            aliases = data.get("alt_names", []) or []
            cats = data.get("categories", []) or []
            actors = [a.get("actor","") for a in (data.get("attribution",[]) or []) if a.get("actor")]
            refs = data.get("urls", []) or []
            if len(desc) < 40:
                done.add(fkey); continue
            parts = [f"Malware Family: {name}"]
            if aliases: parts.append(f"Aliases: {', '.join(aliases[:10])}")
            if cats: parts.append(f"Categories: {', '.join(cats)}")
            if actors: parts.append(f"Threat actors: {', '.join(actors[:5])}")
            parts.append(f"\nDescription:\n{desc}")
            if refs: parts.append(f"\nReferences: {'; '.join(refs[:5])}")
            batch.append({"source": "malpedia", "family": fkey, "name": name,
                           "url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{fkey}",
                           "text": "\n".join(parts)})
        except Exception:
            pass
        done.add(fkey)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["malpedia_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["malpedia_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[malpedia] Done. {len(done)}")

# ── CISA ─────────────────────────────────────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def run_cisa(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["cisa"]
    if not c.get("enabled", True): print("[cisa] Disabled."); return
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    if c.get("scrape_kev", True) and not cp.get("cisa_kev_done"):
        print("[cisa] Fetching KEV catalog...")
        r = safe_get(KEV_URL, timeout=30)
        if r:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            batch = []
            for v in vulns:
                cve = v.get("cveID","")
                desc = v.get("shortDescription","")
                if not desc: continue
                parts = [f"CISA Known Exploited Vulnerability: {cve}",
                         f"Vulnerability: {v.get('vulnerabilityName','')}",
                         f"Vendor/Product: {v.get('vendorProject','')} — {v.get('product','')}",
                         f"Date added: {v.get('dateAdded','')}",
                         f"\nDescription:\n{desc}",
                         f"\nRequired action: {v.get('requiredAction','')}"]
                batch.append({"source": "cisa_kev", "cve_id": cve,
                               "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                               "text": "\n".join(parts)})
            if batch: append_jsonl(raw_file, batch)
            print(f"[cisa] KEV: {len(batch)}")
        cp["cisa_kev_done"] = True
        save_checkpoint(checkpoint_file, cp)
    if c.get("scrape_advisories", True):
        done_urls = set(cp.get("cisa_adv_done", []))
        adv_urls = []
        for page in range(0, 100):
            r = safe_get(f"https://www.cisa.gov/news-events/cybersecurity-advisories?page={page}")
            if not r: break
            soup = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href","")
                if "/news-events/cybersecurity-advisories/" in href and len(href) > 45:
                    full = "https://www.cisa.gov" + href if href.startswith("/") else href
                    if full not in adv_urls:
                        adv_urls.append(full); found = True
            if not found: break
            time.sleep(delay)
        batch = []
        for url in tqdm([u for u in adv_urls if u not in done_urls], desc="CISA advisories"):
            r = safe_get(url)
            if not r: done_urls.add(url); continue
            soup = BeautifulSoup(r.text, "html.parser")
            title_e = soup.select_one("h1")
            title = title_e.get_text(strip=True) if title_e else ""
            body_e = soup.select_one("article, main, .field--type-text-long")
            text = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                batch.append({"source": "cisa_advisory", "title": title, "url": url,
                               "text": f"CISA Advisory: {title}\n\n{text[:6000]}"})
            done_urls.add(url)
            if len(batch) >= 50:
                append_jsonl(raw_file, batch)
                cp["cisa_adv_done"] = list(done_urls)
                save_checkpoint(checkpoint_file, cp)
                batch = []
            time.sleep(delay)
        if batch:
            append_jsonl(raw_file, batch)
            cp["cisa_adv_done"] = list(done_urls)
            save_checkpoint(checkpoint_file, cp)
    print("[cisa] Done.")

# ── MSRC ─────────────────────────────────────────────────────────
def run_msrc(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["msrc"]
    if not c.get("enabled", True): print("[msrc] Disabled."); return
    start_yr = c.get("start_year", 2016)
    end_yr   = c.get("end_year", datetime.now().year)
    delay    = c.get("delay_seconds", 1.0)
    BASE     = "https://api.msrc.microsoft.com/cvrf/v3.0"
    # MSRC's CVRF API uses three-letter month abbreviations in update IDs
    # (e.g. "2024-Jan"), not zero-padded numbers ("2024-01"). Hitting the
    # numeric form returns 404 for every month → zero docs.
    MONTH_ABBREV = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    cp = load_checkpoint(checkpoint_file)
    done_updates = set(cp.get("msrc_done_updates", []))
    total_docs = 0
    for year in range(start_yr, end_yr + 1):
        for month_idx, mon in enumerate(MONTH_ABBREV, start=1):
            # Skip future months in the current year.
            if year == datetime.now().year and month_idx > datetime.now().month:
                continue
            update_id = f"{year}-{mon}"
            if update_id in done_updates:
                continue
            try:
                # /cvrf/{id} returns the full CVRF document with Vulnerability
                # entries. /updates/{id} returns only metadata (no vulns) —
                # using it here was the original bug.
                r = SESSION.get(f"{BASE}/cvrf/{update_id}",
                    headers={"Accept": "application/json"}, timeout=20)
                if r.status_code == 404:
                    # Month not yet published or never existed.
                    done_updates.add(update_id); continue
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                print(f"[msrc] {update_id} failed: {e}")
                time.sleep(5); continue
            month_count = 0
            for vuln in (data.get("Vulnerability") or []):
                cve = vuln.get("CVE", "")
                if not cve: continue
                title_obj = vuln.get("Title") or {}
                title = title_obj.get("Value", "") if isinstance(title_obj, dict) else str(title_obj)
                notes = vuln.get("Notes") or []
                desc = faq = ""
                for note in notes:
                    ntype = note.get("Type", 0)
                    nval  = note.get("Value", "") or ""
                    if ntype == 1: desc = nval
                    elif ntype == 7: faq = nval
                if not desc and not faq: continue
                threats = vuln.get("Threats") or []
                impact = severity = ""
                for t in threats:
                    ttype = t.get("Type", -1)
                    tdesc = (t.get("Description") or {}).get("Value", "")
                    if ttype == 0: impact = tdesc
                    if ttype == 3: severity = tdesc
                cvss_sets = vuln.get("CVSSScoreSets") or []
                cvss = str(cvss_sets[0].get("BaseScore", "")) if cvss_sets else ""
                parts = [f"Microsoft Security Advisory: {cve}"]
                if title: parts.append(f"Title: {title}")
                if severity: parts.append(f"Severity: {severity}")
                if impact: parts.append(f"Impact: {impact}")
                if cvss: parts.append(f"CVSS: {cvss}")
                if desc: parts.append(f"\nDescription:\n{desc[:2000]}")
                if faq: parts.append(f"\nFAQ:\n{faq[:800]}")
                append_jsonl(raw_file, [{"source": "msrc", "cve_id": cve,
                    "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                    "text": "\n".join(parts)}])
                month_count += 1
            total_docs += month_count
            if month_count > 0:
                print(f"[msrc] {update_id}: {month_count}")
            done_updates.add(update_id)
            cp["msrc_done_updates"] = list(done_updates)
            save_checkpoint(checkpoint_file, cp)
            time.sleep(delay)
    print(f"[msrc] Done. Total: {total_docs}")

# ── Vendor Advisories ────────────────────────────────────────────
def run_vendor_advisories(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["vendor_advisories"]
    if not c.get("enabled", True): print("[vendor] Disabled."); return
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)

    # ── Ubuntu Security Notices ───────────────────────────────────────
    # Endpoint: https://ubuntu.com/security/notices.json supports
    # `offset` and `limit` (max 100 per page). The older `details=1`
    # parameter is rejected with HTTP 422.
    if not cp.get("ubuntu_done"):
        print("[vendor] Ubuntu...")
        ubuntu_ok = False
        try:
            offset = 0
            page_size = 100
            total_ubuntu = 0
            while True:
                r = SESSION.get(
                    "https://ubuntu.com/security/notices.json",
                    params={"offset": offset, "limit": page_size},
                    timeout=60,
                )
                r.raise_for_status()
                data = r.json()
                notices = data.get("notices", data if isinstance(data, list) else [])
                if not notices:
                    break
                batch = []
                for n in notices:
                    usn   = n.get("id", "")
                    title = n.get("title", "") or ""
                    desc  = n.get("description", "") or n.get("summary", "") or ""
                    cves  = n.get("cves", []) or []
                    pkgs  = list((n.get("packages") or {}).keys())[:10]
                    if len(desc) < 40:
                        continue
                    parts = [f"Ubuntu Security Notice: {usn}", f"Title: {title}"]
                    if cves: parts.append(f"CVEs: {', '.join(cves[:10])}")
                    if pkgs: parts.append(f"Affected packages: {', '.join(pkgs)}")
                    parts.append(f"\n{desc}")
                    batch.append({"source": "ubuntu_advisory", "id": usn,
                                   "url": f"https://ubuntu.com/security/notices/{usn}",
                                   "text": "\n".join(parts)})
                if batch:
                    append_jsonl(raw_file, batch)
                    total_ubuntu += len(batch)
                if len(notices) < page_size:
                    break
                offset += page_size
                time.sleep(delay)
            print(f"[vendor] Ubuntu: {total_ubuntu}")
            ubuntu_ok = True
        except Exception as e:
            print(f"[vendor] Ubuntu failed: {e}")
        # Only mark done on success — failed runs can retry later.
        if ubuntu_ok:
            cp["ubuntu_done"] = True
            save_checkpoint(checkpoint_file, cp)

    # ── Red Hat Security Data ──────────────────────────────────────────
    # Endpoint moved from /labs/securitydataapi/ to /hydra/rest/securitydata/.
    # The old path returns HTTP 404. Query params are unchanged.
    if not cp.get("redhat_done"):
        print("[vendor] Red Hat...")
        redhat_ok = False
        try:
            page = 1  # Red Hat's API uses 1-based pagination
            total_rh = 0
            while True:
                r = SESSION.get(
                    "https://access.redhat.com/hydra/rest/securitydata/cve.json",
                    params={"per_page": 1000, "page": page},
                    timeout=30,
                )
                r.raise_for_status()
                cves = r.json()
                if not cves:
                    break
                batch = []
                for cve_entry in cves:
                    cve  = cve_entry.get("CVE", "")
                    desc = (cve_entry.get("public_description", "") or
                            cve_entry.get("bugzilla_description", "") or "")
                    sev  = cve_entry.get("severity", "")
                    cvss = cve_entry.get("cvss3_score", "")
                    pkgs = cve_entry.get("affected_packages", [])[:8]
                    if len(desc) < 40:
                        continue
                    parts = [f"Red Hat Security: {cve}", f"Severity: {sev}"]
                    if cvss: parts.append(f"CVSS3: {cvss}")
                    if pkgs: parts.append(f"Packages: {', '.join(pkgs)}")
                    parts.append(f"\n{desc}")
                    batch.append({"source": "redhat_advisory", "cve_id": cve,
                                   "url": f"https://access.redhat.com/security/cve/{cve}",
                                   "text": "\n".join(parts)})
                if batch:
                    append_jsonl(raw_file, batch)
                    total_rh += len(batch)
                page += 1
                time.sleep(delay)
                if len(cves) < 1000:
                    break
            print(f"[vendor] Red Hat: {total_rh}")
            redhat_ok = True
        except Exception as e:
            print(f"[vendor] Red Hat failed: {e}")
        if redhat_ok:
            cp["redhat_done"] = True
            save_checkpoint(checkpoint_file, cp)

    print("[vendor] Done.")

# ── AlienVault OTX ───────────────────────────────────────────────
def run_alienvault(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["alienvault_otx"]
    if not c.get("enabled", True): print("[alienvault] Disabled."); return
    api_key = cfg["api"].get("alienvault_key","")
    if not api_key: print("[alienvault] No API key — skipping."); return
    max_pulses = c.get("max_pulses", 50000)
    delay = c.get("delay_seconds", 1.0)
    headers = {"X-OTX-API-KEY": api_key}
    cp = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("alienvault_done", []))
    next_url = cp.get("alienvault_next","https://otx.alienvault.com/api/v1/pulses/subscribed")
    total = len(done_ids)
    batch = []
    with tqdm(total=max_pulses, initial=total, desc="AlienVault OTX") as pbar:
        while total < max_pulses and next_url:
            try:
                r = SESSION.get(next_url, headers=headers, timeout=20)
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                print(f"[alienvault] Failed: {e}"); break
            for pulse in data.get("results", []):
                pid = pulse.get("id","")
                if not pid or pid in done_ids: continue
                name = pulse.get("name","") or ""
                desc = pulse.get("description","") or ""
                tags = pulse.get("tags",[]) or []
                families = pulse.get("malware_families",[]) or []
                attacks = pulse.get("attack_ids",[]) or []
                iocs = pulse.get("indicators",[]) or []
                ioc_types = {}
                for ioc in iocs[:20]:
                    t = ioc.get("type","")
                    ioc_types[t] = ioc_types.get(t,0) + 1
                parts = [f"Threat Intelligence: {name}"]
                if tags: parts.append(f"Tags: {', '.join(str(t) for t in tags[:15])}")
                if families:
                    fnames = [f.get("display_name",f.get("id","")) for f in families[:5]]
                    parts.append(f"Malware families: {', '.join(fnames)}")
                if attacks:
                    anames = [a.get("display_name",a.get("id","")) for a in attacks[:8]]
                    parts.append(f"ATT&CK: {', '.join(str(a) for a in anames)}")
                if desc: parts.append(f"\n{desc[:2500]}")
                if ioc_types:
                    parts.append(f"\nIOC types: {', '.join(f'{v} {k}' for k,v in ioc_types.items())}")
                batch.append({"source": "alienvault_otx", "id": pid,
                               "url": f"https://otx.alienvault.com/pulse/{pid}",
                               "text": "\n".join(parts)})
                done_ids.add(pid); total += 1; pbar.update(1)
            if len(batch) >= 200:
                append_jsonl(raw_file, batch)
                cp["alienvault_done"] = list(done_ids)
                cp["alienvault_next"] = data.get("next","")
                save_checkpoint(checkpoint_file, cp)
                batch = []
            next_url = data.get("next","")
            time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["alienvault_done"] = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
    print(f"[alienvault] Done. {total}")

# ── NSA Advisories ───────────────────────────────────────────────
def run_nsa(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["nsa_advisories"]
    if not c.get("enabled", True): print("[nsa] Disabled."); return
    delay = c.get("delay_seconds", 2.0)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("nsa_done", []))
    BASE = "https://www.nsa.gov"
    adv_urls = []
    for lurl in [f"{BASE}/Press-Room/Cybersecurity-Advisories-Guidance/",
                 f"{BASE}/cybersecurity-guidance/"]:
        r = safe_get(lurl)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.lower().endswith(".pdf") or "/Press-Room/" in href or "/news-features/" in href:
                full = BASE + href if href.startswith("/") else href
                if full not in adv_urls: adv_urls.append(full)
    batch = []
    for url in tqdm([u for u in adv_urls if u not in done], desc="NSA advisories"):
        text = ""; title = url.split("/")[-1].replace(".pdf","").replace("-"," ")
        if url.lower().endswith(".pdf"):
            r = safe_get(url, timeout=30)
            if r: text = extract_pdf_text(r.content)
        else:
            r = safe_get(url)
            if r:
                soup = BeautifulSoup(r.text, "html.parser")
                title_e = soup.select_one("h1")
                if title_e: title = title_e.get_text(strip=True)
                body_e = soup.select_one("article, main, .field-items")
                text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({"source":"nsa_advisory","title":title,"url":url,
                           "text":f"NSA Advisory: {title}\n\n{text[:6000]}"})
        done.add(url)
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["nsa_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[nsa] Done. {len(done)}")

# ── PortSwigger Academy ──────────────────────────────────────────
def run_portswigger(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["portswigger_academy"]
    if not c.get("enabled", True): print("[portswigger] Disabled."); return
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("portswigger_done", []))
    BASE = "https://portswigger.net"
    topic_links = set()
    for sp in [f"{BASE}/web-security/all-topics", f"{BASE}/web-security/all-labs"]:
        r = safe_get(sp)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if "/web-security/" in href and href.count("/") >= 3:
                full = BASE + href if href.startswith("/") else href
                topic_links.add(full)
    batch = []
    for url in tqdm([u for u in topic_links if u not in done], desc="PortSwigger"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("article, main, .content-container, #academy-content")
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({"source":"portswigger_academy","title":title,"url":url,
                           "text":f"PortSwigger Web Security Academy: {title}\n\n{text[:6000]}"})
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["portswigger_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["portswigger_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[portswigger] Done. {len(done)}")

# ── CISA ICS ─────────────────────────────────────────────────────
def run_cisa_ics(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["cisa_ics"]
    if not c.get("enabled", True): print("[cisa_ics] Disabled."); return
    max_pages = c.get("max_pages", 100)
    delay = c.get("delay_seconds", 1.0)
    BASE = "https://www.cisa.gov"
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("cisa_ics_done", []))
    adv_urls = []
    for page in range(0, max_pages):
        r = safe_get(f"{BASE}/news-events/ics-advisories?page={page}")
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if "/news-events/ics-advisories/icsa-" in href or "/news-events/ics-advisories/icsma-" in href:
                full = BASE + href if href.startswith("/") else href
                if full not in adv_urls:
                    adv_urls.append(full); found = True
        if not found: break
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in adv_urls if u not in done], desc="CISA ICS"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("article, main, .field--type-text-long")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 150:
            batch.append({"source":"cisa_ics","title":title,"url":url,
                           "text":f"CISA ICS Advisory: {title}\n\n{text[:6000]}"})
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["cisa_ics_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["cisa_ics_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[cisa_ics] Done. {len(done)}")

# ── VX-Underground ───────────────────────────────────────────────
def run_vx_underground(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["vx_underground"]
    if not c.get("enabled", True): print("[vxug] Disabled."); return
    delay = c.get("delay_seconds", 2.0)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("vx_underground_done", []))
    r = safe_get("https://vx-underground.org/papers.html") or safe_get("https://vx-underground.org")
    if not r: print("[vxug] Site unreachable."); return
    soup = BeautifulSoup(r.text, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.lower().endswith((".pdf",".txt")):
            full = ("https://vx-underground.org/" + href.lstrip("/")
                    if not href.startswith("http") else href)
            title = a.get_text(strip=True) or href.split("/")[-1]
            links.append({"url": full, "title": title})
    batch = []
    for item in tqdm([l for l in links if l["url"] not in done], desc="VX-Underground"):
        text = ""
        if item["url"].lower().endswith(".pdf"):
            r2 = safe_get(item["url"], timeout=30)
            if r2: text = extract_pdf_text(r2.content)
        else:
            r2 = safe_get(item["url"])
            if r2: text = r2.text
        if len(text) > 200:
            batch.append({"source":"vx_underground","title":item["title"],
                           "url":item["url"],"text":text[:7000]})
        done.add(item["url"])
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["vx_underground_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[vxug] Done. {len(done)}")

# ── NIST Publications ────────────────────────────────────────────
def run_nist(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["nist_publications"]
    if not c.get("enabled", True): print("[nist] Disabled."); return
    delay = c.get("delay_seconds", 2.0)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("nist_done", []))
    pub_links = []
    try:
        api_r = SESSION.get(
            "https://csrc.nist.gov/CSRC/media/publications/sp/800/archive/json/publications.json",
            timeout=30)
        if api_r.status_code == 200:
            for p in api_r.json():
                url = p.get("detailUrl","") or p.get("url","")
                title = p.get("title","")
                if url: pub_links.append({"url":url,"title":title})
    except Exception:
        pass
    r = safe_get("https://csrc.nist.gov/publications/search", timeout=30)
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if "/publications/detail/sp/800/" in href or "/publications/detail/sp/1800/" in href:
                full = "https://csrc.nist.gov" + href if href.startswith("/") else href
                title = a.get_text(strip=True)
                pub_links.append({"url":full,"title":title})
    batch = []
    for pub in tqdm([p for p in pub_links if p["url"] not in done], desc="NIST pubs"):
        pr = safe_get(pub["url"])
        if not pr: done.add(pub["url"]); continue
        soup = BeautifulSoup(pr.text, "html.parser")
        abstract = soup.select_one(".abstract, #abstract")
        abs_text = abstract.get_text("\n",strip=True) if abstract else ""
        pdf_url = None
        for a in soup.find_all("a", href=True):
            if a["href"].lower().endswith(".pdf") and "800" in a["href"]:
                pdf_url = ("https://nvlpubs.nist.gov" + a["href"]
                           if a["href"].startswith("/") else a["href"])
                break
        text = f"NIST Special Publication: {pub['title']}\n\n"
        if abs_text: text += f"Abstract:\n{abs_text}\n\n"
        if pdf_url:
            pr2 = safe_get(pdf_url, timeout=60)
            if pr2:
                pdf_text = extract_pdf_text(pr2.content, max_pages=40)
                if pdf_text: text += pdf_text
        if len(text) > 200:
            batch.append({"source":"nist_publication","title":pub["title"],
                           "url":pub["url"],"text":text[:8000]})
        done.add(pub["url"])
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["nist_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[nist] Done. {len(done)}")
