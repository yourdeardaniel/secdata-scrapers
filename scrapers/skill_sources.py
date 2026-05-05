"""
Skill-focused sources: pentest, binary exploitation, malware RE, red team.
Covers: pentest_reports, owasp_wstg, ptes, pentester_land, sans_reading_room,
        ropemporium, ir0nstone, nightmare, how2heap, exploit_education,
        liveoverflow, pwn_college, malwareunicorn, hasherezade, zeroxdf,
        flareon, ghidra_course, opensecuritytraining, malwarebazaar, anyrun,
        malware_traffic_analysis, ired_team, cobalt_strike_docs,
        urlhaus, threatfox
"""
import os, time, subprocess, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


def extract_md_from_dir(repo_dir, source_name, label):
    docs = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules",".git")]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".md",".txt",".rst",".c",".cpp",".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > 300_000:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                if len(text) < 150:
                    continue
                rel = os.path.relpath(fpath, repo_dir)
                title = fname.rsplit(".",1)[0].replace("-"," ").replace("_"," ")
                docs.append({"source": source_name, "file": rel, "title": title,
                              "url": label, "text": text[:7000]})
            except Exception:
                pass
    return docs


def extract_pdf_text(content, max_pages=30):
    try:
        import pdfplumber, io
        parts = []
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            for page in pdf.pages[:max_pages]:
                t = page.extract_text()
                if t: parts.append(t)
        return "\n".join(parts)
    except Exception:
        return ""


def _scrape_gitbook(base_url, source_name, label, max_pages, delay, cp_key, checkpoint_file, raw_file):
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get(cp_key, []))
    to_visit = ["/"]
    visited = set()
    docs = []
    while to_visit and len(visited) < max_pages:
        path = to_visit.pop(0)
        url = base_url + path if path.startswith("/") else path
        if url in visited: continue
        visited.add(url)
        if url in done: continue
        r = safe_get(url)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else path
        body_e = soup.select_one(".gitbook-markdown-body,.page-inner,article,main")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            docs.append({"source":source_name,"title":title,"url":url,
                          "text":f"{label} — {title}:\n\n{text[:6000]}"})
        done.add(url)
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if href.startswith("/") and href not in visited:
                to_visit.append(href)
        time.sleep(delay)
    if docs: append_jsonl(raw_file, docs)
    cp[cp_key] = list(done)
    save_checkpoint(checkpoint_file, cp)
    return len(docs)


def _scrape_blog(base_url, source_name, label, max_pages, delay, cp_key, checkpoint_file, raw_file):
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get(cp_key, []))
    post_urls = []
    for page in range(1, max_pages + 1):
        url = f"{base_url}page/{page}/" if page > 1 else base_url + "/"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("h2 a[href], h1 a[href], .post-title a[href], article a[href]"):
            href = a.get("href","")
            domain = base_url.split("//")[1].split("/")[0]
            if domain in href and href not in post_urls:
                post_urls.append(href); found = True
        if not found: break
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in post_urls if u not in done], desc=source_name):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1.entry-title, h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one(".entry-content, article, .post-content")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 300:
            batch.append({"source":source_name,"title":title,"url":url,
                           "text":f"{label}: {title}\n\n{text[:6000]}"})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp[cp_key] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp[cp_key] = list(done)
        save_checkpoint(checkpoint_file, cp)
    return len(done)


# ── PENTEST SOURCES ──────────────────────────────────────────────

def run_pentest_reports(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("pentest_reports", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("pentest_reports_done"): return
    dest = "./data/repos/public-pentesting-reports"
    ok = clone_repo("https://github.com/juliocesarfort/public-pentesting-reports", dest)
    if not ok: print("[pentest_reports] Clone failed."); return
    docs = []
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        firm = os.path.relpath(root, dest).split(os.sep)[0]
        for fname in files:
            fpath = os.path.join(root, fname)
            text = ""
            if fname.lower().endswith(".pdf"):
                try:
                    with open(fpath, "rb") as f: text = extract_pdf_text(f.read(), max_pages=40)
                except Exception: pass
            elif fname.lower().endswith(".md"):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f: text = f.read()
                except Exception: pass
            if len(text) > 300:
                title = fname.rsplit(".",1)[0].replace("-"," ").replace("_"," ")
                docs.append({"source":"pentest_report","firm":firm,"title":title,
                              "url":"https://github.com/juliocesarfort/public-pentesting-reports",
                              "text":f"Penetration Test Report ({firm}): {title}\n\n{text[:8000]}"})
    if docs: append_jsonl(raw_file, docs)
    print(f"[pentest_reports] {len(docs)}")
    cp["pentest_reports_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_owasp_wstg(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("owasp_wstg", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("owasp_wstg_done"): return
    dest = "./data/repos/owasp-wstg"
    ok = clone_repo("https://github.com/OWASP/wstg", dest)
    if ok:
        docs = extract_md_from_dir(dest, "owasp_wstg", "https://github.com/OWASP/wstg")
        if docs: append_jsonl(raw_file, docs)
        print(f"[owasp_wstg] {len(docs)}")
    cp["owasp_wstg_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_ptes(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ptes", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("ptes_done"): return
    delay = c.get("delay_seconds", 1.5)
    pages = [
        "http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines",
        "http://www.pentest-standard.org/index.php/Pre-engagement",
        "http://www.pentest-standard.org/index.php/Intelligence_Gathering",
        "http://www.pentest-standard.org/index.php/Threat_Modeling",
        "http://www.pentest-standard.org/index.php/Vulnerability_Analysis",
        "http://www.pentest-standard.org/index.php/Exploitation",
        "http://www.pentest-standard.org/index.php/Post_Exploitation",
        "http://www.pentest-standard.org/index.php/Reporting",
    ]
    docs = []
    for url in pages:
        r = safe_get(url, timeout=20)
        if not r: time.sleep(delay); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else url.split("/")[-1]
        body_e = soup.select_one("#mw-content-text, .mw-parser-output")
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 200:
            docs.append({"source":"ptes","title":title,"url":url,
                          "text":f"PTES: {title}\n\n{text[:7000]}"})
        time.sleep(delay)
    if docs: append_jsonl(raw_file, docs)
    print(f"[ptes] {len(docs)}")
    cp["ptes_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_pentester_land(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("pentester_land", {})
    if not c.get("enabled", True): return
    max_pages = c.get("max_pages", 50)
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("pentester_land_done", []))
    BASE = "https://pentester.land"
    all_urls = []
    for page in tqdm(range(1, max_pages + 1), desc="pentester.land listing"):
        url = f"{BASE}/writeups" if page == 1 else f"{BASE}/writeups?page={page}"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if "/writeups/" in href and href != "/writeups":
                full = BASE + href if href.startswith("/") else href
                if full not in all_urls:
                    all_urls.append(full); found = True
        if not found: break
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in all_urls if u not in done], desc="pentester.land"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("article, .content, main")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({"source":"pentester_land","title":title,"url":url,
                           "text":f"Pentest Writeup: {title}\n\n{text[:6000]}"})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["pentester_land_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["pentester_land_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[pentester_land] Done. {len(done)}")


def run_sans_reading_room(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("sans_reading_room", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 2.0)
    max_pages = c.get("max_pages", 100)
    categories = c.get("categories", ["/reading-room/whitepapers/penetesting/"])
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("sans_rr_done", []))
    BASE = "https://www.sans.org"
    paper_urls = []
    for cat in categories:
        for page in range(1, max_pages + 1):
            url = BASE + cat if page == 1 else f"{BASE}{cat}page/{page}/"
            r = safe_get(url)
            if not r: break
            soup = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href","")
                if "/reading-room/whitepapers/" in href and href != cat:
                    full = BASE + href if href.startswith("/") else href
                    if full not in paper_urls and full.endswith("/"):
                        paper_urls.append(full); found = True
            if not found: break
            time.sleep(delay)
    batch = []
    for url in tqdm([u for u in paper_urls if u not in done], desc="SANS Reading Room"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        abstract = soup.select_one(".abstract, .paper-abstract")
        abs_text = abstract.get_text("\n",strip=True) if abstract else ""
        body_e = soup.select_one("article, .paper-content, main")
        body = body_e.get_text("\n",strip=True) if body_e else ""
        combined = f"SANS Reading Room: {title}\n\n"
        if abs_text: combined += f"Abstract:\n{abs_text}\n\n"
        if body: combined += body[:4000]
        if len(combined) > 200:
            batch.append({"source":"sans_reading_room","title":title,
                           "url":url,"text":combined})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["sans_rr_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["sans_rr_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[sans_rr] Done. {len(done)}")


# ── BINARY EXPLOITATION ──────────────────────────────────────────

def run_ropemporium(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ropemporium", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("ropemporium_done"): return
    delay = c.get("delay_seconds", 1.5)
    docs = []
    for path in ["/guide.html","/","/challenge/ret2win.html","/challenge/split.html",
                 "/challenge/callme.html","/challenge/write4.html","/challenge/badchars.html",
                 "/challenge/fluff.html","/challenge/pivot.html","/challenge/ret2csu.html"]:
        r = safe_get("https://ropemporium.com" + path)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1,h2")
        title = title_e.get_text(strip=True) if title_e else path
        body_e = soup.select_one("main,article,.content")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            docs.append({"source":"ropemporium","title":title,
                          "url":"https://ropemporium.com"+path,
                          "text":f"ROP Technique — {title}:\n\n{text[:6000]}"})
        time.sleep(delay)
    if docs: append_jsonl(raw_file, docs)
    cp["ropemporium_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[ropemporium] {len(docs)}")


def run_ir0nstone(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ir0nstone", {})
    if not c.get("enabled", True): return
    n = _scrape_gitbook("https://ir0nstone.gitbook.io", "ir0nstone",
                        "Binary Exploitation Notes", 200,
                        c.get("delay_seconds",1.0), "ir0nstone_done",
                        checkpoint_file, raw_file)
    print(f"[ir0nstone] {n}")


def run_nightmare(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("nightmare", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("nightmare_done"): return
    dest = "./data/repos/nightmare"
    ok = clone_repo("https://github.com/guyinatuxedo/nightmare", dest)
    if ok:
        docs = extract_md_from_dir(dest, "nightmare", "https://github.com/guyinatuxedo/nightmare")
        if docs: append_jsonl(raw_file, docs)
        print(f"[nightmare] {len(docs)}")
    cp["nightmare_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_how2heap(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("how2heap", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("how2heap_done"): return
    dest = "./data/repos/how2heap"
    ok = clone_repo("https://github.com/shellphish/how2heap", dest)
    if ok:
        docs = extract_md_from_dir(dest, "how2heap", "https://github.com/shellphish/how2heap")
        if docs: append_jsonl(raw_file, docs)
        print(f"[how2heap] {len(docs)}")
    cp["how2heap_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_exploit_education(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("exploit_education", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("exploit_edu_done", []))
    BASE = "https://exploit.education"
    delay = c.get("delay_seconds", 1.5)
    all_urls = []
    for sec in ["/phoenix/","/protostar/","/nebula/","/fusion/"]:
        r = safe_get(BASE + sec)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if href.startswith(sec) and href != sec:
                all_urls.append(BASE + href)
    batch = []
    for url in tqdm([u for u in set(all_urls) if u not in done], desc="exploit.education"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else url
        body_e = soup.select_one("main,article,.content")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({"source":"exploit_education","title":title,"url":url,
                           "text":f"Exploit Education — {title}:\n\n{text[:6000]}"})
        done.add(url)
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["exploit_edu_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[exploit_education] {len(done)}")


def run_liveoverflow(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("liveoverflow", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("liveoverflow_done"): return
    all_docs = []
    for repo_url, dest in [
        ("https://github.com/LiveOverflow/liveoverflow_youtube","./data/repos/liveoverflow_yt"),
        ("https://github.com/LiveOverflow/ctf-writeups","./data/repos/liveoverflow_ctf"),
    ]:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_from_dir(dest, "liveoverflow", repo_url)
            all_docs.extend(docs)
    if all_docs: append_jsonl(raw_file, all_docs)
    cp["liveoverflow_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[liveoverflow] {len(all_docs)}")


def run_pwn_college(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("pwn_college", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("pwn_college_done", []))
    delay = c.get("delay_seconds", 1.5)
    modules = ["/intro-to-cybersecurity/","/program-security/","/system-security/",
               "/software-exploitation/","/assembly-crash-course/","/debugging-refresher/",
               "/reverse-engineering/","/memory-errors/","/shellcode-injection/",
               "/format-string-exploits/","/return-oriented-programming/",
               "/heap-exploitation/","/kernel-security/"]
    docs = []
    for path in modules:
        url = "https://pwn.college" + path
        if url in done: continue
        r = safe_get(url)
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1,h2")
        title = title_e.get_text(strip=True) if title_e else path
        body_e = soup.select_one("main,article,.module-content")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            docs.append({"source":"pwn_college","title":title,"url":url,
                          "text":f"pwn.college — {title}:\n\n{text[:6000]}"})
        done.add(url)
        time.sleep(delay)
    if docs:
        append_jsonl(raw_file, docs)
        cp["pwn_college_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[pwn_college] {len(docs)}")


# ── MALWARE RE ───────────────────────────────────────────────────

def run_malwareunicorn(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("malwareunicorn", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("malwareunicorn_done"): return
    all_docs = []
    for repo_url, dest in [
        ("https://github.com/malwareunicorn/RE101","./data/repos/RE101"),
        ("https://github.com/malwareunicorn/RE102","./data/repos/RE102"),
    ]:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_from_dir(dest, "malwareunicorn", repo_url)
            all_docs.extend(docs)
    if all_docs: append_jsonl(raw_file, all_docs)
    cp["malwareunicorn_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[malwareunicorn] {len(all_docs)}")


def run_hasherezade(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("hasherezade", {})
    if not c.get("enabled", True): return
    n = _scrape_blog("https://hshrzd.wordpress.com", "hasherezade",
                     "Malware RE", c.get("max_pages",20),
                     c.get("delay_seconds",1.5), "hasherezade_done",
                     checkpoint_file, raw_file)
    print(f"[hasherezade] {n}")


def run_zeroxdf(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("zeroxdf", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("zeroxdf_done",[]))
    delay = c.get("delay_seconds",1.5)
    post_urls = []
    for page in range(1, c.get("max_pages",30)+1):
        url = "https://0xdf.gitlab.io/" if page==1 else f"https://0xdf.gitlab.io/page{page}/"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text,"html.parser")
        found = False
        for a in soup.select("h2 a[href],.post-title a[href]"):
            href=a.get("href","")
            if "0xdf.gitlab.io" in href and href not in post_urls:
                post_urls.append(href); found=True
        if not found: break
        time.sleep(delay)
    batch=[]
    for url in tqdm([u for u in post_urls if u not in done], desc="0xdf"):
        r=safe_get(url)
        if not r: done.add(url); continue
        soup=BeautifulSoup(r.text,"html.parser")
        title_e=soup.select_one("h1")
        title=title_e.get_text(strip=True) if title_e else ""
        body_e=soup.select_one("article,.post-content,main")
        text=body_e.get_text("\n",strip=True) if body_e else ""
        if len(text)>300:
            batch.append({"source":"zeroxdf","title":title,"url":url,
                           "text":f"Security Writeup — {title}:\n\n{text[:6000]}"})
        done.add(url)
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file,batch)
        cp["zeroxdf_done"]=list(done)
        save_checkpoint(checkpoint_file,cp)
    print(f"[0xdf] {len(done)}")


def run_flareon(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("flareon", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("flareon_done"): return
    dest = "./data/repos/flare-on-writeups"
    ok = clone_repo("https://github.com/mandiant/flare-on-writeups", dest)
    if ok:
        docs = extract_md_from_dir(dest, "flareon", "https://github.com/mandiant/flare-on-writeups")
        if docs: append_jsonl(raw_file, docs)
        print(f"[flareon] {len(docs)}")
    cp["flareon_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_ghidra_course(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ghidra_course", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("ghidra_course_done"): return
    dest = "./data/repos/ghidra-docs"
    ok = clone_repo("https://github.com/NationalSecurityAgency/ghidra", dest, timeout=600)
    if ok:
        docs_dir = os.path.join(dest, "GhidraDocs")
        if not os.path.exists(docs_dir):
            subprocess.run(["git","-C",dest,"sparse-checkout","set","GhidraDocs"], capture_output=True)
            subprocess.run(["git","-C",dest,"checkout"], capture_output=True)
        if os.path.exists(docs_dir):
            docs = extract_md_from_dir(docs_dir, "ghidra_course",
                                       "https://github.com/NationalSecurityAgency/ghidra")
            if docs: append_jsonl(raw_file, docs)
            print(f"[ghidra_course] {len(docs)}")
    cp["ghidra_course_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_opensecuritytraining(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("opensecuritytraining", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("opensectraining_done"): return
    repos = [
        "https://github.com/opensecuritytraining/IntroX86",
        "https://github.com/opensecuritytraining/IntroX86-64",
        "https://github.com/opensecuritytraining/LifeOfBinaries",
        "https://github.com/opensecuritytraining/MalwareDynamicAnalysis",
        "https://github.com/opensecuritytraining/ReverseEngineeringMalware101",
        "https://github.com/opensecuritytraining/Exploits1",
        "https://github.com/opensecuritytraining/Exploits2",
    ]
    all_docs = []
    for repo_url in repos:
        name = repo_url.split("/")[-1]
        dest = f"./data/repos/ost2_{name}"
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_from_dir(dest, "opensecuritytraining", repo_url)
            all_docs.extend(docs)
    if all_docs: append_jsonl(raw_file, all_docs)
    cp["opensectraining_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[opensecuritytraining] {len(all_docs)}")


def run_malwarebazaar(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("malwarebazaar", {})
    if not c.get("enabled", True): return
    max_pages = c.get("max_pages", 100)
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("malwarebazaar_done", []))
    batch = []
    for _ in tqdm(range(max_pages), desc="MalwareBazaar"):
        try:
            r = SESSION.post("https://mb-api.abuse.ch/api/v1/",
                             data={"query":"get_recent","selector":"time"}, timeout=20)
            r.raise_for_status()
            for s in r.json().get("data", []):
                sha = s.get("sha256_hash","")
                if not sha or sha in done: continue
                tags = s.get("tags",[]) or []
                sig = s.get("signature","") or ""
                parts = [f"MalwareBazaar Sample: {s.get('file_name',sha)}",
                         f"SHA256: {sha}", f"Type: {s.get('file_type','')}"]
                if sig: parts.append(f"Signature: {sig}")
                if tags: parts.append(f"Tags: {', '.join(str(t) for t in tags[:15])}")
                if s.get("delivery_method"): parts.append(f"Delivery: {s['delivery_method']}")
                batch.append({"source":"malwarebazaar","sha256":sha,
                               "url":f"https://bazaar.abuse.ch/sample/{sha}/",
                               "text":"\n".join(parts)})
                done.add(sha)
        except Exception as e:
            print(f"[malwarebazaar] Error: {e}")
        if len(batch) >= 500:
            append_jsonl(raw_file, batch)
            cp["malwarebazaar_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["malwarebazaar_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[malwarebazaar] Done. {len(done)}")


def run_anyrun(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("anyrun", {})
    if not c.get("enabled", True): return
    max_pages = c.get("max_pages", 50)
    delay = c.get("delay_seconds", 2.0)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("anyrun_done", []))
    batch = []
    for page in tqdm(range(1, max_pages+1), desc="ANY.RUN"):
        try:
            r = SESSION.get("https://app.any.run/api/analysis/",
                params={"skip":(page-1)*25,"limit":25,"isPublic":"true"}, timeout=20)
            if r.status_code != 200: break
            data = r.json()
            tasks = (data.get("data",{}).get("tasks") or data.get("tasks") or [])
            if not tasks: break
            for t in tasks:
                tid = t.get("uuid", t.get("taskid",""))
                if not tid or tid in done: continue
                verdict = t.get("verdict","") or ""
                fname = t.get("name","") or ""
                tags = t.get("tags",[]) or []
                mitre = t.get("mitre",[]) or []
                procs = t.get("processes",[]) or []
                anames = [m.get("technique",str(m)) for m in mitre[:8] if m]
                pnames = [p.get("fileName",p.get("name","")) for p in procs[:8] if isinstance(p,dict)]
                parts = [f"ANY.RUN Analysis: {fname or tid}", f"Verdict: {verdict}"]
                if tags: parts.append(f"Tags: {', '.join(str(t2) for t2 in tags[:15])}")
                if anames: parts.append(f"ATT&CK: {', '.join(str(a) for a in anames)}")
                if pnames: parts.append(f"Processes: {', '.join(p for p in pnames if p)}")
                batch.append({"source":"anyrun","id":tid,
                               "url":f"https://app.any.run/tasks/{tid}/",
                               "text":"\n".join(parts)})
                done.add(tid)
        except Exception as e:
            print(f"[anyrun] Page {page}: {e}"); break
        if len(batch) >= 200:
            append_jsonl(raw_file, batch)
            cp["anyrun_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["anyrun_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[anyrun] Done. {len(done)}")


def run_malware_traffic_analysis(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("malware_traffic_analysis", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("mta_done", []))
    BASE = "https://www.malware-traffic-analysis.net"
    post_urls = []
    for year in range(2013, 2026):
        r = safe_get(f"{BASE}/{year}/index.html")
        if not r: continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.endswith(".html") and not href.endswith("index.html"):
                full = BASE+"/"+href.lstrip("/") if not href.startswith("http") else href
                if full not in post_urls: post_urls.append(full)
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in post_urls if u not in done], desc="MTA"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1,h2,title")
        title = title_e.get_text(strip=True) if title_e else url
        body_e = soup.select_one("div.blog-post, article, .entry-content")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({"source":"malware_traffic_analysis","title":title,
                           "url":url,"text":f"Malware Traffic Analysis: {title}\n\n{text[:6000]}"})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["mta_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp["mta_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[mta] Done. {len(done)}")


# ── RED TEAM + THREAT INTEL ──────────────────────────────────────

def run_ired_team(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ired_team", {})
    if not c.get("enabled", True): return
    n = _scrape_gitbook("https://www.ired.team", "ired_team",
                        "Red Team Technique", 500,
                        c.get("delay_seconds",1.5), "ired_team_done",
                        checkpoint_file, raw_file)
    print(f"[ired_team] {n}")


def run_cobalt_strike_docs(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("cobalt_strike_docs", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("cobalt_strike_done",[]))
    delay = c.get("delay_seconds",1.5)
    blog_urls = []
    for page in range(1, 20):
        url = "https://www.cobaltstrike.com/blog" if page==1 else f"https://www.cobaltstrike.com/blog/page/{page}"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text,"html.parser")
        found = False
        for a in soup.select("article a[href], h2 a[href]"):
            href = a.get("href","")
            if "cobaltstrike.com/blog/" in href and href not in blog_urls:
                blog_urls.append(href); found=True
        if not found: break
        time.sleep(delay)
    batch=[]
    for url in tqdm([u for u in blog_urls if u not in done], desc="Cobalt Strike"):
        r=safe_get(url)
        if not r: done.add(url); continue
        soup=BeautifulSoup(r.text,"html.parser")
        title_e=soup.select_one("h1")
        title=title_e.get_text(strip=True) if title_e else ""
        body_e=soup.select_one("article,.post-content,main")
        text=body_e.get_text("\n",strip=True) if body_e else ""
        if len(text)>300:
            batch.append({"source":"cobalt_strike","title":title,"url":url,
                           "text":f"Red Team C2 — {title}:\n\n{text[:6000]}"})
        done.add(url)
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file,batch)
        cp["cobalt_strike_done"]=list(done)
        save_checkpoint(checkpoint_file,cp)
    print(f"[cobalt_strike] {len(done)}")


def run_urlhaus(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("urlhaus", {})
    if not c.get("enabled", True): return
    max_batches = c.get("max_batches", 50)
    delay = c.get("delay_seconds", 0.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("urlhaus_done",[]))
    batch=[]
    for _ in tqdm(range(max_batches), desc="URLhaus"):
        try:
            r = SESSION.post("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                             data={"limit":1000}, timeout=20)
            r.raise_for_status()
            for entry in r.json().get("urls",[]):
                uid = str(entry.get("id",""))
                if not uid or uid in done: continue
                url = entry.get("url","")
                threat = entry.get("threat","") or ""
                tags = entry.get("tags",[]) or []
                plds = entry.get("payloads",[]) or []
                pinfo = []
                for p in plds[:5]:
                    if isinstance(p,dict):
                        n2=p.get("filename","") or p.get("file_type","")
                        s2=p.get("signature","")
                        if n2 or s2: pinfo.append(f"{n2}({s2})" if s2 else n2)
                parts=[f"URLhaus: {url}",f"Threat: {threat}",
                       f"Status: {entry.get('url_status','')}"]
                if tags: parts.append(f"Tags: {', '.join(str(t) for t in tags[:10])}")
                if pinfo: parts.append(f"Payloads: {', '.join(pinfo)}")
                batch.append({"source":"urlhaus","id":uid,
                               "url":f"https://urlhaus.abuse.ch/url/{uid}/",
                               "text":"\n".join(parts)})
                done.add(uid)
        except Exception as e:
            print(f"[urlhaus] Error: {e}")
        if len(batch)>=500:
            append_jsonl(raw_file,batch)
            cp["urlhaus_done"]=list(done)
            save_checkpoint(checkpoint_file,cp)
            batch=[]
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file,batch)
        cp["urlhaus_done"]=list(done)
        save_checkpoint(checkpoint_file,cp)
    print(f"[urlhaus] Done. {len(done)}")


def run_threatfox(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("threatfox", {})
    if not c.get("enabled", True): return
    max_days = c.get("max_days", 90)
    delay = c.get("delay_seconds", 1.0)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("threatfox_done",[]))
    done_days = set(cp.get("threatfox_days",[]))
    batch=[]
    for days in [1,3,7,14,30,60,max_days]:
        if str(days) in done_days: continue
        try:
            r = SESSION.post("https://threatfox-api.abuse.ch/api/v1/",
                             json={"query":"get_iocs","days":days}, timeout=30)
            r.raise_for_status()
            for ioc in r.json().get("data",[]):
                iid=str(ioc.get("id",""))
                if not iid or iid in done: continue
                parts=[f"ThreatFox IOC: {ioc.get('ioc','')}",
                       f"Type: {ioc.get('ioc_type','')}",
                       f"Threat: {ioc.get('threat_type','')}"]
                if ioc.get("malware"): parts.append(f"Malware: {ioc['malware']}")
                if ioc.get("tags"): parts.append(f"Tags: {', '.join(str(t) for t in ioc['tags'][:10])}")
                if ioc.get("reference"): parts.append(f"Reference: {ioc['reference']}")
                batch.append({"source":"threatfox","id":iid,
                               "url":f"https://threatfox.abuse.ch/ioc/{iid}/",
                               "text":"\n".join(parts)})
                done.add(iid)
        except Exception as e:
            print(f"[threatfox] days={days}: {e}")
        if len(batch)>=500:
            append_jsonl(raw_file,batch)
            cp["threatfox_done"]=list(done)
            done_days.add(str(days))
            cp["threatfox_days"]=list(done_days)
            save_checkpoint(checkpoint_file,cp)
            batch=[]
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file,batch)
        cp["threatfox_done"]=list(done)
        save_checkpoint(checkpoint_file,cp)
    print(f"[threatfox] Done. {len(done)}")
