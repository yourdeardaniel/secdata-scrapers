"""
Advanced sources — v5 additions.

DFIR / FORENSICS (8 sources)
  1.  Mandiant / Google Cloud Threat Intelligence blog
  2.  Microsoft Security blog (DART team)
  3.  13Cubed Windows forensics blog
  4.  Windows Forensic Artifacts Guide (GitHub)
  5.  ForensicArtifacts definitions database
  6.  Linux forensics repos
  7.  IR playbook repos (GitHub)
  8.  SANS Digital Forensics blog (targeted)

VULNERABILITY RESEARCH METHODOLOGY (10 sources)
  9.  NCC Group research blog
  10. Synacktiv blog
  11. ZDI (Zero Day Initiative) blog
  12. Orange Tsai / Devcore blog
  13. Quarkslab blog
  14. CERT/CC vulnerability notes database
  15. Qualys Security Labs blog
  16. James Kettle / PortSwigger research papers
  17. ret2 systems binary exploitation curriculum
  18. Google Project Zero issue tracker

NEW GAPS (11 topics, 16 sources)
  19. Browser exploitation (WebKit, Firefox, Chromium security blogs)
  20. Fileless malware (Red Canary, SpecterOps, Elastic Security research)
  21. EDR evasion methodology (ScareCrow, direct syscall, AMSI bypass repos)
  22. SOC workflow / security operations (SOC Prime, CISA IR, OpenSOC)
  23. SIEM implementation (Sentinel GitHub, Elastic SIEM docs, Splunk security)
  24. Post-quantum cryptography (NIST PQC, Open Quantum Safe)
  25. Serverless security (OWASP Serverless, PureSec, AWS Lambda security)
  26. Purple team methodology (AttackIQ, PTEF, Scythe blog)
  27. Crypto implementation bugs (NCC Group crypto + Trail of Bits audits)
  28. Binary code auditing (RPISEC MBE, ret2school, systematic audit repos)
  29. Rootkits / UEFI bootkits (ESET research, NSA UEFI, GitHub UEFI repos)
"""
import os, re, time, json, subprocess, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    parse_html, extract_pdf_text,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


def clone_many(repos, source, raw_file, checkpoint_file, cp_key):
    cp = load_checkpoint(checkpoint_file)
    if cp.get(cp_key): return 0
    all_docs = []
    for repo_url, dest, label in repos:
        if clone_repo(repo_url, dest):
            all_docs.extend(extract_md(dest, source, repo_url, label))
    if all_docs:
        for i in range(0, len(all_docs), 500):
            append_jsonl(raw_file, all_docs[i:i+500])
    cp[cp_key] = True
    save_checkpoint(checkpoint_file, cp)
    return len(all_docs)


def scrape_blog(base_url, source, label, cp_key, raw_file, checkpoint_file,
                delay=1.5, max_pages=30, selectors=None, link_filter=None):
    cp   = load_checkpoint(checkpoint_file)
    done = set(cp.get(cp_key, []))
    selectors = selectors or ["article", ".post-content", ".entry-content", "main"]
    domain = base_url.split("//")[-1].split("/")[0]
    post_urls = []

    for page in range(1, max_pages + 1):
        url = base_url if page == 1 else f"{base_url}page/{page}/"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if not href or href in done or href in post_urls: continue
            if domain not in href:
                if not href.startswith("/"): continue
                href = base_url.rstrip("/") + href
            if link_filter and not link_filter(href): continue
            if len(href) > len(base_url) + 4:
                post_urls.append(href); found = True
        if not found: break
        time.sleep(delay)

    batch = []
    for url in tqdm([u for u in post_urls if u not in done], desc=source):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = None
        for sel in selectors:
            body_e = soup.select_one(sel)
            if body_e: break
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({"source": source, "title": title, "url": url,
                          "text": f"{label}: {title}\n\n{text[:7000]}"})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp[cp_key] = list(done); save_checkpoint(checkpoint_file, cp); batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp[cp_key] = list(done); save_checkpoint(checkpoint_file, cp)
    return len(done)


# ================================================================
# DFIR SOURCES
# ================================================================

def run_mandiant_blog(cfg, raw_file, checkpoint_file):
    """
    Mandiant / Google Cloud Threat Intelligence blog.
    Formerly FireEye. The gold standard for APT attribution, adversary
    TTP analysis, and enterprise incident response case studies.
    Covers nation-state groups, ransomware operations, malware families.
    """
    c = cfg["scrapers"].get("mandiant_blog", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("mandiant_done", []))
    delay = c.get("delay_seconds", 1.5)

    urls_to_check = [
        "https://cloud.google.com/blog/topics/threat-intelligence",
        "https://www.mandiant.com/resources/blog",
    ]
    post_urls = []
    for base in urls_to_check:
        for page in range(1, 20):
            url = base if page == 1 else f"{base}?page={page}"
            r = safe_get(url)
            if not r: break
            soup = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if any(d in href for d in ["mandiant.com/resources/blog/",
                                            "cloud.google.com/blog/topics/threat-intelligence"]):
                    full = ("https://www.mandiant.com" + href
                            if href.startswith("/") else href)
                    if full not in post_urls and full not in done:
                        post_urls.append(full); found = True
            if not found: break
            time.sleep(delay)

    batch = []
    for url in tqdm([u for u in post_urls if u not in done], desc="Mandiant"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("article, .blog-content, .post-body, main")
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({"source": "mandiant_blog", "title": title, "url": url,
                          "text": f"Mandiant Threat Intelligence: {title}\n\n{text[:7000]}"})
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["mandiant_done"] = list(done); save_checkpoint(checkpoint_file, cp); batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["mandiant_done"] = list(done); save_checkpoint(checkpoint_file, cp)
    print(f"[mandiant] Done. {len(done)} posts.")


def run_microsoft_security_blog(cfg, raw_file, checkpoint_file):
    """
    Microsoft Security blog including MSTIC and DART team posts.
    Enterprise Windows IR, cloud IR, ransomware case studies,
    nation-state attribution. Best source for Azure and M365 incident analysis.
    """
    c = cfg["scrapers"].get("microsoft_security_blog", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://www.microsoft.com/en-us/security/blog/",
        "microsoft_security_blog",
        "Microsoft DART / MSTIC Security Research",
        "msft_sec_blog_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=40,
        link_filter=lambda h: "microsoft.com/en-us/security/blog/" in h and len(h) > 55,
    )
    print(f"[msft_sec] Done. {n} posts.")


def run_13cubed(cfg, raw_file, checkpoint_file):
    """
    13Cubed blog — Richard Davis (SANS instructor).
    The most detailed Windows forensic artifact documentation
    available publicly. UserAssist, ShimCache, Amcache, BAM/DAM,
    prefetch, event logs — each post is a reference document.
    """
    c = cfg["scrapers"].get("13cubed", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://www.13cubed.com/",
        "13cubed",
        "Windows Forensic Artifact Analysis",
        "13cubed_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        link_filter=lambda h: "13cubed.com" in h and len(h) > 25,
    )
    print(f"[13cubed] Done. {n} posts.")


def run_windows_artifact_guide(cfg, raw_file, checkpoint_file):
    """
    Windows Forensic Artifacts Guide + ForensicArtifacts definitions.
    Structured documentation for every Windows forensic artifact:
    what it records, file paths, parsing method, investigative value.
    Format converts exceptionally well to Q&A training examples.
    """
    c = cfg["scrapers"].get("windows_artifact_guide", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/Psmths/windows-forensic-artifacts",
         "./data/repos/win-forensic-artifacts",
         "Windows Forensic Artifact Reference"),
        ("https://github.com/ForensicArtifacts/artifacts",
         "./data/repos/forensic-artifacts-db",
         "Forensic Artifact Definitions Database"),
        ("https://github.com/libyal/winreg-kb",
         "./data/repos/winreg-kb",
         "Windows Registry Knowledge Base"),
        ("https://github.com/libyal/libevtx",
         "./data/repos/libevtx",
         "Windows Event Log Format Documentation"),
        ("https://github.com/EricZimmerman/evtx",
         "./data/repos/evtx-parser",
         "EVTX Parser and Event Log Analysis"),
    ], "windows_artifact_guide", raw_file, checkpoint_file, "win_artifacts_done")
    print(f"[win_artifacts] Done. {n} files.")


def run_linux_forensics(cfg, raw_file, checkpoint_file):
    """
    Linux forensics documentation — fills the Windows bias in the
    current DFIR coverage. /proc forensics, audit daemon, systemd
    journal, bash artifacts, Linux memory forensics.
    """
    c = cfg["scrapers"].get("linux_forensics", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/meirwah/awesome-incident-response",
         "./data/repos/awesome-ir",
         "Awesome Incident Response Resources"),
        ("https://github.com/tclahr/uac",
         "./data/repos/uac",
         "Unix-like Artifacts Collector Documentation"),
    ], "linux_forensics", raw_file, checkpoint_file, "linux_forensics_done")
    print(f"[linux_forensics] Done. {n} files.")


def run_ir_playbooks(cfg, raw_file, checkpoint_file):
    """
    Incident response playbooks and runbooks.
    Fills the operational IR gap: concrete decision trees, triage
    checklists, containment steps, communication templates for
    ransomware, BEC, data breach, insider threat, phishing.
    """
    c = cfg["scrapers"].get("ir_playbooks", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/certsocietegenerale/IRM",
         "./data/repos/irm-playbooks",
         "Incident Response Methodologies (CERT SG)"),
        ("https://github.com/counteractive/incident-response-plan-template",
         "./data/repos/ir-plan-template",
         "Incident Response Plan Template"),
        ("https://github.com/swisskyrepo/InternalAllTheThings",
         "./data/repos/internal-all-things",
         "Internal Network Pentest and IR Reference"),
    ], "ir_playbooks", raw_file, checkpoint_file, "ir_playbooks_done")
    print(f"[ir_playbooks] Done. {n} files.")


def run_sans_dfir(cfg, raw_file, checkpoint_file):
    """
    SANS Digital Forensics and Incident Response blog.
    Targeted scrape of DFIR-tagged posts only. High quality
    practitioner content from SANS faculty and course alumni.
    """
    c = cfg["scrapers"].get("sans_dfir", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 2.0)

    n = scrape_blog(
        "https://www.sans.org/blog/",
        "sans_dfir",
        "SANS DFIR Practitioner Content",
        "sans_dfir_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=30,
        link_filter=lambda h: "sans.org/blog/" in h and len(h) > 40,
    )
    print(f"[sans_dfir] Done. {n} posts.")


# ================================================================
# VULNERABILITY RESEARCH METHODOLOGY SOURCES
# ================================================================

def run_ncc_group_research(cfg, raw_file, checkpoint_file):
    """
    NCC Group research blog — exceptional quality, broad coverage.
    Cryptographic implementation audits, hardware security, binary
    exploitation, web research. Full public audit reports.
    More detailed than any other commercial security firm's public output.
    """
    c = cfg["scrapers"].get("ncc_group_research", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://research.nccgroup.com/",
        "ncc_group_research",
        "NCC Group Security Research",
        "ncc_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=50,
        link_filter=lambda h: "research.nccgroup.com" in h and
                               any(y in h for y in ["2019","2020","2021","2022","2023","2024","2025"]),
    )
    print(f"[ncc] Done. {n} posts.")


def run_synacktiv_blog(cfg, raw_file, checkpoint_file):
    """
    Synacktiv blog — French offensive security research.
    Automotive hacking, hardware RE, binary exploitation on embedded
    platforms, web application research. Unique geographic and technical
    perspective not found in US-centric sources.
    """
    c = cfg["scrapers"].get("synacktiv_blog", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://www.synacktiv.com/en/publications.html",
        "synacktiv_blog",
        "Synacktiv Offensive Security Research",
        "synacktiv_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        selectors=["article", ".publication-content", "main", ".content"],
        link_filter=lambda h: "synacktiv.com" in h and "/publications" in h and len(h) > 45,
    )
    print(f"[synacktiv] Done. {n} posts.")


def run_zdi_blog(cfg, raw_file, checkpoint_file):
    """
    Zero Day Initiative (ZDI) blog — Trend Micro's vuln broker blog.
    Unique perspective: they analyze thousands of submitted bugs and
    write up root cause patterns across vulnerability classes. Also
    publishes vendor-specific vulnerability analysis and disclosure writeups.
    """
    c = cfg["scrapers"].get("zdi_blog", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://www.zerodayinitiative.com/blog/",
        "zdi_blog",
        "Zero Day Initiative Vulnerability Research",
        "zdi_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=30,
        link_filter=lambda h: "zerodayinitiative.com/blog" in h and len(h) > 45,
    )
    print(f"[zdi] Done. {n} posts.")


def run_orange_tsai_blog(cfg, raw_file, checkpoint_file):
    """
    Orange Tsai / Devcore blog — web and enterprise vulnerability research.
    ProxyLogon, ProxyShell, SSRF chains through enterprise products.
    Each post introduces or deeply analyzes a vulnerability class in
    enterprise software. Low volume, exceptional quality.
    """
    c = cfg["scrapers"].get("orange_tsai_blog", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 2.0)

    for base_url, cp_key, label in [
        ("https://blog.orange.tw/", "orange_done", "Orange Tsai Vulnerability Research"),
        ("https://devco.re/blog/", "devcore_done", "Devcore Security Research"),
    ]:
        n = scrape_blog(base_url, "orange_tsai_blog", label, cp_key,
                        raw_file, checkpoint_file, delay=delay, max_pages=20)
        print(f"[orange_tsai] {label}: {n} posts.")


def run_quarkslab_blog(cfg, raw_file, checkpoint_file):
    """
    Quarkslab blog — reverse engineering and crypto implementation attacks.
    Posts on attacking real cryptographic implementations in deployed
    software, firmware RE, binary analysis methodology.
    """
    c = cfg["scrapers"].get("quarkslab_blog", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://blog.quarkslab.com/",
        "quarkslab_blog",
        "Quarkslab Reverse Engineering and Crypto Research",
        "quarkslab_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        link_filter=lambda h: "quarkslab.com" in h and len(h) > 35,
    )
    print(f"[quarkslab] Done. {n} posts.")


def run_certcc_vulnerability_notes(cfg, raw_file, checkpoint_file):
    """
    CERT/CC Vulnerability Notes Database — Carnegie Mellon.
    ~10,000 structured vulnerability analyses written by CERT/CC analysts.
    Deeper than NVD: explains the actual flaw, affected components,
    and mitigation in prose. Different voice from the same vulnerabilities.
    """
    c = cfg["scrapers"].get("certcc_vulnotes", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 0.8)
    max_notes = c.get("max_notes", 10000)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("certcc_done", []))

    # CERT/CC provides a full JSON feed
    feed_url = "https://kb.cert.org/vuls/api/vulnerabilities/?format=json&limit=100"
    batch = []
    page_url = feed_url

    with tqdm(total=max_notes, desc="CERT/CC vuln notes") as pbar:
        while page_url and len(done) < max_notes:
            r = safe_get(page_url, timeout=30)
            if not r: break
            try:
                data = r.json()
            except Exception: break

            for vuln in data.get("results", []):
                vid = str(vuln.get("id", ""))
                if not vid or vid in done: continue

                vuid   = vuln.get("vuln_id", "")
                name   = vuln.get("name", "")
                desc   = vuln.get("description", "") or ""
                impact = vuln.get("impact", "") or ""
                sol    = vuln.get("resolution", "") or ""
                refs   = [r.get("url","") for r in (vuln.get("references") or [])[:3]]
                cvss   = str(vuln.get("cvss_score","")) or ""
                cves   = ", ".join(vuln.get("cve_ids") or [])

                if len(desc) < 50: done.add(vid); continue

                parts = [f"CERT/CC Vulnerability Note: {vuid}",
                         f"Title: {name}"]
                if cves: parts.append(f"CVEs: {cves}")
                if cvss: parts.append(f"CVSS: {cvss}")
                parts.append(f"\nDescription:\n{desc}")
                if impact: parts.append(f"\nImpact:\n{impact[:600]}")
                if sol:    parts.append(f"\nResolution:\n{sol[:600]}")
                if refs:   parts.append(f"\nReferences: {'; '.join(refs)}")

                batch.append({"source": "certcc_vulnotes", "id": vuid,
                              "url": f"https://kb.cert.org/vuls/id/{vuid}",
                              "text": "\n".join(parts)})
                done.add(vid); pbar.update(1)

            if len(batch) >= 500:
                append_jsonl(raw_file, batch)
                cp["certcc_done"] = list(done)
                save_checkpoint(checkpoint_file, cp)
                batch = []

            page_url = data.get("next")
            time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["certcc_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[certcc] Done. {len(done)} vulnerability notes.")


def run_qualys_research(cfg, raw_file, checkpoint_file):
    """
    Qualys Security Labs blog — deep Linux and enterprise vulnerability research.
    PwnKit, Sequoia, Baron Samedit writeups are technical masterpieces
    on Unix privilege escalation. Full root cause and exploitation analysis.
    """
    c = cfg["scrapers"].get("qualys_research", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    n = scrape_blog(
        "https://blog.qualys.com/vulnerabilities-threat-research",
        "qualys_research",
        "Qualys Security Labs Vulnerability Research",
        "qualys_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=30,
        link_filter=lambda h: "qualys.com/blog" in h and len(h) > 55,
    )
    print(f"[qualys] Done. {n} posts.")


def run_portswigger_research(cfg, raw_file, checkpoint_file):
    """
    James Kettle / PortSwigger research papers.
    The methodology papers behind HTTP request smuggling, web cache
    poisoning, prototype pollution, browser-powered attacks.
    Distinct from the Academy teaching content — these are the original
    research papers showing how new vulnerability classes are discovered.
    """
    c = cfg["scrapers"].get("portswigger_research", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("ps_research_done", []))

    BASE = "https://portswigger.net"
    r = safe_get(f"{BASE}/research")
    if not r: return

    soup = BeautifulSoup(r.text, "html.parser")
    paper_urls = []
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if "/research/" in href and href != "/research" and "/research/alert" not in href:
            full = BASE + href if href.startswith("/") else href
            if full not in paper_urls: paper_urls.append(full)

    batch = []
    for url in tqdm([u for u in paper_urls if u not in done], desc="PortSwigger Research"):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one(".research-content, article, main")
        text = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({"source": "portswigger_research", "title": title,
                          "url": url,
                          "text": f"Web Vulnerability Discovery Research: {title}\n\n{text[:7000]}"})
        done.add(url)
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["ps_research_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[portswigger_research] Done. {len(done)} papers.")


def run_ret2_curriculum(cfg, raw_file, checkpoint_file):
    """
    ret2 systems binary exploitation curriculum + RPISEC MBE course.
    Systematic binary exploitation taught as a curriculum with
    methodological progression rather than individual writeups.
    """
    c = cfg["scrapers"].get("ret2_curriculum", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/ret2school/ret2.fr",
         "./data/repos/ret2school",
         "ret2 Binary Exploitation Curriculum"),
    ], "ret2_curriculum", raw_file, checkpoint_file, "ret2_done")
    print(f"[ret2] Done. {n} files.")


def run_p0_issue_tracker(cfg, raw_file, checkpoint_file):
    """
    Google Project Zero issue tracker (public issues only).
    Shows the raw vulnerability research process: initial report,
    PoC development, vendor interaction, exploitation development.
    Complements the polished blog posts with working research artifacts.
    """
    c = cfg["scrapers"].get("p0_issue_tracker", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.0)
    max_issues = c.get("max_issues", 2000)
    cp = load_checkpoint(checkpoint_file)
    done = set(cp.get("p0_issues_done", []))

    # Public P0 issues via Chromium bug tracker
    BASE = "https://bugs.chromium.org/p/project-zero/issues"
    r = safe_get(f"{BASE}/list?can=1&q=&colspec=ID+Type+Status+Priority+Milestone+Owner+Summary&sort=-id")
    if not r:
        print("[p0_issues] Cannot access issue tracker."); return

    soup = BeautifulSoup(r.text, "html.parser")
    issue_ids = []
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        m = re.search(r"/issues/detail\?id=(\d+)", href)
        if m and m.group(1) not in issue_ids:
            issue_ids.append(m.group(1))

    new_ids = [i for i in issue_ids[:max_issues] if i not in done]
    batch = []
    for iid in tqdm(new_ids, desc="P0 issues"):
        url = f"{BASE}/detail?id={iid}"
        r = safe_get(url)
        if not r: done.add(iid); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one(".issue-title, h3")
        title = title_e.get_text(strip=True) if title_e else f"Issue #{iid}"
        comments = soup.select(".comments-item, .comment-content")
        texts = [c.get_text("\n", strip=True) for c in comments[:5]]
        combined = "\n\n---\n\n".join(texts)
        if len(combined) > 300:
            batch.append({"source": "p0_issue_tracker", "id": iid,
                          "url": url, "title": title,
                          "text": f"Project Zero Vulnerability Research: {title}\n\n{combined[:6000]}"})
        done.add(iid)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["p0_issues_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["p0_issues_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)
    print(f"[p0_issues] Done. {len(done)} issues.")


# ================================================================
# NEW GAP SOURCES
# ================================================================

def run_browser_security(cfg, raw_file, checkpoint_file):
    """
    Browser exploitation and security research.
    WebKit security blog, Firefox security blog, browser RE repos.
    V8/SpiderMonkey/JavaScriptCore vulnerability classes, JIT bugs,
    sandbox escape techniques, extension security.
    """
    c = cfg["scrapers"].get("browser_security", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    # Blog posts
    for base, cp_key, label in [
        ("https://webkit.org/blog/", "webkit_done",
         "WebKit Browser Security Research"),
        ("https://hacks.mozilla.org/", "mozilla_hacks_done",
         "Mozilla Firefox Security Research"),
        ("https://v8.dev/blog/", "v8_done",
         "V8 JavaScript Engine Security and Internals"),
    ]:
        n = scrape_blog(base, "browser_security", label, cp_key,
                        raw_file, checkpoint_file, delay=delay, max_pages=20)
        print(f"[browser_sec] {label}: {n}")

    # Repos
    n = clone_many([
    ], "browser_security", raw_file, checkpoint_file, "browser_repos_done")
    print(f"[browser_sec] Repos: {n} files.")


def run_fileless_malware(cfg, raw_file, checkpoint_file):
    """
    Fileless malware and memory-only attack techniques.
    Process hollowing, reflective DLL injection, PowerShell-based
    attacks, WMI persistence, living-in-memory tradecraft.
    Red Canary and SpecterOps publish the best content on this.
    """
    c = cfg["scrapers"].get("fileless_malware", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    # Red Canary blog
    n = scrape_blog(
        "https://redcanary.com/blog/",
        "fileless_malware",
        "Red Canary Threat Detection Research",
        "redcanary_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=30,
        link_filter=lambda h: "redcanary.com/blog/" in h and len(h) > 35,
    )
    print(f"[fileless] Red Canary: {n}")

    # SpecterOps blog
    n = scrape_blog(
        "https://posts.specterops.io/",
        "fileless_malware",
        "SpecterOps Offensive Research",
        "specterops_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
    )
    print(f"[fileless] SpecterOps: {n}")

    # Repos
    n2 = clone_many([
    ], "fileless_malware", raw_file, checkpoint_file, "fileless_repos_done")
    print(f"[fileless] Repos: {n2} files.")


def run_edr_evasion(cfg, raw_file, checkpoint_file):
    """
    EDR/XDR evasion methodology — red team tradecraft.
    Direct syscalls, AMSI bypass, ETW patching, PPL abuse,
    unhooking, process injection evasion, sandbox evasion.
    Published research from GitHub repos and security blogs.
    """
    c = cfg["scrapers"].get("edr_evasion", {})
    if not c.get("enabled", True): return

    n = clone_many([
    ], "edr_evasion", raw_file, checkpoint_file, "edr_evasion_done")
    print(f"[edr_evasion] Done. {n} files.")


def run_soc_workflow(cfg, raw_file, checkpoint_file):
    """
    Security operations center workflow and IR procedures.
    Alert triage, escalation, playbooks, SOC metrics, analyst workflow.
    The gap between knowing security and operating a SOC day-to-day.
    """
    c = cfg["scrapers"].get("soc_workflow", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    # SOC Prime blog
    n = scrape_blog(
        "https://socprime.com/blog/",
        "soc_workflow",
        "SOC Operations and Detection Engineering",
        "socprime_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        link_filter=lambda h: "socprime.com/blog/" in h and len(h) > 35,
    )
    print(f"[soc] SOC Prime: {n}")

    # Repos
    n2 = clone_many([
    ], "soc_workflow", raw_file, checkpoint_file, "soc_done")
    print(f"[soc] Repos: {n2} files.")


def run_siem_implementation(cfg, raw_file, checkpoint_file):
    """
    SIEM implementation and log analysis — Sentinel, Elastic, Splunk.
    Writing KQL for Sentinel, SPL for Splunk, EQL for Elastic.
    Configuring log sources, tuning alerts, building detection content.
    """
    c = cfg["scrapers"].get("siem_implementation", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/Azure/Azure-Sentinel",
         "./data/repos/azure-sentinel",
         "Microsoft Sentinel Detection Rules and Playbooks"),
        ("https://github.com/elastic/detection-rules",
         "./data/repos/elastic-detection-rules",
         "Elastic SIEM Detection Rules"),
    ], "siem_implementation", raw_file, checkpoint_file, "siem_done")
    print(f"[siem] Done. {n} files.")


def run_post_quantum_crypto(cfg, raw_file, checkpoint_file):
    """
    Post-quantum cryptography — NIST PQC standards and implementation.
    CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+. Migration guidance,
    implementation security, hybrid approaches.
    """
    c = cfg["scrapers"].get("post_quantum_crypto", {})
    if not c.get("enabled", True): return

    n = clone_many([
        ("https://github.com/open-quantum-safe/liboqs",
         "./data/repos/liboqs",
         "Open Quantum Safe Library Documentation"),
        ("https://github.com/pq-crystals/kyber",
         "./data/repos/kyber",
         "CRYSTALS-Kyber Reference Implementation and Docs"),
        ("https://github.com/pq-crystals/dilithium",
         "./data/repos/dilithium",
         "CRYSTALS-Dilithium Reference Implementation and Docs"),
    ], "post_quantum_crypto", raw_file, checkpoint_file, "pqc_done")
    print(f"[pqc] Done. {n} files.")


def run_serverless_security(cfg, raw_file, checkpoint_file):
    """
    Serverless security — Lambda, Azure Functions, Google Cloud Functions.
    Event injection, permission escalation, cold-start attacks,
    function URL abuse, serverless-specific attack patterns.
    """
    c = cfg["scrapers"].get("serverless_security", {})
    if not c.get("enabled", True): return

    n = clone_many([
    ], "serverless_security", raw_file, checkpoint_file, "serverless_done")
    print(f"[serverless] Done. {n} files.")


def run_purple_team(cfg, raw_file, checkpoint_file):
    """
    Purple team methodology — adversary simulation with feedback loops.
    PTEF (Purple Team Exercise Framework), detection coverage measurement,
    ATT&CK gap analysis, tabletop exercise methodology.
    """
    c = cfg["scrapers"].get("purple_team", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    # AttackIQ Academy blog
    n = scrape_blog(
        "https://www.attackiq.com/blog/",
        "purple_team",
        "AttackIQ Purple Team Methodology",
        "attackiq_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        link_filter=lambda h: "attackiq.com/blog/" in h and len(h) > 35,
    )
    print(f"[purple] AttackIQ: {n}")

    n2 = clone_many([
    ], "purple_team", raw_file, checkpoint_file, "purple_done")
    print(f"[purple] Repos: {n2} files.")


def run_crypto_impl_bugs(cfg, raw_file, checkpoint_file):
    """
    Cryptographic implementation bugs — timing attacks, nonce reuse,
    padding oracle, weak RNG. The gap between IACR theory and
    finding actual implementation flaws in deployed libraries.
    NCC Group and Trail of Bits both publish full crypto audit reports.
    """
    c = cfg["scrapers"].get("crypto_impl_bugs", {})
    if not c.get("enabled", True): return

    n = clone_many([
    ], "crypto_impl_bugs", raw_file, checkpoint_file, "crypto_impl_done")
    print(f"[crypto_impl] Done. {n} files.")


def run_binary_auditing(cfg, raw_file, checkpoint_file):
    """
    Binary code auditing methodology — systematic approaches to finding
    vulnerabilities in compiled binaries. IDA/Ghidra scripting,
    automated analysis, pattern recognition in disassembly.
    """
    c = cfg["scrapers"].get("binary_auditing", {})
    if not c.get("enabled", True): return

    n = clone_many([
    ], "binary_auditing", raw_file, checkpoint_file, "binary_audit_done")
    print(f"[binary_auditing] Done. {n} files.")


def run_rootkit_uefi(cfg, raw_file, checkpoint_file):
    """
    Rootkits and UEFI bootkit security research.
    ESET UEFI threat research (public posts), NSA UEFI guidance,
    GitHub UEFI exploit repos, bootloader security analysis.
    """
    c = cfg["scrapers"].get("rootkit_uefi", {})
    if not c.get("enabled", True): return
    delay = c.get("delay_seconds", 1.5)

    # ESET research blog (UEFI/rootkit posts)
    n = scrape_blog(
        "https://www.welivesecurity.com/en/eset-research/",
        "rootkit_uefi",
        "ESET Rootkit and UEFI Threat Research",
        "eset_uefi_done",
        raw_file, checkpoint_file,
        delay=delay, max_pages=20,
        link_filter=lambda h: "welivesecurity.com" in h and len(h) > 45,
    )
    print(f"[rootkit] ESET: {n}")

    n2 = clone_many([
        ("https://github.com/chipsec/chipsec",
         "./data/repos/chipsec",
         "Intel CHIPSEC Platform Security Assessment"),
    ], "rootkit_uefi", raw_file, checkpoint_file, "rootkit_done")
    print(f"[rootkit] Repos: {n2} files.")
