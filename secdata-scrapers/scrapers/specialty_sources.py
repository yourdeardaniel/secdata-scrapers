"""
Specialty sources — 20 high-quality additions across four underrepresented domains:

CRYPTOGRAPHY & CRYPTO ATTACKS (5 sources)
  1.  IACR ePrint Archive        — thousands of academic cryptography papers
  2.  CryptoHack writeups        — challenge writeups teaching real crypto attacks
  3.  Cryptopals GitHub repos    — challenge solutions with detailed explanations
  4.  MysteryTwister C3          — crypto challenge archive with solutions
  5.  Dan Boneh Stanford crypto  — public lecture notes and course materials

NETWORK SECURITY (4 sources)
  6.  Cloudflare Blog            — DDoS, BGP, DNS, TLS research at internet scale
  7.  RIPE NCC security blog     — BGP hijacking, routing security, DNS research
  8.  Zeek/Bro documentation     — network analysis scripts and detection logic
  9.  Suricata rule documentation — IDS/IPS rules with attack context

RED / BLUE TEAM (6 sources)
  10. Atomic Red Team            — MITRE ATT&CK-mapped adversary simulation tests
  11. LOLBAS project             — Living Off the Land Binaries attack techniques
  12. GTFOBins                   — Unix binary privilege escalation/bypass catalog
  13. MITRE D3FEND               — defensive countermeasures knowledge graph
  14. Threat Hunter Playbook     — hypothesis-driven threat hunting procedures
  15. LOLDrivers                 — vulnerable/malicious Windows driver database

CLOUD SECURITY (5 sources)
  16. flaws.cloud + flaws2.cloud — AWS security challenge writeups (Scott Piper)
  17. CloudGoat scenarios        — Rhino Security vulnerable-by-design AWS envs
  18. Wiz research blog          — cloud vulnerability research at scale
  19. Cloud Security Alliance    — CSA guidelines, CCM, cloud threat reports
  20. CloudSecDocs               — cloud security attack/defense documentation
"""
import os
import io
import re
import time
import subprocess
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    parse_html, extract_pdf_text,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


# ================================================================
# CRYPTOGRAPHY SOURCES
# ================================================================

def run_iacr_eprint(cfg, raw_file, checkpoint_file):
    """
    IACR ePrint Archive — cryptography research papers.
    Fetches the full paper listing and downloads abstracts + metadata.
    Full PDFs downloaded for the most recent/cited papers.
    """
    c = cfg["scrapers"].get("iacr_eprint", {})
    if not c.get("enabled", True):
        print("[iacr] Disabled."); return

    delay    = c.get("delay_seconds", 2.0)
    max_papers = c.get("max_papers", 5000)
    cp       = load_checkpoint(checkpoint_file)
    done_ids = set(cp.get("iacr_done", []))

    print(f"[iacr] Fetching IACR ePrint listing...")
    # IACR provides a listing feed
    listing_url = "https://eprint.iacr.org/rss/rss.xml"
    r = safe_get(listing_url, timeout=30)

    paper_ids = set()
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for item in soup.find_all("item"):
            link = item.find("link")
            if link and link.text:
                # IDs look like https://eprint.iacr.org/2023/1234
                m = re.search(r"eprint\.iacr\.org/(\d{4}/\d+)", link.text)
                if m:
                    paper_ids.add(m.group(1))

    # Also scrape listing pages for more papers
    for year in range(2015, 2026):
        if len(paper_ids) >= max_papers:
            break
        r2 = safe_get(f"https://eprint.iacr.org/search?q=&year={year}&category=all", timeout=20)
        if not r2:
            continue
        soup2 = BeautifulSoup(r2.text, "html.parser")
        for a in soup2.select("a[href]"):
            href = a.get("href", "")
            m = re.search(r"/(\d{4}/\d+)$", href)
            if m:
                paper_ids.add(m.group(1))
        time.sleep(delay)

    new_ids = [pid for pid in list(paper_ids)[:max_papers] if pid not in done_ids]
    print(f"[iacr] {len(new_ids)} new papers to fetch.")

    batch = []
    for pid in tqdm(new_ids, desc="IACR ePrint"):
        url = f"https://eprint.iacr.org/{pid}"
        r = safe_get(url, timeout=20)
        if not r:
            done_ids.add(pid)
            continue

        soup = BeautifulSoup(r.text, "html.parser")

        title_e = soup.select_one("h2, h1, .papertitle")
        title   = title_e.get_text(strip=True) if title_e else ""

        abstract_e = soup.select_one(".abstract, #abstract, [id*='abstract']")
        abstract   = abstract_e.get_text("\n", strip=True) if abstract_e else ""

        authors_e = soup.select_one(".authors, .paperauthors")
        authors   = authors_e.get_text(strip=True) if authors_e else ""

        cats_e = soup.select(".category, .keyword")
        keywords = ", ".join(c.get_text(strip=True) for c in cats_e)

        if not abstract or len(abstract) < 80:
            done_ids.add(pid)
            time.sleep(delay)
            continue

        # detect if it's a crypto attack paper by keywords
        attack_keywords = ["attack", "break", "collision", "forgery", "fault",
                           "side-channel", "timing", "differential", "linear",
                           "algebraic", "lattice", "cryptanalysis", "weakness",
                           "vulnerability", "exploit", "key recovery"]
        is_attack = any(kw in abstract.lower() or kw in title.lower()
                        for kw in attack_keywords)

        label = "Cryptographic Attack Research" if is_attack else "Cryptography Research"

        parts = [
            f"IACR ePrint {pid}: {title}",
            f"Authors: {authors}" if authors else "",
            f"Keywords: {keywords}" if keywords else "",
            f"\nAbstract:\n{abstract}",
        ]

        batch.append({
            "source":  "iacr_eprint",
            "id":      pid,
            "url":     url,
            "title":   title,
            "is_attack": is_attack,
            "text":    "\n".join(p for p in parts if p),
        })
        done_ids.add(pid)

        if len(batch) >= 200:
            append_jsonl(raw_file, batch)
            cp["iacr_done"] = list(done_ids)
            save_checkpoint(checkpoint_file, cp)
            batch = []

        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["iacr_done"] = list(done_ids)
        save_checkpoint(checkpoint_file, cp)

    print(f"[iacr] Done. {len(done_ids)} papers.")


def run_cryptohack(cfg, raw_file, checkpoint_file):
    """
    CryptoHack challenge writeups and blog.
    Covers real crypto attacks: RSA, ECC, AES, hash functions, protocols.
    """
    c = cfg["scrapers"].get("cryptohack", {})
    if not c.get("enabled", True):
        print("[cryptohack] Disabled."); return

    delay = c.get("delay_seconds", 1.5)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("cryptohack_done", []))

    BASE = "https://cryptohack.org"
    blog_urls = []

    # Blog posts
    for page in range(1, 20):
        url = f"{BASE}/blog/" if page == 1 else f"{BASE}/blog/?page={page}"
        r = safe_get(url)
        if not r:
            break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/blog/" in href and href != "/blog/" and href not in blog_urls:
                full = BASE + href if href.startswith("/") else href
                blog_urls.append(full)
                found = True
        if not found:
            break
        time.sleep(delay)

    # Challenge categories for writeup scraping
    challenge_cats = [
        "/courses/", "/challenges/", "/general/", "/crypto-on-the-web/",
        "/elliptic-curves/", "/lattices/", "/post-quantum/",
    ]
    for cat in challenge_cats:
        r = safe_get(BASE + cat)
        if not r:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if href.startswith("/") and href not in blog_urls:
                blog_urls.append(BASE + href)
        time.sleep(delay)

    new_urls = [u for u in blog_urls if u not in done]
    print(f"[cryptohack] {len(new_urls)} pages to scrape.")

    batch = []
    for url in tqdm(new_urls, desc="CryptoHack"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2.title, .challenge-title")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .challenge-body, .blog-content, main")
        text    = body_e.get_text("\n", strip=True) if body_e else ""

        # Look for code blocks which are especially valuable
        code_blocks = [c.get_text() for c in (body_e or soup).select("pre, code")]

        if len(text) > 200:
            batch.append({
                "source": "cryptohack",
                "title":  title,
                "url":    url,
                "text":   f"CryptoHack — {title}:\n\n{text[:7000]}",
            })
        done.add(url)

        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["cryptohack_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["cryptohack_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[cryptohack] Done. {len(done)} pages.")


def run_cryptopals(cfg, raw_file, checkpoint_file):
    """
    Cryptopals challenge solutions from GitHub.
    These repos typically contain detailed explanations of:
    CBC padding oracle, MT19937, RSA attacks, stream cipher reuse, etc.
    """
    c = cfg["scrapers"].get("cryptopals", {})
    if not c.get("enabled", True):
        print("[cryptopals] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("cryptopals_done"):
        print("[cryptopals] Already done."); return

    # Top-quality cryptopals solution repos with explanations
    repos = [
        ("https://github.com/ricpacca/cryptopals",      "./data/repos/cryptopals_ricpacca"),
        ("https://github.com/akalin/cryptopals-python3","./data/repos/cryptopals_akalin"),
        ("https://github.com/crvdgc/cryptopals-haskell","./data/repos/cryptopals_crvdgc"),
        ("https://github.com/tmvst/cryptopals",         "./data/repos/cryptopals_tmvst"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "cryptopals", repo_url)
            # also grab Python files with docstrings — they explain the attacks
            for root, dirs, files in os.walk(dest):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                        # only include files with substantial docstrings/comments
                        comments = re.findall(r'"""(.*?)"""', text, re.DOTALL)
                        comment_text = "\n".join(comments)
                        if len(comment_text) > 200:
                            title = fname.replace(".py","").replace("_"," ")
                            docs.append({
                                "source": "cryptopals",
                                "file":   os.path.relpath(fpath, dest),
                                "title":  f"Cryptopals: {title}",
                                "url":    repo_url,
                                "text":   f"Cryptopals Attack Solution — {title}:\n\n{text[:6000]}",
                            })
                    except Exception:
                        pass
            all_docs.extend(docs)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[cryptopals] {len(all_docs)} files saved.")

    cp["cryptopals_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_dan_boneh_crypto(cfg, raw_file, checkpoint_file):
    """
    Dan Boneh's cryptography course — Stanford public materials.
    Covers: block ciphers, stream ciphers, MAC, authenticated encryption,
    public key crypto, digital signatures, zero-knowledge proofs.
    """
    c = cfg["scrapers"].get("dan_boneh_crypto", {})
    if not c.get("enabled", True):
        print("[boneh] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("boneh_done"):
        print("[boneh] Already done."); return

    delay = c.get("delay_seconds", 2.0)

    # Public lecture slides and notes
    repos = [
        ("https://github.com/crypto-stanford/crypto-notes", "./data/repos/boneh-notes"),
        ("https://github.com/jmsdnns/cryptominiproject",    "./data/repos/crypto-mini"),
    ]
    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "dan_boneh_crypto", repo_url)
            all_docs.extend(docs)

    # Also scrape the public Coursera-based resources and crypto.stanford.edu
    pages = [
        "https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf",
    ]
    for url in pages:
        r = safe_get(url, timeout=60)
        if r and url.endswith(".pdf"):
            text = extract_pdf_text(r.content, max_pages=50)
            if len(text) > 500:
                all_docs.append({
                    "source": "dan_boneh_crypto",
                    "title":  "A Graduate Course in Applied Cryptography — Boneh & Shoup",
                    "url":    url,
                    "text":   text[:10000],
                })
        time.sleep(delay)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[boneh] {len(all_docs)} resources saved.")

    cp["boneh_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_mystery_twister(cfg, raw_file, checkpoint_file):
    """
    MysteryTwister C3 — crypto challenge archive.
    Wide range of classical and modern crypto attack challenges.
    """
    c = cfg["scrapers"].get("mystery_twister", {})
    if not c.get("enabled", True):
        print("[mtc3] Disabled."); return

    delay = c.get("delay_seconds", 2.0)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("mtc3_done", []))

    BASE = "https://www.mysterytwisterc3.org"
    r = safe_get(f"{BASE}/en/challenges/")
    if not r:
        print("[mtc3] Site unreachable.")
        return

    soup = BeautifulSoup(r.text, "html.parser")
    challenge_urls = []
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if "/challenges/" in href and href not in challenge_urls:
            full = BASE + href if href.startswith("/") else href
            challenge_urls.append(full)

    new_urls = [u for u in challenge_urls if u not in done]
    print(f"[mtc3] {len(new_urls)} challenges to scrape.")

    batch = []
    for url in tqdm(new_urls, desc="MysteryTwister"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one(".challenge-text, article, main, .content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({
                "source": "mystery_twister",
                "title":  title,
                "url":    url,
                "text":   f"MysteryTwister Crypto Challenge — {title}:\n\n{text[:6000]}",
            })
        done.add(url)

        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["mtc3_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["mtc3_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[mtc3] Done. {len(done)} challenges.")


# ================================================================
# NETWORK SECURITY SOURCES
# ================================================================

def run_cloudflare_blog(cfg, raw_file, checkpoint_file):
    """
    Cloudflare Blog — security and network research at internet scale.
    Covers: DDoS anatomy, BGP hijacking, DNS attacks, TLS vulnerabilities,
    bot detection, zero-day responses, traffic analysis.
    """
    c = cfg["scrapers"].get("cloudflare_blog", {})
    if not c.get("enabled", True):
        print("[cloudflare_blog] Disabled."); return

    delay     = c.get("delay_seconds", 1.5)
    max_pages = c.get("max_pages", 30)
    cp        = load_checkpoint(checkpoint_file)
    done      = set(cp.get("cloudflare_blog_done", []))

    security_tags = [
        "security", "ddos", "vulnerabilities", "zero-day",
        "network", "dns", "tls", "ssl", "attacks", "threat-intelligence",
        "bgp", "waf", "bot-management", "cryptography",
    ]

    post_urls = []
    for tag in security_tags:
        for page in range(1, 5):
            url = f"https://blog.cloudflare.com/tag/{tag}/" if page == 1 else \
                  f"https://blog.cloudflare.com/tag/{tag}/page/{page}/"
            r = safe_get(url)
            if not r:
                break
            soup = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("article a[href], h2 a[href], h3 a[href]"):
                href = a.get("href", "")
                if "blog.cloudflare.com" in href and href not in post_urls:
                    post_urls.append(href)
                    found = True
            if not found:
                break
            time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    print(f"[cloudflare_blog] {len(new_urls)} posts to scrape.")

    batch = []
    for url in tqdm(new_urls, desc="Cloudflare Blog"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .post-content, main")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "cloudflare_blog",
                "title":  title,
                "url":    url,
                "text":   f"Cloudflare Security Research: {title}\n\n{text[:7000]}",
            })
        done.add(url)

        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["cloudflare_blog_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["cloudflare_blog_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[cloudflare_blog] Done. {len(done)} posts.")


def run_ripe_ncc_blog(cfg, raw_file, checkpoint_file):
    """
    RIPE NCC Security blog — routing security, BGP hijacking, DNS research.
    Authoritative source on internet infrastructure security.
    """
    c = cfg["scrapers"].get("ripe_ncc_blog", {})
    if not c.get("enabled", True):
        print("[ripe] Disabled."); return

    delay = c.get("delay_seconds", 2.0)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("ripe_done", []))

    BASE = "https://labs.ripe.net"
    post_urls = []

    for page in range(1, 20):
        url = f"{BASE}/Members/tag/security/" if page == 1 else \
              f"{BASE}/Members/tag/security/?b_start={( page-1)*20}"
        r = safe_get(url)
        if not r:
            break
        soup  = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/Members/author" in href or "/Members/publication" in href:
                full = BASE + href if href.startswith("/") else href
                if full not in post_urls:
                    post_urls.append(full)
                    found = True
        if not found:
            break
        time.sleep(delay)

    # also scrape RIPE NCC main blog
    r_main = safe_get("https://www.ripe.net/publications/news/")
    if r_main:
        soup = BeautifulSoup(r_main.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/publications/news/" in href and len(href) > 30:
                full = "https://www.ripe.net" + href if href.startswith("/") else href
                if full not in post_urls:
                    post_urls.append(full)

    new_urls = [u for u in post_urls if u not in done]
    print(f"[ripe] {len(new_urls)} articles to scrape.")

    batch = []
    for url in tqdm(new_urls, desc="RIPE NCC"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2.tile")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .document-body, main, .plone-content-body")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 300:
            batch.append({
                "source": "ripe_ncc_blog",
                "title":  title,
                "url":    url,
                "text":   f"RIPE NCC Network Security Research: {title}\n\n{text[:6000]}",
            })
        done.add(url)

        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["ripe_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["ripe_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[ripe] Done. {len(done)} articles.")


def run_zeek_documentation(cfg, raw_file, checkpoint_file):
    """
    Zeek (formerly Bro) network analysis framework documentation.
    Covers: protocol analysis scripts, network forensics, detection logic,
    threat hunting with network data.
    """
    c = cfg["scrapers"].get("zeek_documentation", {})
    if not c.get("enabled", True):
        print("[zeek] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("zeek_done"):
        print("[zeek] Already done."); return

    repos = [
        ("https://github.com/zeek/zeek",         "./data/repos/zeek-main"),
        ("https://github.com/zeek/zeek-docs",    "./data/repos/zeek-docs"),
        ("https://github.com/corelight/zeek-community-id", "./data/repos/zeek-community"),
        ("https://github.com/salesforce/ja3",    "./data/repos/ja3"),
        ("https://github.com/activecm/threat-hunting-labs", "./data/repos/th-labs"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "zeek_documentation", repo_url)
            # also grab Zeek scripting files (.zeek) — self-documenting
            for root, dirs, files in os.walk(dest):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if not fname.endswith(".zeek"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                        if len(text) > 200:
                            docs.append({
                                "source": "zeek_documentation",
                                "file":   os.path.relpath(fpath, dest),
                                "title":  fname.replace(".zeek", ""),
                                "url":    repo_url,
                                "text":   f"Zeek Network Analysis Script:\n\n{text[:5000]}",
                            })
                    except Exception:
                        pass
            all_docs.extend(docs)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[zeek] {len(all_docs)} files saved.")

    cp["zeek_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_suricata_rules(cfg, raw_file, checkpoint_file):
    """
    Suricata IDS/IPS rules and documentation.
    Covers: network-based threat detection, rule writing, protocol anomaly detection.
    Complements Sigma (host-based) with network-layer detection knowledge.
    """
    c = cfg["scrapers"].get("suricata_rules", {})
    if not c.get("enabled", True):
        print("[suricata] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("suricata_done"):
        print("[suricata] Already done."); return

    repos = [
        ("https://github.com/OISF/suricata",                "./data/repos/suricata-main"),
        ("https://github.com/travisbgreen/hunting-rules",    "./data/repos/suricata-hunting"),
        ("https://github.com/ptresearch/AttackDetection",   "./data/repos/suricata-attack"),
        ("https://github.com/jasonish/suricata-trafficid",  "./data/repos/suricata-traffic"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if not ok:
            continue
        docs = extract_md_files(dest, "suricata_rules", repo_url)

        # Parse .rules files — each rule is a training example
        rule_batch = []
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".rules"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    # parse individual rules
                    for rule in content.split("\n"):
                        rule = rule.strip()
                        if not rule or rule.startswith("#"):
                            continue
                        # extract metadata
                        msg_m = re.search(r'msg:"([^"]+)"', rule)
                        msg   = msg_m.group(1) if msg_m else ""
                        sid_m = re.search(r'sid:(\d+)', rule)
                        sid   = sid_m.group(1) if sid_m else ""
                        cve_m = re.findall(r'CVE-\d{4}-\d{4,7}', rule, re.IGNORECASE)
                        if not msg:
                            continue
                        parts = [
                            f"Suricata IDS Rule: {msg}",
                            f"SID: {sid}" if sid else "",
                            f"CVEs: {', '.join(cve_m)}" if cve_m else "",
                            f"Rule file: {fname}",
                            f"\nFull rule:\n{rule[:800]}",
                        ]
                        rule_batch.append({
                            "source": "suricata_rules",
                            "title":  msg,
                            "url":    repo_url,
                            "text":   "\n".join(p for p in parts if p),
                        })
                        if len(rule_batch) >= 500:
                            append_jsonl(raw_file, rule_batch)
                            rule_batch = []
                except Exception:
                    pass

        if rule_batch:
            append_jsonl(raw_file, rule_batch)
        all_docs.extend(docs)

    if all_docs:
        append_jsonl(raw_file, all_docs)

    cp["suricata_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[suricata] Done.")


# ================================================================
# RED / BLUE TEAM SOURCES
# ================================================================

def run_atomic_red_team(cfg, raw_file, checkpoint_file):
    """
    Atomic Red Team by Red Canary — ATT&CK-mapped adversary simulation tests.
    Each atomic test describes an adversary technique with commands,
    detection opportunities, and cleanup procedures.
    Arguably the best red/blue team training resource available publicly.
    """
    c = cfg["scrapers"].get("atomic_red_team", {})
    if not c.get("enabled", True):
        print("[atomic] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("atomic_done"):
        print("[atomic] Already done."); return

    dest = "./data/repos/atomic-red-team"
    ok   = clone_repo("https://github.com/redcanaryco/atomic-red-team", dest)
    if not ok:
        print("[atomic] Clone failed."); return

    # Parse YAML atomic test files — richer than just markdown
    try:
        import yaml as _yaml
        yaml_available = True
    except ImportError:
        yaml_available = False

    all_docs = []
    atomics_dir = os.path.join(dest, "atomics")

    if not os.path.exists(atomics_dir):
        all_docs = extract_md_files(dest, "atomic_red_team",
                                    "https://github.com/redcanaryco/atomic-red-team")
    else:
        for root, dirs, files in os.walk(atomics_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                fpath = os.path.join(root, fname)

                if fname.endswith(".yaml") and yaml_available:
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            data = _yaml.safe_load(f)
                        if not isinstance(data, dict):
                            continue

                        tech_id   = data.get("attack_technique", "")
                        tech_name = data.get("display_name", "")
                        atomic_tests = data.get("atomic_tests", []) or []

                        for test in atomic_tests:
                            tname   = test.get("name", "")
                            tdesc   = test.get("description", "") or ""
                            ttype   = test.get("executor", {}).get("name", "")
                            command = test.get("executor", {}).get("command", "") or ""
                            cleanup = test.get("executor", {}).get("cleanup_command", "") or ""
                            detects = test.get("detection_hint", "") or ""
                            deps    = [d.get("description","") for d in (test.get("dependencies") or [])]
                            platforms = test.get("supported_platforms", [])

                            parts = [
                                f"Atomic Red Team — {tech_id}: {tech_name}",
                                f"Test: {tname}",
                                f"Platforms: {', '.join(platforms)}" if platforms else "",
                                f"Executor: {ttype}" if ttype else "",
                                f"\nDescription:\n{tdesc}" if tdesc else "",
                            ]
                            if command:
                                parts.append(f"\nCommand:\n{command[:800]}")
                            if cleanup:
                                parts.append(f"\nCleanup:\n{cleanup[:300]}")
                            if detects:
                                parts.append(f"\nDetection opportunity:\n{detects}")
                            if deps:
                                parts.append(f"\nDependencies:\n" + "\n".join(deps[:3]))

                            all_docs.append({
                                "source":       "atomic_red_team",
                                "technique_id": tech_id,
                                "title":        f"{tech_id}: {tname}",
                                "url":          f"https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{tech_id}",
                                "text":         "\n".join(p for p in parts if p),
                            })
                    except Exception:
                        pass

                elif fname.endswith(".md"):
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                        if len(text) > 200:
                            title = fname.replace(".md","").replace("-"," ")
                            all_docs.append({
                                "source": "atomic_red_team",
                                "file":   os.path.relpath(fpath, dest),
                                "title":  title,
                                "url":    "https://github.com/redcanaryco/atomic-red-team",
                                "text":   text[:7000],
                            })
                    except Exception:
                        pass

    if all_docs:
        # batch write
        for i in range(0, len(all_docs), 500):
            append_jsonl(raw_file, all_docs[i:i+500])

    cp["atomic_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[atomic] {len(all_docs)} atomic tests saved.")


def run_lolbas(cfg, raw_file, checkpoint_file):
    """
    LOLBAS — Living Off the Land Binaries, Scripts and Libraries.
    Documents Windows binaries that attackers abuse to blend in.
    Each entry describes: what the binary does, how it's abused,
    command examples, and detection opportunities.
    """
    c = cfg["scrapers"].get("lolbas", {})
    if not c.get("enabled", True):
        print("[lolbas] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("lolbas_done"):
        print("[lolbas] Already done."); return

    dest = "./data/repos/lolbas-project"
    ok   = clone_repo("https://github.com/LOLBAS-Project/LOLBAS", dest)
    if not ok:
        print("[lolbas] Clone failed."); return

    try:
        import yaml as _yaml
    except ImportError:
        print("[lolbas] pyyaml not installed."); return

    all_docs = []
    yml_dir  = os.path.join(dest, "yml")
    if not os.path.exists(yml_dir):
        yml_dir = dest

    for root, dirs, files in os.walk(yml_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    data = _yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue

                name        = data.get("Name", "")
                description = data.get("Description", "") or ""
                author      = data.get("Author", "") or ""
                commands    = data.get("Commands", []) or []
                detections  = data.get("Detections", []) or []
                resources   = data.get("Resources", []) or []
                opsec_tips  = data.get("Opsec_Tip", "") or ""

                if not description:
                    continue

                parts = [
                    f"LOLBAS — Living Off the Land: {name}",
                    f"Author: {author}" if author else "",
                    f"\nDescription:\n{description}",
                ]

                for cmd in commands[:5]:
                    cmd_str    = cmd.get("Command", "") or ""
                    cmd_desc   = cmd.get("Description", "") or ""
                    usecase    = cmd.get("Usecase", "") or ""
                    mitre_id   = cmd.get("MitreID", "") or ""
                    operatingsys = cmd.get("OperatingSystem", "") or ""
                    if cmd_str:
                        parts.append(f"\nTechnique — {usecase or cmd_desc}:")
                        if mitre_id:
                            parts.append(f"  ATT&CK: {mitre_id}")
                        if operatingsys:
                            parts.append(f"  OS: {operatingsys}")
                        parts.append(f"  Command: {cmd_str}")

                if detections:
                    det_strs = [d.get("Command","") or d.get("Description","")
                                for d in detections[:3] if isinstance(d, dict)]
                    parts.append(f"\nDetection:\n" + "\n".join(d for d in det_strs if d))

                if opsec_tips:
                    parts.append(f"\nOpSec considerations: {opsec_tips}")

                all_docs.append({
                    "source": "lolbas",
                    "name":   name,
                    "url":    f"https://lolbas-project.github.io/#{name}",
                    "text":   "\n".join(p for p in parts if p),
                })
            except Exception:
                pass

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[lolbas] {len(all_docs)} binaries saved.")

    cp["lolbas_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_gtfobins(cfg, raw_file, checkpoint_file):
    """
    GTFOBins — Unix binary privilege escalation and bypass techniques.
    Every entry documents: what the binary does, how to exploit it for
    shell, file read/write, sudo bypass, SUID abuse, etc.
    """
    c = cfg["scrapers"].get("gtfobins", {})
    if not c.get("enabled", True):
        print("[gtfobins] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("gtfobins_done"):
        print("[gtfobins] Already done."); return

    dest = "./data/repos/GTFOBins"
    ok   = clone_repo("https://github.com/GTFOBins/GTFOBins.github.io", dest)
    if not ok:
        print("[gtfobins] Clone failed."); return

    try:
        import yaml as _yaml
    except ImportError:
        # fallback: parse markdown files
        all_docs = extract_md_files(dest, "gtfobins",
                                    "https://gtfobins.github.io")
        if all_docs:
            append_jsonl(raw_file, all_docs)
        cp["gtfobins_done"] = True
        save_checkpoint(checkpoint_file, cp)
        return

    all_docs = []
    bins_dir = os.path.join(dest, "_gtfobins")
    if not os.path.exists(bins_dir):
        bins_dir = dest

    for root, dirs, files in os.walk(bins_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()

                # GTFOBins .md files have YAML front matter
                if text.startswith("---"):
                    parts = text.split("---", 2)
                    if len(parts) >= 3:
                        try:
                            fm   = _yaml.safe_load(parts[1])
                            body = parts[2].strip()
                        except Exception:
                            fm, body = {}, text
                    else:
                        fm, body = {}, text
                else:
                    fm, body = {}, text

                binary_name = fname.replace(".md", "")
                functions   = fm.get("functions", {}) if isinstance(fm, dict) else {}

                if not functions and len(body) < 100:
                    continue

                doc_parts = [f"GTFOBins — {binary_name}: Unix privilege escalation techniques"]

                for func_name, func_entries in (functions.items() if isinstance(functions, dict) else []):
                    for entry in (func_entries if isinstance(func_entries, list) else []):
                        if not isinstance(entry, dict):
                            continue
                        code    = entry.get("code", "") or ""
                        desc    = entry.get("description", "") or ""
                        ex_code = entry.get("example", {}).get("code","") if isinstance(entry.get("example"),dict) else ""
                        doc_parts.append(f"\n[{func_name.upper()}]")
                        if desc:
                            doc_parts.append(desc)
                        if code:
                            doc_parts.append(f"Command:\n{code[:400]}")

                if body and len(body) > 50:
                    doc_parts.append(f"\n{body[:500]}")

                all_docs.append({
                    "source": "gtfobins",
                    "binary": binary_name,
                    "url":    f"https://gtfobins.github.io/gtfobins/{binary_name}/",
                    "text":   "\n".join(p for p in doc_parts if p),
                })
            except Exception:
                pass

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[gtfobins] {len(all_docs)} binaries saved.")

    cp["gtfobins_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_mitre_d3fend(cfg, raw_file, checkpoint_file):
    """
    MITRE D3FEND — defensive countermeasures knowledge graph.
    The blue-team complement to ATT&CK. Maps defensive techniques
    to offensive techniques they counter. Excellent for training
    a model to reason about defense.
    """
    c = cfg["scrapers"].get("mitre_d3fend", {})
    if not c.get("enabled", True):
        print("[d3fend] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("d3fend_done"):
        print("[d3fend] Already done."); return

    delay = c.get("delay_seconds", 1.5)

    # D3FEND has a public API and a GitHub repo with all techniques
    dest = "./data/repos/d3fend-full-corpus"
    ok   = clone_repo("https://github.com/d3fend/d3fend-ontology", dest)

    all_docs = []
    if ok:
        docs = extract_md_files(dest, "mitre_d3fend",
                                "https://d3fend.mitre.org")
        all_docs.extend(docs)

    # Also scrape technique pages from the website
    r = safe_get("https://d3fend.mitre.org/")
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        technique_urls = []
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/technique/" in href:
                full = "https://d3fend.mitre.org" + href if href.startswith("/") else href
                if full not in technique_urls:
                    technique_urls.append(full)

        for url in tqdm(technique_urls[:200], desc="D3FEND techniques"):
            r2 = safe_get(url)
            if not r2:
                continue
            soup2   = BeautifulSoup(r2.text, "html.parser")
            title_e = soup2.select_one("h1, h2")
            title   = title_e.get_text(strip=True) if title_e else ""
            body_e  = soup2.select_one("main, article, .technique-content")
            text    = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                all_docs.append({
                    "source": "mitre_d3fend",
                    "title":  title,
                    "url":    url,
                    "text":   f"MITRE D3FEND Defensive Technique: {title}\n\n{text[:6000]}",
                })
            time.sleep(delay)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[d3fend] {len(all_docs)} techniques saved.")

    cp["d3fend_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_threat_hunter_playbook(cfg, raw_file, checkpoint_file):
    """
    Threat Hunter Playbook — hypothesis-driven threat hunting.
    Covers: hunting procedures, analytics, data sources, Jupyter notebooks
    with real detection logic. Maps to ATT&CK techniques.
    """
    c = cfg["scrapers"].get("threat_hunter_playbook", {})
    if not c.get("enabled", True):
        print("[thp] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("thp_done"):
        print("[thp] Already done."); return

    dest = "./data/repos/threat-hunter-playbook"
    ok   = clone_repo("https://github.com/OTRF/ThreatHunter-Playbook", dest)
    if not ok:
        print("[thp] Clone failed."); return

    all_docs = extract_md_files(dest, "threat_hunter_playbook",
                                "https://threathunterplaybook.com")

    # Also parse Jupyter notebooks — they contain query logic
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".ipynb"):
                continue
            fpath = os.path.join(root, fname)
            try:
                import json as _json
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    nb = _json.load(f)
                cells = nb.get("cells", [])
                text_parts = []
                for cell in cells:
                    src = cell.get("source", [])
                    src_text = "".join(src) if isinstance(src, list) else src
                    if src_text.strip():
                        text_parts.append(src_text)
                full_text = "\n\n".join(text_parts)
                if len(full_text) > 300:
                    all_docs.append({
                        "source": "threat_hunter_playbook",
                        "file":   os.path.relpath(fpath, dest),
                        "title":  fname.replace(".ipynb", "").replace("-", " ").replace("_", " "),
                        "url":    "https://github.com/OTRF/ThreatHunter-Playbook",
                        "text":   f"Threat Hunting Playbook Notebook:\n\n{full_text[:7000]}",
                    })
            except Exception:
                pass

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[thp] {len(all_docs)} files saved.")

    cp["thp_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_loldrivers(cfg, raw_file, checkpoint_file):
    """
    LOLDrivers — vulnerable and malicious Windows driver database.
    Documents drivers abused by threat actors for BYOVD attacks,
    EDR killing, privilege escalation. Each entry has ATT&CK mapping,
    known threat actors using it, and hashes.
    """
    c = cfg["scrapers"].get("loldrivers", {})
    if not c.get("enabled", True):
        print("[loldrivers] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("loldrivers_done"):
        print("[loldrivers] Already done."); return

    dest = "./data/repos/loldrivers"
    ok   = clone_repo("https://github.com/magicsword-io/LOLDrivers", dest)
    if not ok:
        print("[loldrivers] Clone failed."); return

    try:
        import yaml as _yaml
    except ImportError:
        cp["loldrivers_done"] = True
        save_checkpoint(checkpoint_file, cp)
        return

    all_docs = []
    drivers_dir = os.path.join(dest, "yaml")
    if not os.path.exists(drivers_dir):
        drivers_dir = dest

    for root, dirs, files in os.walk(drivers_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in files:
            if not fname.endswith((".yml", ".yaml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    data = _yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue

                name        = data.get("Name", "") or ""
                description = data.get("Description", "") or ""
                author      = data.get("Author", "") or ""
                created     = data.get("Created", "") or ""
                mitre_ids   = data.get("MitreID", []) or []
                tags        = data.get("Tags", []) or []
                known_vuln  = data.get("KnownVulnerableSamples", []) or []
                resources   = data.get("Resources", []) or []
                detection   = data.get("Detection", []) or []

                if not description:
                    continue

                parts = [
                    f"LOLDrivers — Vulnerable/Malicious Windows Driver: {name}",
                    f"Created: {created}" if created else "",
                    f"ATT&CK: {', '.join(mitre_ids)}" if mitre_ids else "",
                    f"Tags: {', '.join(str(t) for t in tags[:10])}" if tags else "",
                    f"\nDescription:\n{description}",
                ]

                if known_vuln:
                    sample = known_vuln[0] if isinstance(known_vuln[0], dict) else {}
                    sha256 = sample.get("SHA256", "") or ""
                    if sha256:
                        parts.append(f"\nSample SHA256: {sha256}")

                if detection:
                    for det in detection[:2]:
                        if isinstance(det, dict):
                            det_type = det.get("type", "")
                            det_val  = det.get("value", "") or det.get("rule", "")
                            if det_val:
                                parts.append(f"\nDetection ({det_type}):\n{str(det_val)[:400]}")

                if resources:
                    parts.append(f"\nReferences: {'; '.join(str(r) for r in resources[:3])}")

                all_docs.append({
                    "source": "loldrivers",
                    "name":   name,
                    "url":    f"https://www.loldrivers.io/drivers/{fname.replace('.yml','')}",
                    "text":   "\n".join(p for p in parts if p),
                })
            except Exception:
                pass

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[loldrivers] {len(all_docs)} driver entries saved.")

    cp["loldrivers_done"] = True
    save_checkpoint(checkpoint_file, cp)


# ================================================================
# CLOUD SECURITY SOURCES
# ================================================================

def run_flaws_cloud(cfg, raw_file, checkpoint_file):
    """
    flaws.cloud and flaws2.cloud — Scott Piper's AWS security challenges.
    Real misconfiguration scenarios with detailed explanations.
    Covers: S3 bucket misconfiguration, instance metadata abuse,
    IAM privilege escalation, role assumption chains.
    """
    c = cfg["scrapers"].get("flaws_cloud", {})
    if not c.get("enabled", True):
        print("[flaws] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("flaws_done", []))
    delay = c.get("delay_seconds", 1.5)

    sites = [
        ("http://flaws.cloud",  "flaws.cloud AWS Security Challenge"),
        ("http://flaws2.cloud", "flaws2.cloud AWS Security Challenge"),
    ]

    batch = []
    for base_url, site_label in sites:
        # Enumerate levels
        for level in range(1, 11):
            url = f"{base_url}/hint{level}.html"
            r   = safe_get(url)
            if not r:
                url = f"{base_url}/level{level}/"
                r   = safe_get(url)
            if not r or url in done:
                continue

            soup    = BeautifulSoup(r.text, "html.parser")
            title_e = soup.select_one("h1, h2")
            title   = title_e.get_text(strip=True) if title_e else f"Level {level}"
            body_e  = soup.select_one("article, main, .content, body")
            text    = body_e.get_text("\n", strip=True) if body_e else ""

            if len(text) > 200:
                batch.append({
                    "source": "flaws_cloud",
                    "title":  f"{site_label} — {title}",
                    "url":    url,
                    "text":   f"{site_label} — Level {level}: {title}\n\n{text[:7000]}",
                })
            done.add(url)
            time.sleep(delay)

        # Main page and hints
        r = safe_get(base_url)
        if r and base_url not in done:
            soup  = BeautifulSoup(r.text, "html.parser")
            body_e= soup.select_one("article, main, body")
            text  = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                batch.append({
                    "source": "flaws_cloud",
                    "title":  site_label,
                    "url":    base_url,
                    "text":   f"{site_label}\n\n{text[:6000]}",
                })
            done.add(base_url)

    if batch:
        append_jsonl(raw_file, batch)
        cp["flaws_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[flaws] Done. {len(batch)} pages saved.")


def run_cloudgoat(cfg, raw_file, checkpoint_file):
    """
    CloudGoat — Rhino Security Labs' vulnerable-by-design AWS environment.
    Each scenario documents an attack path through cloud misconfigurations.
    Covers: IAM privesc, Lambda exploitation, ECS task abuse, STS,
    Cognito attacks, S3 path traversal.
    """
    c = cfg["scrapers"].get("cloudgoat", {})
    if not c.get("enabled", True):
        print("[cloudgoat] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("cloudgoat_done"):
        print("[cloudgoat] Already done."); return

    repos = [
        ("https://github.com/RhinoSecurityLabs/cloudgoat",        "./data/repos/cloudgoat"),
        ("https://github.com/RhinoSecurityLabs/pacu",             "./data/repos/pacu"),
        ("https://github.com/RhinoSecurityLabs/GHRecon",          "./data/repos/ghrecon"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "cloudgoat", repo_url)
            all_docs.extend(docs)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[cloudgoat] {len(all_docs)} files saved.")

    cp["cloudgoat_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_wiz_research(cfg, raw_file, checkpoint_file):
    """
    Wiz Research blog — cloud vulnerability research at scale.
    Covers: cross-tenant vulnerabilities, cloud provider bugs,
    container escapes, IMDS abuse, supply chain attacks in cloud.
    Some of the most significant cloud security research published.
    """
    c = cfg["scrapers"].get("wiz_research", {})
    if not c.get("enabled", True):
        print("[wiz] Disabled."); return

    delay = c.get("delay_seconds", 1.5)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("wiz_done", []))

    post_urls = []
    for page in range(1, 15):
        url = "https://www.wiz.io/blog" if page == 1 else f"https://www.wiz.io/blog?page={page}"
        r   = safe_get(url)
        if not r:
            break
        soup  = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/blog/" in href and href != "/blog" and "wiz.io" in href:
                full = "https://www.wiz.io" + href if href.startswith("/") else href
                # filter for research posts
                if any(kw in href.lower() for kw in
                       ["research","vulnerability","cve","attack","cloud","aws","azure","gcp",
                        "kubernetes","container","exploit","bypass","critical","security"]):
                    if full not in post_urls:
                        post_urls.append(full)
                        found = True
        if not found:
            break
        time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    print(f"[wiz] {len(new_urls)} research posts to scrape.")

    batch = []
    for url in tqdm(new_urls, desc="Wiz Research"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .blog-content, main, .post-body")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "wiz_research",
                "title":  title,
                "url":    url,
                "text":   f"Wiz Cloud Security Research: {title}\n\n{text[:7000]}",
            })
        done.add(url)

        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["wiz_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["wiz_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[wiz] Done. {len(done)} posts.")


def run_cloud_security_alliance(cfg, raw_file, checkpoint_file):
    """
    Cloud Security Alliance — CSA guidelines, threat reports, and research.
    Covers: Top Threats to Cloud Computing, CCM framework,
    CAIQ, cloud security best practices, zero trust in cloud.
    """
    c = cfg["scrapers"].get("cloud_security_alliance", {})
    if not c.get("enabled", True):
        print("[csa] Disabled."); return

    delay = c.get("delay_seconds", 2.0)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("csa_done", []))

    post_urls = []
    for path in ["/blog/", "/research/", "/artifacts/"]:
        for page in range(1, 10):
            url = f"https://cloudsecurityalliance.org{path}" if page == 1 else \
                  f"https://cloudsecurityalliance.org{path}?page={page}"
            r = safe_get(url)
            if not r:
                break
            soup  = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if ("cloudsecurityalliance.org" in href or href.startswith("/")) and \
                   len(href) > 20 and href not in post_urls:
                    full = "https://cloudsecurityalliance.org" + href \
                           if href.startswith("/") else href
                    post_urls.append(full)
                    found = True
            if not found:
                break
            time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    print(f"[csa] {len(new_urls)} pages to scrape.")

    batch = []
    for url in tqdm(new_urls[:500], desc="CSA"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2.entry-title")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .entry-content, main, .post-content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 300:
            batch.append({
                "source": "cloud_security_alliance",
                "title":  title,
                "url":    url,
                "text":   f"Cloud Security Alliance: {title}\n\n{text[:6000]}",
            })
        done.add(url)

        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["csa_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["csa_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[csa] Done. {len(done)} pages.")


def run_cloudsecdocs(cfg, raw_file, checkpoint_file):
    """
    CloudSecDocs — cloud security attack and defense documentation.
    Covers: AWS/Azure/GCP attack paths, privilege escalation,
    lateral movement in cloud, persistence techniques, defense.
    """
    c = cfg["scrapers"].get("cloudsecdocs", {})
    if not c.get("enabled", True):
        print("[cloudsecdocs] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("cloudsecdocs_done"):
        print("[cloudsecdocs] Already done."); return

    repos = [
        ("https://github.com/SecureAuthCorp/impacket",              "./data/repos/impacket"),  # already may exist
        ("https://github.com/Hacking-the-Cloud/hackingthe.cloud",   "./data/repos/hackingthecloud"),
        ("https://github.com/dafthack/CloudPentestCheatsheets",     "./data/repos/cloud-cheatsheets"),
        ("https://github.com/dafthack/MSOLSpray",                   "./data/repos/msolspray"),
        ("https://github.com/BishopFox/cloudfox",                   "./data/repos/cloudfox"),
        ("https://github.com/nccgroup/PMapper",                     "./data/repos/pmapper"),
        ("https://github.com/cisagov/ScubaGear",                    "./data/repos/scubagear"),
        ("https://github.com/prowler-cloud/prowler",                "./data/repos/prowler"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "cloudsecdocs", repo_url)
            all_docs.extend(docs)

    # Also scrape hackingthe.cloud directly
    delay = c.get("delay_seconds", 1.5)
    done_urls = set()
    r = safe_get("https://hackingthe.cloud")
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        page_urls = []
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if href.startswith("/") and len(href) > 2:
                page_urls.append("https://hackingthe.cloud" + href)

        for url in tqdm(page_urls[:200], desc="hackingthe.cloud"):
            if url in done_urls:
                continue
            r2 = safe_get(url)
            if not r2:
                continue
            soup2   = BeautifulSoup(r2.text, "html.parser")
            title_e = soup2.select_one("h1")
            title   = title_e.get_text(strip=True) if title_e else ""
            body_e  = soup2.select_one("article, main, .content")
            text    = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                all_docs.append({
                    "source": "cloudsecdocs",
                    "title":  title,
                    "url":    url,
                    "text":   f"Cloud Attack/Defense Technique: {title}\n\n{text[:7000]}",
                })
            done_urls.add(url)
            time.sleep(delay)

    if all_docs:
        # stream write
        for i in range(0, len(all_docs), 500):
            append_jsonl(raw_file, all_docs[i:i+500])
        print(f"[cloudsecdocs] {len(all_docs)} files saved.")

    cp["cloudsecdocs_done"] = True
    save_checkpoint(checkpoint_file, cp)
