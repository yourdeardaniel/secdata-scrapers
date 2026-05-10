"""
Network security specialty sources — targeting genuine coverage gaps.

NETWORK MAPPING (3 sources)
  1.  Nmap official documentation + NSE scripts
  2.  Shodan research blog
  3.  Masscan + masscan-style tools documentation

NETWORK TRAFFIC ANALYSIS (3 sources)
  4.  Wireshark documentation and protocol wiki
  5.  PacketLife cheatsheets and PCAP analysis
  6.  PCAP challenge archives (CloudShark / public capture sets)

NETWORK HARDENING AND CONFIGURATION (4 sources)
  7.  CIS Benchmarks public content (network devices)
  8.  DISA STIGs for network devices (public)
  9.  MANRS routing security documentation (BGP hardening)
  10. NIST network-specific SP800 publications (targeted subset)

BGP / ROUTING SECURITY DEPTH (2 sources)
  11. CAIDA network security research
  12. Team Cymru blog (routing threat intelligence)

NETWORK DECEPTION AND HONEYPOTS (2 sources)
  13. The Honeynet Project (attack data, papers, tools)
  14. T-Pot / Modern Honeypot documentation

NOT ADDED (already well covered, would produce near-duplicates):
  - Network infiltration: 11 existing sources
  - Threat intelligence: 9 existing sources
  - DDoS mitigation: Cloudflare Blog + RIPE NCC already comprehensive
  - Network security assessments: PTES + SANS + pentest sources
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

# Silence noisy pdfminer warnings (FontBBox, encoding, etc.)
import logging
logging.getLogger("pdfminer").setLevel(logging.ERROR)
logging.getLogger("pdfplumber").setLevel(logging.ERROR)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})


def scrape_paginated_blog(base_urls, source_name, label, delay,
                          done_set, raw_file, checkpoint_file, cp_key,
                          max_pages=20):
    """Generic blog scraper for sites with standard HTML structure."""
    post_urls = []
    for base_url in (base_urls if isinstance(base_urls, list) else [base_urls]):
        for page in range(1, max_pages + 1):
            url = base_url if page == 1 else f"{base_url}page/{page}/"
            r   = safe_get(url)
            if not r:
                break
            soup  = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                # find article links that aren't the listing page itself
                domain = base_url.split("//")[-1].split("/")[0]
                if domain in href and len(href) > len(base_url) + 5:
                    if href not in post_urls and href not in done_set:
                        post_urls.append(href)
                        found = True
            if not found:
                break
            time.sleep(delay)

    batch = []
    for url in tqdm([u for u in post_urls if u not in done_set],
                    desc=source_name):
        r = safe_get(url)
        if not r:
            done_set.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .post-content, .entry-content, main")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": source_name,
                "title":  title,
                "url":    url,
                "text":   f"{label}: {title}\n\n{text[:6500]}",
            })
        done_set.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp = load_checkpoint(checkpoint_file)
            cp[cp_key] = list(done_set)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp = load_checkpoint(checkpoint_file)
        cp[cp_key] = list(done_set)
        save_checkpoint(checkpoint_file, cp)

    return len(done_set)


# ================================================================
# NETWORK MAPPING
# ================================================================

def run_nmap_documentation(cfg, raw_file, checkpoint_file):
    """
    Nmap official documentation and NSE script library.

    The Nmap repository contains:
    - The Nmap book (publicly available)
    - NSE script documentation — each script has a description of what
      it does, what vulnerabilities it detects, and example output
    - Service fingerprinting database documentation
    - OS detection documentation

    This is the authoritative reference on network scanning technique.
    """
    c = cfg["scrapers"].get("nmap_documentation", {})
    if not c.get("enabled", True):
        print("[nmap_docs] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("nmap_docs_done"):
        print("[nmap_docs] Already done."); return

    repos = [
        ("https://github.com/nmap/nmap",           "./data/repos/nmap"),
        ("https://github.com/vulnersCom/nmap-vulners",  "./data/repos/nmap-vulners"),
        ("https://github.com/scipag/vulscan",       "./data/repos/nmap-vulscan"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if not ok:
            continue

        docs = extract_md_files(dest, "nmap_documentation", repo_url,
                                "Nmap Network Scanning")

        # NSE scripts are Lua with documentation headers — very valuable
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".git"]
            for fname in files:
                if not fname.endswith(".nse"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # Extract the Lua docstring block at the top
                    desc_m = re.search(
                        r'description\s*=\s*\[\[(.+?)\]\]', content, re.DOTALL)
                    description = desc_m.group(1).strip() if desc_m else ""

                    categories_m = re.search(r'categories\s*=\s*\{([^}]+)\}', content)
                    categories = categories_m.group(1).strip() if categories_m else ""

                    author_m = re.search(r'author\s*=\s*[\{"]([^}"]+)', content)
                    author = author_m.group(1).strip() if author_m else ""

                    script_name = fname.replace(".nse", "")

                    if not description or len(description) < 30:
                        continue

                    parts = [
                        f"Nmap NSE Script: {script_name}",
                        f"Categories: {categories}" if categories else "",
                        f"Author: {author}" if author else "",
                        f"\nDescription:\n{description}",
                        f"\nScript excerpt:\n{content[:800]}",
                    ]

                    all_docs.append({
                        "source": "nmap_documentation",
                        "script": script_name,
                        "url":    f"https://nmap.org/nsedoc/scripts/{script_name}.html",
                        "text":   "\n".join(p for p in parts if p),
                    })
                except Exception:
                    pass

    # Also scrape nmap.org/nsedoc for official descriptions
    delay = c.get("delay_seconds", 1.5)
    done_urls = set()
    r = safe_get("https://nmap.org/nsedoc/")
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        script_urls = []
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/nsedoc/scripts/" in href:
                full = "https://nmap.org" + href if href.startswith("/") else href
                if full not in script_urls:
                    script_urls.append(full)

        for url in tqdm(script_urls[:200], desc="nmap.org NSE docs"):
            r2 = safe_get(url)
            if not r2 or url in done_urls:
                continue
            soup2   = BeautifulSoup(r2.text, "html.parser")
            title_e = soup2.select_one("h1, h2")
            title   = title_e.get_text(strip=True) if title_e else ""
            body_e  = soup2.select_one("#main, .content, article")
            text    = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                all_docs.append({
                    "source": "nmap_documentation",
                    "title":  title,
                    "url":    url,
                    "text":   f"Nmap NSE Script Documentation: {title}\n\n{text[:5000]}",
                })
            done_urls.add(url)
            time.sleep(delay)

    # Batch write
    for i in range(0, len(all_docs), 500):
        append_jsonl(raw_file, all_docs[i:i+500])

    cp["nmap_docs_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[nmap_docs] Done. {len(all_docs)} entries saved.")


def run_shodan_research(cfg, raw_file, checkpoint_file):
    """
    Shodan research blog and public data.

    Shodan is internet-wide scanning infrastructure. Their blog covers:
    - What's exposed on the internet (ICS, cameras, routers)
    - Vulnerability research at internet scale
    - Search query techniques for finding exposed services
    - Analysis of specific protocols and their security posture

    Unique perspective: they see the internet from the outside.
    """
    c = cfg["scrapers"].get("shodan_research", {})
    if not c.get("enabled", True):
        print("[shodan] Disabled."); return

    delay = c.get("delay_seconds", 1.5)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("shodan_done", []))

    post_urls = []

    # Blog
    for page in range(1, 15):
        url = "https://blog.shodan.io/" if page == 1 else f"https://blog.shodan.io/page/{page}/"
        r   = safe_get(url)
        if not r:
            break
        soup  = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("article a[href], h2 a[href], h1 a[href]"):
            href = a.get("href", "")
            if "blog.shodan.io" in href and href not in post_urls:
                post_urls.append(href)
                found = True
        if not found:
            break
        time.sleep(delay)

    # Shodan public reports / trends pages
    extra_pages = [
        "https://www.shodan.io/search/examples",
        "https://help.shodan.io/guides",
        "https://help.shodan.io/developer-fundamentals/shodan-dorks",
        "https://help.shodan.io/data-analysis/introduction",
    ]
    for url in extra_pages:
        r = safe_get(url)
        if r and url not in done:
            soup    = BeautifulSoup(r.text, "html.parser")
            title_e = soup.select_one("h1, h2")
            title   = title_e.get_text(strip=True) if title_e else ""
            body_e  = soup.select_one("article, main, .content, .docs-content")
            text    = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 200:
                append_jsonl(raw_file, [{
                    "source": "shodan_research",
                    "title":  title,
                    "url":    url,
                    "text":   f"Shodan Network Intelligence: {title}\n\n{text[:6000]}",
                }])
            done.add(url)
        time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    batch = []
    for url in tqdm(new_urls, desc="Shodan blog"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .post-content, section")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "shodan_research",
                "title":  title,
                "url":    url,
                "text":   f"Shodan Internet Security Research: {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["shodan_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["shodan_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[shodan] Done. {len(done)} entries.")


def run_masscan_recon_tools(cfg, raw_file, checkpoint_file):
    """
    Masscan and related network reconnaissance tool documentation.

    Covers masscan (fast internet scanner), its use cases, comparison
    to nmap, banner grabbing, and integration with other tools.
    Also includes related recon tool repositories.
    """
    c = cfg["scrapers"].get("masscan_recon_tools", {})
    if not c.get("enabled", True):
        print("[masscan] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("masscan_done"):
        print("[masscan] Already done."); return

    repos = [
        ("https://github.com/robertdavidgraham/masscan",    "./data/repos/masscan"),
        ("https://github.com/projectdiscovery/naabu",       "./data/repos/naabu"),
        ("https://github.com/projectdiscovery/dnsx",        "./data/repos/dnsx"),
        ("https://github.com/projectdiscovery/httpx",       "./data/repos/httpx"),
        ("https://github.com/projectdiscovery/katana",      "./data/repos/katana"),
        ("https://github.com/Edu4rdSHL/findomain",          "./data/repos/findomain"),
        ("https://github.com/blechschmidt/massdns",         "./data/repos/massdns"),
        ("https://github.com/ElevenPaths/FOCA",             "./data/repos/foca"),
        ("https://github.com/laramies/theHarvester",        "./data/repos/theharvester"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "masscan_recon_tools", repo_url,
                                    "Network Reconnaissance Tool")
            all_docs.extend(docs)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[masscan] {len(all_docs)} files saved.")

    cp["masscan_done"] = True
    save_checkpoint(checkpoint_file, cp)


# ================================================================
# NETWORK TRAFFIC ANALYSIS
# ================================================================

def run_wireshark_documentation(cfg, raw_file, checkpoint_file):
    """
    Wireshark documentation, protocol wiki, and sample capture analysis.

    Wireshark's documentation covers:
    - Protocol dissector internals (how each protocol is decoded)
    - Display filter syntax for threat hunting
    - Protocol-specific analysis (TLS, DNS, HTTP, QUIC, etc.)
    - Capture file analysis workflow

    The Wireshark wiki has hundreds of protocol pages explaining
    packet structure, what to look for in captures, and attack indicators.
    This is the gold standard reference for network traffic analysis.
    """
    c = cfg["scrapers"].get("wireshark_documentation", {})
    if not c.get("enabled", True):
        print("[wireshark] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("wireshark_done", []))
    delay = c.get("delay_seconds", 1.5)

    # Clone documentation repo — very rich
    dest = "./data/repos/wireshark"
    ok = clone_repo("https://gitlab.com/wireshark/wireshark", dest, timeout=600)
    if ok:
        # Doc subdirectory has RST/asciidoc files
        docs_dir = os.path.join(dest, "doc")
        all_docs = []
        if os.path.exists(docs_dir):
            for root, dirs, files in os.walk(docs_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in (".rst", ".adoc", ".asciidoc", ".txt", ".md"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getsize(fpath) > 200_000:
                            continue
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            text = f.read()
                        if len(text) < 200:
                            continue
                        title = fname.rsplit(".", 1)[0].replace("-", " ").replace("_", " ")
                        all_docs.append({
                            "source": "wireshark_documentation",
                            "file":   os.path.relpath(fpath, dest),
                            "title":  title,
                            "url":    "https://www.wireshark.org/docs/",
                            "text":   f"Wireshark Network Analysis: {title}\n\n{text[:7000]}",
                        })
                    except Exception:
                        pass
        if all_docs:
            append_jsonl(raw_file, all_docs)

    # Scrape the Wireshark wiki — protocol analysis pages
    wiki_base  = "https://wiki.wireshark.org"
    page_urls  = []

    # Protocol pages index
    r = safe_get(f"{wiki_base}/ProtocolReference")
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if href.startswith("/") and not any(
                skip in href for skip in ["action=", "UserPreferences", "HelpOn"]
            ):
                full = wiki_base + href
                if full not in page_urls:
                    page_urls.append(full)

    # SampleCaptures page has protocol-specific analysis
    extra_wiki = [
        f"{wiki_base}/SampleCaptures",
        f"{wiki_base}/DisplayFilters",
        f"{wiki_base}/CaptureFilters",
        f"{wiki_base}/Security",
        f"{wiki_base}/Protocols",
        f"{wiki_base}/TLS",
        f"{wiki_base}/DNS",
        f"{wiki_base}/TCP",
        f"{wiki_base}/HTTP",
        f"{wiki_base}/QUIC",
    ]
    for u in extra_wiki:
        if u not in page_urls:
            page_urls.append(u)

    new_urls = [u for u in page_urls if u not in done]
    batch = []
    for url in tqdm(new_urls[:400], desc="Wireshark wiki"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, #page-title")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("#page-content, .wiki-content, #content, article")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 300:
            batch.append({
                "source": "wireshark_documentation",
                "title":  title,
                "url":    url,
                "text":   f"Wireshark Protocol Analysis: {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp["wireshark_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["wireshark_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[wireshark] Done. {len(done)} pages.")


def run_packetlife(cfg, raw_file, checkpoint_file):
    """
    PacketLife.net — network protocol cheatsheets and PCAP analysis notes.

    PacketLife has two key resources:
    - Protocol cheatsheets (one per protocol — IP, TCP, UDP, OSPF, BGP, etc.)
      that document packet structure, key fields, and what to look for
    - PCAP analysis blog posts examining specific captures

    These are widely referenced in network analysis training.
    Also includes related public PCAP challenge resources.
    """
    c = cfg["scrapers"].get("packetlife", {})
    if not c.get("enabled", True):
        print("[packetlife] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("packetlife_done", []))
    delay = c.get("delay_seconds", 1.5)
    BASE  = "http://packetlife.net"

    page_urls = []

    # Cheatsheets listing
    r = safe_get(f"{BASE}/library/cheat-sheets/")
    if r:
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "/library/cheat-sheets/" in href and len(href) > 30:
                full = BASE + href if href.startswith("/") else href
                if full not in page_urls:
                    page_urls.append(full)

    # Blog posts
    for page in range(1, 15):
        url = f"{BASE}/blog/" if page == 1 else f"{BASE}/blog/{page}/"
        r2  = safe_get(url)
        if not r2:
            break
        soup2 = BeautifulSoup(r2.text, "html.parser")
        found = False
        for a in soup2.select("a[href]"):
            href = a.get("href", "")
            if "/blog/" in href and len(href) > len(f"{BASE}/blog/") + 5:
                full = BASE + href if href.startswith("/") else href
                if full not in page_urls:
                    page_urls.append(full)
                    found = True
        if not found:
            break
        time.sleep(delay)

    # also grab public PCAP challenge repos
    pcap_repos = [
        ("https://github.com/activecm/threat-hunting-labs", "./data/repos/th-labs"),
        ("https://github.com/pan-unit42/wireshark-workshop", "./data/repos/palo-ws"),
    ]
    pcap_docs = []
    for repo_url, dest in pcap_repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "packetlife", repo_url,
                                    "Network Traffic Analysis")
            pcap_docs.extend(docs)
    if pcap_docs:
        append_jsonl(raw_file, pcap_docs)

    new_urls = [u for u in page_urls if u not in done]
    batch = []
    for url in tqdm(new_urls, desc="PacketLife"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2.title")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .post, .entry, main")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 200:
            batch.append({
                "source": "packetlife",
                "title":  title,
                "url":    url,
                "text":   f"Network Protocol Analysis: {title}\n\n{text[:6000]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["packetlife_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["packetlife_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[packetlife] Done. {len(done)} pages.")


# ================================================================
# NETWORK HARDENING AND CONFIGURATION
# ================================================================

def run_cis_benchmarks(cfg, raw_file, checkpoint_file):
    """
    CIS (Center for Internet Security) Benchmarks — public content.

    CIS publishes hardening guides for every major platform.
    The full PDF benchmarks are member-only, but:
    - CIS Controls are publicly available (18 controls, detailed implementation)
    - CIS Benchmark community editions are available for certain platforms
    - The CIS GitHub repos contain machine-readable benchmark content

    For network devices specifically: Cisco IOS, network infrastructure,
    firewall configuration guidance.
    """
    c = cfg["scrapers"].get("cis_benchmarks", {})
    if not c.get("enabled", True):
        print("[cis] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("cis_done"):
        print("[cis] Already done."); return

    delay = c.get("delay_seconds", 2.0)

    # CIS GitHub repos with machine-readable benchmark content
    repos = [
        ("https://github.com/CISecurity/CIS-Controls",        "./data/repos/cis-controls"),
        ("https://github.com/CISecurity/cis-benchmarks",       "./data/repos/cis-benchmarks"),
        ("https://github.com/dev-sec/ansible-collection-hardening", "./data/repos/dev-sec-hardening"),
        ("https://github.com/openstack/security-doc",          "./data/repos/openstack-security"),
        ("https://github.com/NIST-SCAP/OVAL-repository",       "./data/repos/oval-repo"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "cis_benchmarks", repo_url,
                                    "Security Hardening Guide")
            all_docs.extend(docs)

    # Scrape the public CIS Controls web page
    controls_pages = [
        "https://www.cisecurity.org/controls/",
        "https://www.cisecurity.org/controls/cis-controls-list/",
        "https://www.cisecurity.org/insights/blog/",
    ]
    done_urls = set()
    for base in controls_pages:
        r = safe_get(base)
        if not r:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        page_links = [base]
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "cisecurity.org" in href and "/controls/" in href:
                full = href if href.startswith("http") else "https://www.cisecurity.org" + href
                if full not in page_links:
                    page_links.append(full)

        for url in page_links[:30]:
            if url in done_urls:
                continue
            r2 = safe_get(url)
            if not r2:
                continue
            soup2   = BeautifulSoup(r2.text, "html.parser")
            title_e = soup2.select_one("h1, h2")
            title   = title_e.get_text(strip=True) if title_e else ""
            body_e  = soup2.select_one("article, main, .entry-content, .page-content")
            text    = body_e.get_text("\n", strip=True) if body_e else ""
            if len(text) > 300:
                all_docs.append({
                    "source": "cis_benchmarks",
                    "title":  title,
                    "url":    url,
                    "text":   f"CIS Security Control/Benchmark: {title}\n\n{text[:6000]}",
                })
            done_urls.add(url)
            time.sleep(delay)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[cis] {len(all_docs)} resources saved.")

    cp["cis_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_disa_stigs(cfg, raw_file, checkpoint_file):
    """
    DISA STIGs (Security Technical Implementation Guides) — network devices.

    STIGs are DoD-mandated configuration standards covering every major
    network device: Cisco routers/switches, Palo Alto firewalls, Juniper,
    F5 load balancers, network infrastructure generally.

    Each STIG check is a specific security requirement with:
    - The vulnerability it prevents
    - How to verify compliance
    - The fix (exact configuration commands)

    These are the most prescriptive network hardening guides available.
    Public domain — no license restrictions.
    """
    c = cfg["scrapers"].get("disa_stigs", {})
    if not c.get("enabled", True):
        print("[stigs] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("stigs_done", []))
    delay = c.get("delay_seconds", 2.0)

    # STIG viewer and machine-readable STIG repos on GitHub
    repos = [
        ("https://github.com/DISA-STIG/U_APACHE_SERVER_2-4_UNIX_STIG", "./data/repos/stig-apache"),
        ("https://github.com/mitre/cisco-ios-xe-21-stig-baseline",     "./data/repos/stig-cisco"),
        ("https://github.com/mitre/stig-microsoft-windows-server-2019-baseline", "./data/repos/stig-win"),
        ("https://github.com/mitre/nginx-stigready-baseline",           "./data/repos/stig-nginx"),
        ("https://github.com/mitre/chef-security-stig",                 "./data/repos/stig-chef"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            # InSpec/STIG repos have Ruby controls with documentation
            docs = extract_md_files(dest, "disa_stigs", repo_url,
                                    "DISA STIG Security Configuration")
            # also parse InSpec control files for security requirements
            for root, dirs, files in os.walk(dest):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fname in files:
                    if not fname.endswith(".rb"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        # extract control blocks
                        controls = re.findall(
                            r"control\s+'([^']+)'.*?end",
                            content, re.DOTALL
                        )
                        for ctrl in controls[:20]:
                            # extract title and desc from block
                            title_m = re.search(r"title\s+'([^']+)'", ctrl)
                            desc_m  = re.search(r'desc\s+"([^"]+)"', ctrl, re.DOTALL)
                            title   = title_m.group(1) if title_m else ""
                            desc    = desc_m.group(1) if desc_m else ""
                            if desc and len(desc) > 50:
                                all_docs.append({
                                    "source": "disa_stigs",
                                    "title":  title,
                                    "url":    repo_url,
                                    "text":   f"DISA STIG Control: {title}\n\nRequirement:\n{desc}\n\nFull control:\n{ctrl[:800]}",
                                })
                    except Exception:
                        pass
            all_docs.extend(docs)

    # Scrape the public STIG library
    stig_base = "https://public.cyber.mil/stigs/srg-stig-tools/"
    r = safe_get(stig_base)
    if r and stig_base not in done:
        soup    = BeautifulSoup(r.text, "html.parser")
        body_e  = soup.select_one("main, article, .entry-content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 200:
            all_docs.append({
                "source": "disa_stigs",
                "title":  "DISA STIG Tools and Library",
                "url":    stig_base,
                "text":   f"DISA STIG Reference: {text[:6000]}",
            })
        done.add(stig_base)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[stigs] {len(all_docs)} STIG resources saved.")

    cp["stigs_done"] = list(done)
    save_checkpoint(checkpoint_file, cp)


def run_manrs_routing_security(cfg, raw_file, checkpoint_file):
    """
    MANRS (Mutually Agreed Norms for Routing Security) documentation.

    MANRS is the global routing security initiative covering:
    - BGP hijacking prevention (route origin validation, RPKI)
    - Filtering of bogon routes and prefixes
    - Anti-spoofing measures (BCP38/BCP84)
    - Route leak prevention

    Also includes related BGP security resources:
    - RPKI documentation (route origin authorization)
    - IRR (Internet Routing Registry) best practices
    - ARTEMIS BGP hijacking detection
    """
    c = cfg["scrapers"].get("manrs_routing_security", {})
    if not c.get("enabled", True):
        print("[manrs] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("manrs_done"):
        print("[manrs] Already done."); return

    delay = c.get("delay_seconds", 1.5)

    repos = [
        ("https://github.com/MANRS-IXP-Capability-Fund/MANRS-implementation-guide",
         "./data/repos/manrs-guide"),
        ("https://github.com/nicehash/bgp-hijack", "./data/repos/bgp-hijack"),
        ("https://github.com/FORTH-ICS-INSPIRE/artemis", "./data/repos/artemis-bgp"),
        ("https://github.com/cloudflare/cfssl",     "./data/repos/cfssl"),
    ]

    all_docs = []
    for repo_url, dest in repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "manrs_routing_security", repo_url,
                                    "BGP/Routing Security")
            all_docs.extend(docs)

    # Scrape MANRS website resources
    manrs_urls = [
        "https://www.manrs.org/isps/guide/",
        "https://www.manrs.org/isps/guide/filtering/",
        "https://www.manrs.org/isps/guide/antispoofing/",
        "https://www.manrs.org/isps/guide/coordination/",
        "https://www.manrs.org/isps/guide/validation/",
        "https://www.manrs.org/netops/",
        "https://www.manrs.org/resources/",
    ]
    for url in manrs_urls:
        r = safe_get(url)
        if not r:
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, main, .entry-content, .page-content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 300:
            all_docs.append({
                "source": "manrs_routing_security",
                "title":  title,
                "url":    url,
                "text":   f"BGP Routing Security — MANRS: {title}\n\n{text[:6000]}",
            })
        time.sleep(delay)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[manrs] {len(all_docs)} resources saved.")

    cp["manrs_done"] = True
    save_checkpoint(checkpoint_file, cp)


def run_nist_network_publications(cfg, raw_file, checkpoint_file):
    """
    NIST network-specific SP800 publications (targeted subset).

    The existing NIST scraper grabs SP800 generally. This scraper
    targets the network security subset specifically:
    - SP 800-41 (Firewall Guidelines)
    - SP 800-77 (IPsec VPNs)
    - SP 800-81 (Secure DNS)
    - SP 800-189 (Routing Security)
    - SP 800-115 (Network Security Assessment)
    - SP 800-137 (ISCM)
    - SP 800-207 (Zero Trust Architecture)
    """
    c = cfg["scrapers"].get("nist_network_publications", {})
    if not c.get("enabled", True):
        print("[nist_network] Disabled."); return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("nist_network_done"):
        print("[nist_network] Already done."); return

    delay = c.get("delay_seconds", 3.0)

    # Targeted NIST network security publications
    pubs = [
        ("800-41", "Firewall Guidelines"),
        ("800-77", "Guide to IPsec VPNs"),
        ("800-81-2", "Secure DNS Deployment Guide"),
        ("800-189", "Resilient Interdomain Traffic Exchange: BGP Security and DDoS Mitigation"),
        ("800-115", "Technical Guide to Information Security Testing and Assessment"),
        ("800-137", "Information Security Continuous Monitoring"),
        ("800-207", "Zero Trust Architecture"),
        ("800-160", "Engineering Trustworthy Secure Systems"),
        ("800-61", "Computer Security Incident Handling Guide"),
        ("800-83", "Guide to Malware Incident Prevention"),
        ("800-94", "Guide to Intrusion Detection and Prevention Systems"),
        ("800-150", "Guide to Cyber Threat Information Sharing"),
    ]

    all_docs = []
    for pub_num, pub_title in pubs:
        url = f"https://csrc.nist.gov/publications/detail/sp/{pub_num}/final"
        r   = safe_get(url, timeout=30)
        if not r:
            # try alternate URL format
            url = f"https://csrc.nist.gov/publications/detail/sp/{pub_num.replace('-','/')}/final"
            r   = safe_get(url, timeout=30)
        if not r:
            time.sleep(delay)
            continue

        soup = BeautifulSoup(r.text, "html.parser")

        abstract_e = soup.select_one(".abstract, #abstract, [itemprop='description']")
        abstract   = abstract_e.get_text("\n", strip=True) if abstract_e else ""

        # find PDF link
        pdf_url = None
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if href.lower().endswith(".pdf") and "nvlpubs" in href:
                pdf_url = href
                break

        text = f"NIST SP {pub_num}: {pub_title}\n\n"
        if abstract:
            text += f"Abstract:\n{abstract}\n\n"

        if pdf_url:
            r2 = safe_get(pdf_url, timeout=60)
            if r2:
                try:
                    import pdfplumber
                    parts = []
                    with pdfplumber.open(io.BytesIO(r2.content)) as pdf:
                        for page in pdf.pages[:50]:
                            t = page.extract_text()
                            if t:
                                parts.append(t)
                    pdf_text = "\n".join(parts)
                    if pdf_text:
                        text += pdf_text[:10000]
                except Exception:
                    pass

        if len(text) > 200:
            all_docs.append({
                "source": "nist_network_publications",
                "pub_num": pub_num,
                "title":  f"NIST SP {pub_num}: {pub_title}",
                "url":    url,
                "text":   text[:10000],
            })
        time.sleep(delay)

    if all_docs:
        append_jsonl(raw_file, all_docs)
        print(f"[nist_network] {len(all_docs)} publications saved.")

    cp["nist_network_done"] = True
    save_checkpoint(checkpoint_file, cp)


# ================================================================
# BGP / ROUTING SECURITY DEPTH
# ================================================================

def run_caida_research(cfg, raw_file, checkpoint_file):
    """
    CAIDA (Center for Applied Internet Data Analysis) — network security research.

    CAIDA studies internet infrastructure at scale:
    - BGP routing security and hijacking analysis
    - DDoS measurement and amplification attack research
    - Internet topology and AS-level routing
    - Traffic analysis methodologies

    Their research is the empirical foundation for understanding how
    internet-scale attacks actually work.
    """
    c = cfg["scrapers"].get("caida_research", {})
    if not c.get("enabled", True):
        print("[caida] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("caida_done", []))
    delay = c.get("delay_seconds", 2.0)
    BASE  = "https://www.caida.org"

    post_urls = []
    for section in ["/research/", "/publications/", "/insights/", "/projects/"]:
        r = safe_get(BASE + section)
        if not r:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if href.startswith("/") and len(href) > 15:
                full = BASE + href
                if full not in post_urls:
                    post_urls.append(full)
        time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    batch = []
    for url in tqdm(new_urls[:200], desc="CAIDA Research"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, main, .content, #content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "caida_research",
                "title":  title,
                "url":    url,
                "text":   f"CAIDA Internet Security Research: {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["caida_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["caida_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[caida] Done. {len(done)} pages.")


def run_team_cymru(cfg, raw_file, checkpoint_file):
    """
    Team Cymru — network threat intelligence focused on BGP and routing.

    Team Cymru operates one of the largest BGP route collectors.
    Their blog covers:
    - BGP hijacking incident analysis
    - Botnet C2 infrastructure tracking via BGP
    - IP reputation and abuse tracking
    - Network-layer threat intelligence methodology

    This is a very different perspective from host-based threat intel —
    it's about understanding the network infrastructure of attackers.
    """
    c = cfg["scrapers"].get("team_cymru", {})
    if not c.get("enabled", True):
        print("[team_cymru] Disabled."); return

    delay = c.get("delay_seconds", 1.5)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("team_cymru_done", []))

    post_urls = []
    for section in ["/blog/", "/research/", "/resources/"]:
        r = safe_get(f"https://team-cymru.com{section}")
        if not r:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "team-cymru.com" in href and len(href) > 30:
                if href not in post_urls:
                    post_urls.append(href)
        time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    batch = []
    for url in tqdm(new_urls, desc="Team Cymru"):
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
                "source": "team_cymru",
                "title":  title,
                "url":    url,
                "text":   f"Network Threat Intelligence (Team Cymru): {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["team_cymru_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["team_cymru_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[team_cymru] Done. {len(done)} posts.")


# ================================================================
# NETWORK DECEPTION AND HONEYPOTS
# ================================================================

def run_honeynet_project(cfg, raw_file, checkpoint_file):
    """
    The Honeynet Project — network deception, attack analysis, honeypot research.

    The Honeynet Project publishes:
    - Know Your Enemy papers (deep analysis of specific attack types)
    - Tool releases with documentation (Dionaea, Cowrie, HoneyDrive)
    - Annual challenge writeups (forensics/network analysis)
    - Research on attacker techniques observed in honeypots

    This is uniquely valuable because it documents real attacker behavior
    observed in controlled environments — empirical attack data.
    """
    c = cfg["scrapers"].get("honeynet_project", {})
    if not c.get("enabled", True):
        print("[honeynet] Disabled."); return

    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("honeynet_done", []))
    delay = c.get("delay_seconds", 1.5)
    BASE  = "https://www.honeynet.org"

    post_urls = []
    for section in ["/blog/", "/papers/", "/challenges/"]:
        for page in range(1, 10):
            url = f"{BASE}{section}" if page == 1 else f"{BASE}{section}page/{page}/"
            r   = safe_get(url)
            if not r:
                break
            soup  = BeautifulSoup(r.text, "html.parser")
            found = False
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if "honeynet.org" in href and len(href) > len(BASE) + 10:
                    if href not in post_urls:
                        post_urls.append(href)
                        found = True
            if not found:
                break
            time.sleep(delay)

    # Also grab repos for popular honeypot tools
    honeypot_repos = [
        ("https://github.com/cowrie/cowrie",        "./data/repos/cowrie"),
        ("https://github.com/DinoTools/dionaea",    "./data/repos/dionaea"),
        ("https://github.com/telekom-security/tpotce", "./data/repos/tpot"),
        ("https://github.com/paralax/awesome-honeypots", "./data/repos/awesome-honeypots"),
        ("https://github.com/mushorg/conpot",       "./data/repos/conpot-ics-honeypot"),
    ]
    for repo_url, dest in honeypot_repos:
        ok = clone_repo(repo_url, dest)
        if ok:
            docs = extract_md_files(dest, "honeynet_project", repo_url,
                                    "Honeypot/Network Deception")
            if docs:
                append_jsonl(raw_file, docs)

    new_urls = [u for u in post_urls if u not in done]
    batch = []
    for url in tqdm(new_urls, desc="Honeynet Project"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2.entry-title")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, .entry-content, main")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "honeynet_project",
                "title":  title,
                "url":    url,
                "text":   f"Honeynet Attack Research: {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["honeynet_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["honeynet_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[honeynet] Done. {len(done)} resources.")


def run_shadowserver(cfg, raw_file, checkpoint_file):
    """
    Shadowserver Foundation — network threat data, reports, and research.

    Shadowserver operates internet-wide sinkholing infrastructure and
    publishes research on:
    - Botnet tracking and takedown operations
    - Vulnerable internet-exposed services (scanning data)
    - Malware C2 infrastructure mapping
    - DDoS amplification source analysis

    Their reports provide real-world data on what attackers are doing
    at internet scale — grounding the model in empirical network threat data.
    """
    c = cfg["scrapers"].get("shadowserver", {})
    if not c.get("enabled", True):
        print("[shadowserver] Disabled."); return

    delay = c.get("delay_seconds", 2.0)
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("shadowserver_done", []))

    post_urls = []
    for section in ["/news/", "/resources/", "/whitepapers/"]:
        r = safe_get(f"https://www.shadowserver.org{section}")
        if not r:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            if "shadowserver.org" in href and len(href) > 30:
                if href not in post_urls:
                    post_urls.append(href)
        time.sleep(delay)

    new_urls = [u for u in post_urls if u not in done]
    batch = []
    for url in tqdm(new_urls, desc="Shadowserver"):
        r = safe_get(url)
        if not r:
            done.add(url)
            continue
        soup    = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1, h2")
        title   = title_e.get_text(strip=True) if title_e else ""
        body_e  = soup.select_one("article, main, .content")
        text    = body_e.get_text("\n", strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({
                "source": "shadowserver",
                "title":  title,
                "url":    url,
                "text":   f"Shadowserver Network Threat Research: {title}\n\n{text[:6500]}",
            })
        done.add(url)
        if len(batch) >= 50:
            append_jsonl(raw_file, batch)
            cp["shadowserver_done"] = list(done)
            save_checkpoint(checkpoint_file, cp)
            batch = []
        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["shadowserver_done"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[shadowserver] Done. {len(done)} resources.")
