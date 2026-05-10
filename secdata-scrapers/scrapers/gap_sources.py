"""
Gap-filling sources for pipeline_combined_v4.
Targets the 10 highest-priority coverage gaps identified in v3.

GAP 1:  Mobile security          (ZERO → covered)
GAP 2:  Digital forensics & IR   (Thin → covered)
GAP 3:  API security             (Thin → covered)
GAP 4:  DevSecOps / CI/CD        (Thin → covered)
GAP 5:  AI/ML security           (Thin → covered)
GAP 6:  Azure & GCP cloud        (Thin → covered)
GAP 7:  Vuln research methodology(Thin → covered)
GAP 8:  Wireless & RF security   (Thin → covered)
GAP 9:  Kubernetes / containers  (Partial → fuller)
GAP 10: Secure coding / AppSec   (Partial → fuller)
"""
import os, re, time, subprocess, io, requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    parse_html, extract_pdf_text,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})

def scrape_blog(base_url, source_name, label, cp_key, raw_file, checkpoint_file,
                delay=1.5, max_pages=30, link_filter=None):
    cp   = load_checkpoint(checkpoint_file)
    done = set(cp.get(cp_key, []))
    post_urls = []
    domain = base_url.split("//")[-1].split("/")[0]
    for page in range(1, max_pages + 1):
        url = base_url if page == 1 else f"{base_url}page/{page}/"
        r = safe_get(url)
        if not r: break
        soup = BeautifulSoup(r.text, "html.parser")
        found = False
        for a in soup.select("a[href]"):
            href = a.get("href","")
            if not href or href in post_urls or href in done: continue
            if domain not in href:
                if not href.startswith("/"): continue
                href = base_url.rstrip("/") + href
            if link_filter and not link_filter(href): continue
            if len(href) > len(base_url) + 4:
                post_urls.append(href); found = True
        if not found: break
        time.sleep(delay)
    batch = []
    for url in tqdm([u for u in post_urls if u not in done], desc=source_name):
        r = safe_get(url)
        if not r: done.add(url); continue
        soup = BeautifulSoup(r.text, "html.parser")
        title_e = soup.select_one("h1")
        title = title_e.get_text(strip=True) if title_e else ""
        body_e = soup.select_one("article,.post-content,.entry-content,.blog-content,main")
        text = body_e.get_text("\n",strip=True) if body_e else ""
        if len(text) > 400:
            batch.append({"source":source_name,"title":title,"url":url,
                          "text":f"{label}: {title}\n\n{text[:7000]}"})
        done.add(url)
        if len(batch) >= 100:
            append_jsonl(raw_file, batch)
            cp[cp_key] = list(done); save_checkpoint(checkpoint_file, cp); batch = []
        time.sleep(delay)
    if batch:
        append_jsonl(raw_file, batch)
        cp[cp_key] = list(done); save_checkpoint(checkpoint_file, cp)
    return len(done)

def _clone_many(repo_list, source_name, raw_file, checkpoint_file, cp_key):
    cp = load_checkpoint(checkpoint_file)
    if cp.get(cp_key): return []
    all_docs = []
    for repo_url, dest, label in repo_list:
        if clone_repo(repo_url, dest):
            all_docs.extend(extract_md_files(dest, source_name, repo_url, label))
    if all_docs:
        for i in range(0, len(all_docs), 500):
            append_jsonl(raw_file, all_docs[i:i+500])
    cp[cp_key] = True; save_checkpoint(checkpoint_file, cp)
    return all_docs

# ── GAP 1: MOBILE SECURITY ─────────────────────────────────────

def run_owasp_mastg(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("owasp_mastg", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/OWASP/owasp-mastg", "./data/repos/owasp-mastg",
         "OWASP Mobile Application Security Testing Guide"),
        ("https://github.com/OWASP/owasp-masvs", "./data/repos/owasp-masvs",
         "OWASP Mobile Application Security Verification Standard"),
    ], "owasp_mastg", raw_file, checkpoint_file, "mastg_done")
    print(f"[mastg] Done. {len(docs)} files.")

def run_hacktricks_mobile(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("hacktricks_mobile", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("hacktricks_done"): return
    mobile_kw = {"mobile","android","ios","iphone","apk","ipa","frida",
                 "objection","keychain","adb","jadx","smali"}
    all_docs = []
    for repo_url, dest in [
        ("https://github.com/carlospolop/hacktricks", "./data/repos/hacktricks"),
    ]:
        if not clone_repo(repo_url, dest): continue
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".")and d!=".git"]
            for fname in files:
                if not fname.endswith(".md"): continue
                if not any(kw in (root+fname).lower() for kw in mobile_kw): continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > 300_000: continue
                    with open(fpath,"r",encoding="utf-8",errors="ignore") as f: text = f.read()
                    if len(text) < 200: continue
                    title = fname.replace(".md","").replace("-"," ").replace("_"," ")
                    all_docs.append({"source":"hacktricks_mobile","title":title,
                                     "url":repo_url,
                                     "text":f"Mobile Security: {title}\n\n{text[:7000]}"})
                except Exception: pass
    if all_docs: append_jsonl(raw_file, all_docs)
    print(f"[hacktricks_mobile] Done. {len(all_docs)} files.")
    cp["hacktricks_done"] = True; save_checkpoint(checkpoint_file, cp)

def run_mobile_security_repos(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("mobile_security_repos", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/MobSF/Mobile-Security-Framework-MobSF",
         "./data/repos/mobsf", "Mobile Security Framework"),
        ("https://github.com/sensepost/objection",
         "./data/repos/objection", "Objection mobile runtime exploration"),
        ("https://github.com/ashishb/android-security-awesome",
         "./data/repos/android-sec-awesome", "Android security resource list"),
        ("https://github.com/Siguza/ios-resources",
         "./data/repos/ios-resources", "iOS security research resources"),
        ("https://github.com/ivRodriguezCA/RE-iOS-Apps",
         "./data/repos/re-ios-apps", "Reverse engineering iOS apps"),
    ], "mobile_security_repos", raw_file, checkpoint_file, "mobile_repos_done")
    print(f"[mobile_repos] Done. {len(docs)} files.")

# ── GAP 2: DFIR ────────────────────────────────────────────────

def run_dfir_report(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("dfir_report", {})
    if not c.get("enabled", True): return
    n = scrape_blog("https://thedfirreport.com/", "dfir_report",
                    "DFIR Real-World Intrusion Report", "dfir_done",
                    raw_file, checkpoint_file,
                    delay=c.get("delay_seconds",2.0), max_pages=30,
                    link_filter=lambda h: "thedfirreport.com" in h and "/20" in h)
    print(f"[dfir] Done. {n} reports.")

def run_volatility_docs(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("volatility_docs", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if cp.get("volatility_done"): return
    all_docs = []
    for repo_url, dest, label in [
        ("https://github.com/volatilityfoundation/volatility3",
         "./data/repos/volatility3","Volatility 3 Memory Forensics"),
        ("https://github.com/volatilityfoundation/community3",
         "./data/repos/volatility-community","Volatility community plugins"),
    ]:
        if not clone_repo(repo_url, dest): continue
        all_docs.extend(extract_md_files(dest,"volatility_docs",repo_url,label))
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".py"): continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath,"r",encoding="utf-8",errors="ignore") as f: code=f.read()
                    docstrings=[d.strip() for d in re.findall(r'"""(.*?)"""',code,re.DOTALL) if len(d.strip())>80]
                    if docstrings:
                        all_docs.append({"source":"volatility_docs",
                                         "title":f"Volatility Plugin: {fname.replace('.py','')}",
                                         "url":repo_url,
                                         "text":f"Memory Forensics Plugin:\n\n"+"\n\n".join(docstrings[:3])})
                except Exception: pass
    if all_docs: append_jsonl(raw_file, all_docs)
    print(f"[volatility] Done. {len(all_docs)} entries.")
    cp["volatility_done"] = True; save_checkpoint(checkpoint_file, cp)

def run_forensic_tools_docs(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("forensic_tools_docs", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/log2timeline/plaso",
         "./data/repos/plaso","Log2timeline timeline generation"),
        ("https://github.com/Velocidex/velociraptor",
         "./data/repos/velociraptor","Velociraptor DFIR platform"),
        ("https://github.com/msuhanov/regf",
         "./data/repos/regf","Windows Registry forensics"),
    ], "forensic_tools_docs", raw_file, checkpoint_file, "forensic_tools_done")
    print(f"[forensic_tools] Done. {len(docs)} files.")

# ── GAP 3: API SECURITY ────────────────────────────────────────

def run_owasp_api_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("owasp_api_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/OWASP/API-Security",
         "./data/repos/owasp-api-security","OWASP API Security Top 10"),
        ("https://github.com/OWASP/CheatSheetSeries",
         "./data/repos/owasp-cheatsheets","OWASP Secure Coding Cheat Sheets"),
        ("https://github.com/shieldfy/API-Security-Checklist",
         "./data/repos/api-sec-checklist","API Security Checklist"),
        ("https://github.com/arainho/awesome-api-security",
         "./data/repos/awesome-api-security","Awesome API Security"),
        ("https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
         "./data/repos/dvga","Damn Vulnerable GraphQL Application"),
    ], "owasp_api_security", raw_file, checkpoint_file, "owasp_api_done")
    print(f"[owasp_api] Done. {len(docs)} files.")

# ── GAP 4: CI/CD SECURITY ──────────────────────────────────────

def run_cicd_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("cicd_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/slsa-framework/slsa",
         "./data/repos/slsa","SLSA Supply Chain Security Framework"),
        ("https://github.com/step-security/harden-runner",
         "./data/repos/harden-runner","GitHub Actions security hardening"),
        ("https://github.com/Checkmarx/kics",
         "./data/repos/kics","Infrastructure-as-code security scanning"),
        ("https://github.com/trufflesecurity/trufflehog",
         "./data/repos/trufflehog","Secret detection in code repos"),
        ("https://github.com/gitleaks/gitleaks",
         "./data/repos/gitleaks","Git secrets detection"),
    ], "cicd_security", raw_file, checkpoint_file, "cicd_done")
    # GitHub Security Lab blog
    n = scrape_blog("https://securitylab.github.com/research/",
                    "cicd_security","GitHub Security Lab Research",
                    "gh_seclab_done", raw_file, checkpoint_file, delay=1.5,
                    max_pages=10,
                    link_filter=lambda h: "securitylab.github.com" in h and len(h)>45)
    print(f"[cicd] Done. {len(docs)} files + {n} blog posts.")

# ── GAP 5: AI/ML SECURITY ──────────────────────────────────────

def run_ai_ml_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("ai_ml_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/mitre-atlas/atlas-data",
         "./data/repos/mitre-atlas","MITRE ATLAS Adversarial ML"),
        ("https://github.com/OWASP/www-project-top-10-for-large-language-model-applications",
         "./data/repos/owasp-llm-top10","OWASP LLM Top 10"),
        ("https://github.com/Trusted-AI/adversarial-robustness-toolbox",
         "./data/repos/art","Adversarial Robustness Toolbox"),
        ("https://github.com/greshake/llm-security",
         "./data/repos/llm-security","LLM security and prompt injection"),
    ], "ai_ml_security", raw_file, checkpoint_file, "ai_ml_done")
    print(f"[ai_ml_sec] Done. {len(docs)} files.")

# ── GAP 6: AZURE & GCP CLOUD ───────────────────────────────────

def run_azure_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("azure_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/dirkjanm/ROADtools",
         "./data/repos/roadtools","ROADtools Azure AD enumeration"),
        ("https://github.com/BloodHoundAD/AzureHound",
         "./data/repos/azurehound","AzureHound AD attack paths"),
        ("https://github.com/Cloud-Architekt/AzureAD-Attack-Defense",
         "./data/repos/aad-attack-defense","Azure AD Attack and Defense"),
        ("https://github.com/NetSPI/MicroBurst",
         "./data/repos/microburst","Azure security assessment"),
        ("https://github.com/hausec/PowerZure",
         "./data/repos/powerzure","Azure penetration testing"),
        ("https://github.com/nccgroup/ScoutSuite",
         "./data/repos/scoutsuite","Multi-cloud security auditing"),
    ], "azure_security", raw_file, checkpoint_file, "azure_done")
    n = scrape_blog("https://aadinternals.com/post/",
                    "azure_security","AADInternals Azure AD Research",
                    "aadinternals_done", raw_file, checkpoint_file,
                    delay=c.get("delay_seconds",2.0), max_pages=20)
    print(f"[azure_sec] Done. {len(docs)} files + {n} blog posts.")

def run_gcp_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("gcp_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation",
         "./data/repos/gcp-privesc","GCP IAM privilege escalation"),
        ("https://github.com/nccgroup/ScoutSuite",
         "./data/repos/scoutsuite-gcp","ScoutSuite GCP auditing"),
    ], "gcp_security", raw_file, checkpoint_file, "gcp_done")
    print(f"[gcp_sec] Done. {len(docs)} files.")

# ── GAP 7: VULN RESEARCH METHODOLOGY ───────────────────────────

def run_vuln_research_methodology(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("vuln_research_methodology", {})
    if not c.get("enabled", True): return
    cp = load_checkpoint(checkpoint_file)
    if not cp.get("p0_done"):
        n = scrape_blog("https://googleprojectzero.blogspot.com/",
                        "vuln_research_methodology",
                        "Google Project Zero Vulnerability Research",
                        "p0_done", raw_file, checkpoint_file,
                        delay=c.get("delay_seconds",2.0), max_pages=50,
                        link_filter=lambda h: "googleprojectzero.blogspot.com" in h and ".html" in h)
        print(f"[vuln_research] Project Zero: {n} posts")
    if not cp.get("tob_done"):
        n = scrape_blog("https://blog.trailofbits.com/",
                        "vuln_research_methodology",
                        "Trail of Bits Security Research",
                        "tob_done", raw_file, checkpoint_file,
                        delay=c.get("delay_seconds",1.5), max_pages=30)
        print(f"[vuln_research] Trail of Bits: {n} posts")
    if not cp.get("fuzzing_done"):
        docs = _clone_many([
            ("https://github.com/AFLplusplus/AFLplusplus",
             "./data/repos/aflplusplus","AFL++ Coverage-Guided Fuzzing"),
            ("https://github.com/google/oss-fuzz",
             "./data/repos/oss-fuzz","Google OSS-Fuzz"),
            ("https://github.com/github/codeql",
             "./data/repos/codeql","CodeQL static analysis queries"),
        ], "vuln_research_methodology", raw_file, checkpoint_file, "fuzzing_done")
        print(f"[vuln_research] Fuzzing/analysis repos: {len(docs)} files")
    print("[vuln_research] Done.")

# ── GAP 8: WIRELESS & RF SECURITY ──────────────────────────────

def run_wireless_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("wireless_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/aircrack-ng/aircrack-ng",
         "./data/repos/aircrack-ng","WiFi Security Testing — aircrack-ng"),
    ], "wireless_security", raw_file, checkpoint_file, "wireless_done")
    print(f"[wireless] Done. {len(docs)} files.")

# ── GAP 9: KUBERNETES & CONTAINERS ─────────────────────────────

def run_k8s_container_security(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("k8s_container_security", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/falcosecurity/falco",
         "./data/repos/falco","Falco Runtime Security"),
        ("https://github.com/falcosecurity/falco-rules",
         "./data/repos/falco-rules","Falco Threat Detection Rules"),
        ("https://github.com/aquasecurity/kube-bench",
         "./data/repos/kube-bench","Kubernetes CIS Benchmark Checks"),
    ], "k8s_container_security", raw_file, checkpoint_file, "k8s_done")
    n = scrape_blog("https://www.aquasec.com/blog/",
                    "k8s_container_security","Aqua Security Container Research",
                    "aqua_blog_done", raw_file, checkpoint_file,
                    delay=c.get("delay_seconds",1.5), max_pages=20,
                    link_filter=lambda h: "aquasec.com/blog/" in h and len(h)>40)
    print(f"[k8s] Done. {len(docs)} files + {n} blog posts.")

# ── GAP 10: SECURE CODING & APPSEC ─────────────────────────────

def run_secure_coding(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"].get("secure_coding", {})
    if not c.get("enabled", True): return
    docs = _clone_many([
        ("https://github.com/OWASP/CheatSheetSeries",
         "./data/repos/owasp-cheatsheets-sc","OWASP Cheat Sheet Series"),
        ("https://github.com/OWASP/www-project-samm",
         "./data/repos/owasp-samm","OWASP Software Assurance Maturity Model"),
        ("https://github.com/OWASP/threat-dragon",
         "./data/repos/threat-dragon","OWASP Threat Modeling"),
    ], "secure_coding", raw_file, checkpoint_file, "secure_coding_done")
    print(f"[secure_coding] Done. {len(docs)} files.")
