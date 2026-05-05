"""
Detection rules and weakness taxonomy:
  - YARA rules (7 repos) — with descriptions explaining what they detect
  - Sigma rules (4 repos) — SIEM detection rules with context
  - CWE full database — complete weakness taxonomy with code examples
"""
import io
import os
import re
import subprocess
import time
import requests
import xml.etree.ElementTree as ET
from tqdm import tqdm

from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    safe_get, clone_repo, extract_md_files,
    SESSION,
)

SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)"})

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


# ================================================================
# YARA Rules
# ================================================================

def parse_yara_file(fpath, repo_name):
    """
    Parse a YARA rule file and extract structured training examples.
    Each rule becomes one training example explaining what it detects.
    """
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    docs = []
    # match individual YARA rules
    rule_pattern = re.compile(
        r'(?:^|\n)((?:private\s+)?(?:global\s+)?rule\s+(\w+)[^\{]*\{(.*?)^\})',
        re.DOTALL | re.MULTILINE
    )

    for m in rule_pattern.finditer(content):
        full_rule   = m.group(1).strip()
        rule_name   = m.group(2).strip()
        rule_body   = m.group(3).strip()

        if len(full_rule) < 50:
            continue

        # extract meta section
        meta = {}
        meta_section = re.search(r'meta:(.*?)(?:strings:|condition:)', rule_body,
                                 re.DOTALL)
        if meta_section:
            for kv in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', meta_section.group(1)):
                meta[kv.group(1).lower()] = kv.group(2)

        description = (meta.get("description", "") or
                       meta.get("desc", "") or
                       meta.get("comment", ""))
        author      = meta.get("author", "")
        reference   = meta.get("reference", "") or meta.get("url", "")
        family      = meta.get("malware", "") or meta.get("family", "")
        threat      = meta.get("threat", "") or meta.get("actor", "")

        # extract strings section
        strings_section = re.search(r'strings:(.*?)condition:', rule_body, re.DOTALL)
        strings_text    = strings_section.group(1).strip() if strings_section else ""

        # extract condition
        cond_section = re.search(r'condition:\s*(.+)', rule_body, re.DOTALL)
        condition    = cond_section.group(1).strip()[:300] if cond_section else ""

        text_parts = [
            f"YARA Detection Rule: {rule_name}",
            f"Repository: {repo_name}",
        ]
        if description:
            text_parts.append(f"Detects: {description}")
        if family:
            text_parts.append(f"Malware family: {family}")
        if threat:
            text_parts.append(f"Threat actor: {threat}")
        if author:
            text_parts.append(f"Author: {author}")
        if reference:
            text_parts.append(f"Reference: {reference}")
        if strings_text:
            text_parts.append(f"\nPattern signatures:\n{strings_text[:1000]}")
        if condition:
            text_parts.append(f"\nDetection condition:\n{condition}")
        text_parts.append(f"\nFull rule:\n{full_rule[:2000]}")

        docs.append({
            "source":      "yara_rule",
            "rule_name":   rule_name,
            "repo":        repo_name,
            "family":      family,
            "description": description,
            "url":         f"https://github.com/{repo_name}",
            "text":        "\n".join(text_parts),
        })

    return docs


def run_yara_rules(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["yara_rules"]
    if not c.get("enabled", True):
        print("[yara] Disabled.")
        return

    repos = c.get("repos", [])
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("yara_done_repos", []))

    for repo_cfg in repos:
        url  = repo_cfg["url"]
        dest = repo_cfg["dest"]
        name = url.rstrip("/").split("/")[-2] + "/" + url.rstrip("/").split("/")[-1]

        if name in done:
            continue

        print(f"[yara] Processing {name}...")
        ok = clone_repo(url, dest)
        if not ok:
            print(f"[yara] Clone failed: {url}")
            done.add(name)
            continue

        batch = []
        rule_count = 0
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".git"]
            for fname in files:
                if not fname.endswith((".yar", ".yara", ".rule")):
                    continue
                fpath = os.path.join(root, fname)
                docs  = parse_yara_file(fpath, name)
                batch.extend(docs)
                if len(batch) >= 500:
                    append_jsonl(raw_file, batch)
                    rule_count += len(batch)
                    batch = []

        if batch:
            append_jsonl(raw_file, batch)
            rule_count += len(batch)
        if rule_count:
            print(f"[yara] {name}: {rule_count} rules saved.")

        done.add(name)
        cp["yara_done_repos"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[yara] Done. {len(done)} repos processed.")


# ================================================================
# Sigma Rules
# ================================================================

def parse_sigma_file(fpath, repo_name):
    """Parse a Sigma YAML rule into a training example."""
    try:
        import yaml
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None

    title       = data.get("title", "") or ""
    description = data.get("description", "") or ""
    status      = data.get("status", "") or ""
    level       = data.get("level", "") or ""
    tags        = data.get("tags", []) or []
    references  = data.get("references", []) or []
    author      = data.get("author", "") or ""
    date        = data.get("date", "") or ""

    # get detection logic
    detection = data.get("detection", {}) or {}
    logsource = data.get("logsource", {}) or {}

    if not title and not description:
        return None

    # extract MITRE ATT&CK technique IDs from tags
    attack_ids = [t.replace("attack.", "").upper()
                  for t in tags if t.startswith("attack.t")]

    text_parts = [
        f"Sigma Detection Rule: {title}",
        f"Repository: {repo_name}",
        f"Severity: {level}" if level else "",
        f"Status: {status}" if status else "",
        f"Author: {author}" if author else "",
        f"Date: {date}" if date else "",
        f"ATT&CK techniques: {', '.join(attack_ids)}" if attack_ids else "",
        f"Log source: {logsource.get('product','')}/{logsource.get('category','')}" if logsource else "",
    ]
    if description:
        text_parts.append(f"\nDescription:\n{description}")
    if detection:
        import json
        text_parts.append(f"\nDetection logic:\n{json.dumps(detection, indent=2)[:1500]}")
    if references:
        text_parts.append(f"\nReferences:\n" + "\n".join(f"  - {r}" for r in references[:5]))

    return {
        "source":     "sigma_rule",
        "title":      title,
        "repo":       repo_name,
        "level":      level,
        "attack_ids": attack_ids,
        "url":        f"https://github.com/{repo_name}",
        "text":       "\n".join(p for p in text_parts if p),
    }


def run_sigma_rules(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["sigma_rules"]
    if not c.get("enabled", True):
        print("[sigma] Disabled.")
        return

    repos = c.get("repos", [])
    cp    = load_checkpoint(checkpoint_file)
    done  = set(cp.get("sigma_done_repos", []))

    for repo_cfg in repos:
        url  = repo_cfg["url"]
        dest = repo_cfg["dest"]
        name = url.rstrip("/").split("/")[-2] + "/" + url.rstrip("/").split("/")[-1]

        if name in done:
            continue

        print(f"[sigma] Processing {name}...")
        ok = clone_repo(url, dest)
        if not ok:
            print(f"[sigma] Clone failed: {url}")
            done.add(name)
            continue

        batch = []
        rule_count = 0
        for root, dirs, files in os.walk(dest):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != ".git"]
            for fname in files:
                if not fname.endswith((".yml", ".yaml")):
                    continue
                if any(skip in root for skip in ("tests", "test", "examples",
                                                   "deprecated", "unsupported")):
                    continue
                fpath = os.path.join(root, fname)
                doc   = parse_sigma_file(fpath, name)
                if doc:
                    batch.append(doc)
                if len(batch) >= 500:
                    append_jsonl(raw_file, batch)
                    rule_count += len(batch)
                    batch = []

        if batch:
            append_jsonl(raw_file, batch)
            rule_count += len(batch)
        if rule_count:
            print(f"[sigma] {name}: {rule_count} rules saved.")

        done.add(name)
        cp["sigma_done_repos"] = list(done)
        save_checkpoint(checkpoint_file, cp)

    print(f"[sigma] Done. {len(done)} repos processed.")


# ================================================================
# CWE Full Database
# ================================================================

def parse_cwe_xml(xml_content):
    """Parse the full CWE XML database into detailed training examples."""
    docs = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        print(f"[cwe] XML parse error: {e}")
        return docs

    # handle namespace
    ns_match = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
    ns = f"{{{ns_match}}}" if ns_match else ""

    def tag(name):
        return f"{ns}{name}"

    def text_of(el):
        if el is None:
            return ""
        return " ".join(el.itertext()).strip()

    weaknesses = root.findall(f".//{tag('Weakness')}")
    print(f"[cwe] Parsing {len(weaknesses)} weaknesses...")

    for w in tqdm(weaknesses, desc="CWE entries"):
        cwe_id   = w.get("ID", "")
        name     = w.get("Name", "")
        status   = w.get("Status", "")

        if status in ("Deprecated", "Obsolete"):
            continue

        # description
        desc_el  = w.find(tag("Description"))
        desc     = text_of(desc_el)

        # extended description
        ext_el   = w.find(tag("Extended_Description"))
        ext_desc = text_of(ext_el)

        if not desc:
            continue

        # relationships
        parents = [r.get("CWE_ID","") for r in
                   w.findall(f".//{tag('Related_Weakness')}[@Nature='ChildOf']")]
        peers   = [r.get("CWE_ID","") for r in
                   w.findall(f".//{tag('Related_Weakness')}[@Nature='PeerOf']")]

        # applicable platforms
        langs = [l.get("Name","") or l.get("Class","")
                 for l in w.findall(f".//{tag('Language')}")]
        techs = [t.get("Name","") or t.get("Class","")
                 for t in w.findall(f".//{tag('Technology')}")]

        # consequences
        consequences = []
        for c_el in w.findall(f".//{tag('Consequence')}"):
            scope  = text_of(c_el.find(tag("Scope")))
            impact = text_of(c_el.find(tag("Impact")))
            if scope or impact:
                consequences.append(f"{scope}: {impact}")

        # detection methods
        detections = []
        for d_el in w.findall(f".//{tag('Detection_Method')}"):
            method = text_of(d_el.find(tag("Method")))
            ddesc  = text_of(d_el.find(tag("Description")))
            if method:
                detections.append(f"{method}: {ddesc[:200]}")

        # mitigations
        mitigations = []
        for m_el in w.findall(f".//{tag('Mitigation')}"):
            phase = text_of(m_el.find(tag("Phase")))
            mdesc = text_of(m_el.find(tag("Description")))
            if mdesc:
                mitigations.append(f"[{phase}] {mdesc[:300]}" if phase else mdesc[:300])

        # demonstrative examples (vulnerable + safe code)
        examples = []
        for ex_el in w.findall(f".//{tag('Demonstrative_Example')}"):
            intro    = text_of(ex_el.find(tag("Intro_Text")))
            body_el  = ex_el.find(f".//{tag('Body_Text')}")
            body     = text_of(body_el)
            # code blocks
            code_els = ex_el.findall(f".//{tag('Example_Code')}")
            code_parts= [text_of(c2) for c2 in code_els]
            combined = (intro + "\n" + body + "\n" + "\n".join(code_parts[:2])).strip()
            if len(combined) > 30:
                examples.append(combined[:800])

        # observed examples (real CVEs)
        observed = []
        for o_el in w.findall(f".//{tag('Observed_Example')}"):
            ref     = text_of(o_el.find(tag("Reference")))
            o_desc  = text_of(o_el.find(tag("Description")))
            link    = text_of(o_el.find(tag("Link")))
            if ref and o_desc:
                observed.append(f"{ref}: {o_desc[:200]}")

        text_parts = [
            f"CWE-{cwe_id}: {name}",
            f"\nDescription:\n{desc}",
        ]
        if ext_desc:
            text_parts.append(f"\nExtended Description:\n{ext_desc[:1000]}")
        if langs:
            text_parts.append(f"\nAffected languages: {', '.join(l for l in langs if l)}")
        if techs:
            text_parts.append(f"Affected technologies: {', '.join(t for t in techs if t)}")
        if parents:
            text_parts.append(f"Parent weaknesses: CWE-{', CWE-'.join(parents[:5])}")
        if consequences:
            text_parts.append(f"\nConsequences:\n" +
                               "\n".join(f"  - {c}" for c in consequences[:5]))
        if detections:
            text_parts.append(f"\nDetection methods:\n" +
                               "\n".join(f"  - {d}" for d in detections[:4]))
        if mitigations:
            text_parts.append(f"\nMitigations:\n" +
                               "\n".join(f"  - {m}" for m in mitigations[:4]))
        if examples:
            text_parts.append(f"\nDemonstrative examples:\n" +
                               "\n\n".join(examples[:2]))
        if observed:
            text_parts.append(f"\nReal-world examples:\n" +
                               "\n".join(f"  - {o}" for o in observed[:5]))

        docs.append({
            "source": "cwe",
            "id":     f"CWE-{cwe_id}",
            "name":   name,
            "url":    f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            "text":   "\n".join(text_parts),
        })

    return docs


def run_cwe_full(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["cwe_full"]
    if not c.get("enabled", True):
        print("[cwe] Disabled.")
        return

    cp = load_checkpoint(checkpoint_file)
    if cp.get("cwe_full_done"):
        print("[cwe] Already done.")
        return

    print("[cwe] Downloading full CWE database...")
    try:
        r = safe_get(CWE_URL, timeout=60)
        r.raise_for_status()
    except Exception as e:
        print(f"[cwe] Download failed: {e}")
        return

    # unzip the XML
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            xml_files = [f for f in z.namelist() if f.endswith(".xml")]
            if not xml_files:
                print("[cwe] No XML file found in zip.")
                return
            xml_content = z.read(xml_files[0])
    except Exception as e:
        print(f"[cwe] Unzip failed: {e}")
        return

    docs = parse_cwe_xml(xml_content)
    if docs:
        append_jsonl(raw_file, docs)
        print(f"[cwe] {len(docs)} weakness entries saved.")

    cp["cwe_full_done"] = True
    save_checkpoint(checkpoint_file, cp)
    print("[cwe] Done.")
