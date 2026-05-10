"""
Stack Exchange data dump processor.
Downloads are done manually — see config.yaml for instructions.
This script processes the 7z dump files locally with no API calls.

Handles: security, reverseengineering, crypto, unix, stackoverflow
"""
import os
import io
import time
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from tqdm import tqdm

from utils import append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs

# Tags that flag a post as security-relevant (used for unix + stackoverflow)
SECURITY_TAGS = {
    "security", "vulnerability", "exploit", "penetration-testing",
    "sql-injection", "xss", "buffer-overflow", "cryptography", "encryption",
    "authentication", "authorization", "privilege-escalation", "malware",
    "reverse-engineering", "network-security", "web-security", "ctf",
    "hacking", "firewall", "ids", "intrusion-detection", "forensics",
    "memory-corruption", "heap", "stack-overflow", "shellcode", "rop",
    "aslr", "dep", "nx", "canary", "format-string", "race-condition",
    "use-after-free", "integer-overflow", "zero-day", "cve", "owasp",
    "burp-suite", "metasploit", "wireshark", "nmap", "kali-linux",
    "sudo", "setuid", "capabilities", "selinux", "apparmor",
    "ssl", "tls", "certificate", "pki", "hash", "hmac", "rsa", "aes",
    "ssh", "vpn", "dnssec", "jwt", "oauth", "saml", "cors", "csrf",
    "password", "bruteforce", "phishing", "social-engineering",
    "android-security", "ios-security", "firmware", "embedded",
}


def strip_html(html_text):
    """Strip HTML tags and return plain text."""
    if not html_text:
        return ""
    return BeautifulSoup(html_text, "html.parser").get_text("\n", strip=True)


def extract_7z(archive_path, dest_dir, target_file="Posts.xml"):
    """Extract a specific file from a 7z archive."""
    ensure_dirs(dest_dir)
    out_path = os.path.join(dest_dir, target_file)
    if os.path.exists(out_path):
        return out_path

    try:
        import py7zr
        print(f"  Extracting {target_file} from {os.path.basename(archive_path)}...")
        with py7zr.SevenZipFile(archive_path, mode="r") as z:
            z.extract(targets=[target_file], path=dest_dir)
        return out_path
    except ImportError:
        print("  py7zr not installed. Run: pip install py7zr")
        print("  Alternatively, extract manually: 7z e archive.7z Posts.xml -o./dest/")
        return None
    except Exception as e:
        print(f"  Extraction failed: {e}")
        return None


def parse_posts_xml(xml_path, min_q_score, min_a_score, security_filter):
    """
    Stream-parse Posts.xml from a Stack Exchange dump.
    Returns (questions dict, answers dict).
    Memory-efficient — processes one element at a time.
    """
    questions = {}
    answers   = {}
    total     = 0

    print(f"  Parsing {os.path.basename(xml_path)}...")
    context = ET.iterparse(xml_path, events=("end",))

    for event, elem in context:
        if elem.tag != "row":
            elem.clear()
            continue

        total += 1
        if total % 100000 == 0:
            print(f"  ... {total:,} rows processed, "
                  f"{len(questions):,} questions, {len(answers):,} answers")

        post_type = elem.get("PostTypeId", "")
        score     = int(elem.get("Score", "0"))
        post_id   = elem.get("Id", "")

        if post_type == "1":  # question
            if score < min_q_score:
                elem.clear()
                continue

            raw_tags = elem.get("Tags", "")
            # tags look like <python><security><ctf>
            tags = [t.strip() for t in raw_tags.replace("<","").split(">") if t.strip()]

            if security_filter and not any(t.lower() in SECURITY_TAGS for t in tags):
                elem.clear()
                continue

            questions[post_id] = {
                "title":    elem.get("Title", ""),
                "body":     elem.get("Body", ""),
                "tags":     tags,
                "score":    score,
                "accepted": elem.get("AcceptedAnswerId", ""),
            }

        elif post_type == "2":  # answer
            if score < min_a_score:
                elem.clear()
                continue
            parent = elem.get("ParentId", "")
            # keep highest-scored answer per question
            if parent not in answers or answers[parent]["score"] < score:
                answers[parent] = {
                    "body":  elem.get("Body", ""),
                    "score": score,
                    "id":    post_id,
                }

        elem.clear()

    print(f"  Parsed {total:,} total rows → "
          f"{len(questions):,} questions, {len(answers):,} answers")
    return questions, answers


def process_site(site_cfg, dump_dir, extract_dir, min_q_score, min_a_score,
                 raw_file, checkpoint_file):
    site_name       = site_cfg["name"]
    archive_name    = site_cfg["file"]
    security_filter = site_cfg.get("security_filter", False)
    enabled         = site_cfg.get("enabled", True)

    if not enabled:
        print(f"[se_dump] {site_name} disabled in config.")
        return

    cp  = load_checkpoint(checkpoint_file)
    key = f"se_dump_{site_name.replace('.', '_')}"
    if cp.get(key):
        print(f"[se_dump] {site_name} already processed.")
        return

    archive_path = os.path.join(dump_dir, archive_name)
    if not os.path.exists(archive_path):
        print(f"[se_dump] Archive not found: {archive_path}")
        print(f"  Download from: https://archive.org/download/stackexchange/{archive_name}")
        print(f"  Place in: {dump_dir}/")
        return

    site_extract_dir = os.path.join(extract_dir, site_name)
    posts_path       = extract_7z(archive_path, site_extract_dir)
    if not posts_path:
        return

    questions, answers = parse_posts_xml(
        posts_path, min_q_score, min_a_score, security_filter
    )

    print(f"[se_dump] Building training pairs for {site_name}...")
    batch       = []
    pairs_saved = 0

    for qid, q in tqdm(questions.items(), desc=f"  {site_name}"):
        # prefer accepted answer, fall back to highest-scored
        ans = answers.get(q["accepted"]) or answers.get(qid)
        if not ans:
            continue

        q_text   = strip_html(q["body"])
        ans_text = strip_html(ans["body"])

        if len(ans_text) < 60:
            continue

        text = "\n".join(filter(None, [
            f"Site: {site_name}",
            f"Tags: {', '.join(q['tags'])}",
            f"Question score: {q['score']}  Answer score: {ans['score']}",
            f"\nQuestion: {q['title']}",
            q_text[:700] if q_text else "",
            f"\nAnswer:\n{ans_text[:4000]}",
        ]))

        batch.append({
            "source":  "stackexchange_dump",
            "site":    site_name,
            "id":      qid,
            "url":     f"https://{site_name}/questions/{qid}",
            "title":   q["title"],
            "tags":    q["tags"],
            "text":    text,
            "license": "CC-BY-SA-4.0",
        })
        pairs_saved += 1

        if len(batch) >= 2000:
            append_jsonl(raw_file, batch)
            batch = []

    if batch:
        append_jsonl(raw_file, batch)

    # clean up extracted XML to save disk space
    if os.path.exists(posts_path):
        os.remove(posts_path)
        print(f"  Removed {posts_path} to free disk space.")

    cp[key] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[se_dump] {site_name}: {pairs_saved:,} pairs saved.")


def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["stackexchange_dumps"]
    if not c.get("enabled", True):
        print("[se_dump] Disabled.")
        return

    dump_dir      = c.get("dump_dir", "./data/se_dumps")
    extract_dir   = c.get("extract_dir", "./data/se_extracted")
    min_q_score   = c.get("min_question_score", 2)
    min_a_score   = c.get("min_answer_score", 1)
    sites         = c.get("sites", [])

    ensure_dirs(dump_dir, extract_dir)

    print(f"[se_dump] Processing {len(sites)} Stack Exchange sites.")
    print(f"  Dump directory: {dump_dir}")
    print(f"  Download dumps from: https://archive.org/download/stackexchange/")
    print()

    for site_cfg in sites:
        process_site(
            site_cfg, dump_dir, extract_dir,
            min_q_score, min_a_score,
            raw_file, checkpoint_file,
        )
