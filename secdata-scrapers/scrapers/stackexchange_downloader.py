"""
Stack Exchange automatic downloader + processor.
Downloads official data dumps from archive.org, then processes them.
No manual steps required.

Files downloaded:
  security.stackexchange.com.7z         ~2 GB
  reverseengineering.stackexchange.com.7z ~200 MB
  crypto.stackexchange.com.7z           ~300 MB
  unix.stackexchange.com.7z             ~4 GB
  stackoverflow.com.7z                  ~80 GB (optional, disabled by default)
"""

# Stack Exchange content is licensed under CC BY-SA 4.0.
# All documents emitted are tagged with "license": "CC-BY-SA-4.0".
import os
import io
import time
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from utils import append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs, safe_get

ARCHIVE_BASE = "https://archive.org/download/stackexchange"

# Sites to download — ordered smallest to largest so you get data fast
SITES = [
    {
        "name":            "reverseengineering.stackexchange.com",
        "file":            "reverseengineering.stackexchange.com.7z",
        "approx_size_gb":  0.2,
        "security_filter": False,
    },
    {
        "name":            "crypto.stackexchange.com",
        "file":            "crypto.stackexchange.com.7z",
        "approx_size_gb":  0.3,
        "security_filter": False,
    },
    {
        "name":            "security.stackexchange.com",
        "file":            "security.stackexchange.com.7z",
        "approx_size_gb":  2.0,
        "security_filter": False,
    },
    {
        "name":            "unix.stackexchange.com",
        "file":            "unix.stackexchange.com.7z",
        "approx_size_gb":  4.0,
        "security_filter": True,   # only keep security-tagged posts
    },
    {
        "name":            "stackoverflow.com",
        "file":            "stackoverflow.com.7z",
        "approx_size_gb":  80.0,
        "security_filter": True,
        "enabled":         False,  # set True in config to enable
    },
]

SECURITY_TAGS = {
    "security","vulnerability","exploit","penetration-testing","sql-injection",
    "xss","buffer-overflow","cryptography","encryption","authentication",
    "authorization","privilege-escalation","malware","reverse-engineering",
    "network-security","web-security","ctf","hacking","firewall","forensics",
    "memory-corruption","heap","shellcode","rop","aslr","dep","format-string",
    "race-condition","use-after-free","integer-overflow","zero-day","cve","owasp",
    "burp-suite","metasploit","wireshark","nmap","kali-linux","sudo","setuid",
    "ssl","tls","certificate","hash","hmac","rsa","aes","ssh","vpn","jwt",
    "oauth","saml","cors","csrf","password","bruteforce","phishing",
    "android-security","ios-security","firmware","embedded","assembly",
}


def download_file(url, dest_path, expected_gb=None):
    """
    Stream-download a file with a progress bar.
    Resumes partial downloads automatically.
    """
    # check if already fully downloaded
    if os.path.exists(dest_path):
        local_size = os.path.getsize(dest_path)
        if expected_gb and local_size > expected_gb * 0.95 * 1e9:
            print(f"  Already downloaded: {dest_path}")
            return True

    # get remote file size
    try:
        head = requests.head(url, timeout=30, allow_redirects=True)
        remote_size = int(head.headers.get("content-length", 0))
    except Exception:
        remote_size = 0

    # resume support
    resume_pos = 0
    headers = {}
    if os.path.exists(dest_path):
        resume_pos = os.path.getsize(dest_path)
        if resume_pos > 0 and remote_size > 0:
            if resume_pos >= remote_size:
                print(f"  Already complete: {dest_path}")
                return True
            headers["Range"] = f"bytes={resume_pos}-"
            print(f"  Resuming from {resume_pos / 1e9:.2f} GB...")

    ensure_dirs(os.path.dirname(dest_path))

    try:
        r = safe_get(url, headers=headers, stream=True, timeout=60)
        # 206 = partial content (resume), 200 = full download
        if r.status_code not in (200, 206):
            print(f"  Download failed: HTTP {r.status_code} for {url}")
            return False

        total = remote_size or int(r.headers.get("content-length", 0))
        mode  = "ab" if resume_pos > 0 and r.status_code == 206 else "wb"

        desc  = os.path.basename(dest_path)
        with open(dest_path, mode) as f:
            with tqdm(
                total=total,
                initial=resume_pos if mode == "ab" else 0,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=f"  {desc[:40]}",
            ) as pbar:
                for chunk in r.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))

        print(f"  Download complete: {dest_path}")
        return True

    except KeyboardInterrupt:
        print(f"\n  Download interrupted. Run again to resume.")
        return False
    except Exception as e:
        print(f"  Download error: {e}")
        return False


def extract_posts_xml(archive_path, extract_dir):
    """Extract Posts.xml from a .7z archive."""
    posts_path = os.path.join(extract_dir, "Posts.xml")
    if os.path.exists(posts_path):
        return posts_path

    ensure_dirs(extract_dir)

    try:
        import py7zr
        print(f"  Extracting Posts.xml from {os.path.basename(archive_path)}...")
        with py7zr.SevenZipFile(archive_path, mode="r") as z:
            # only extract Posts.xml — skip the rest (saves hours on large archives)
            z.extract(targets=["Posts.xml"], path=extract_dir)
        if os.path.exists(posts_path):
            print(f"  Extracted to {posts_path}")
            return posts_path
    except ImportError:
        print("  py7zr not installed — trying system 7z command...")
        try:
            import subprocess
            result = subprocess.run(
                ["7z", "e", archive_path, "Posts.xml", f"-o{extract_dir}", "-y"],
                capture_output=True, timeout=7200,
            )
            if result.returncode == 0 and os.path.exists(posts_path):
                return posts_path
            print(f"  7z extraction failed: {result.stderr.decode()[:200]}")
        except Exception as e:
            print(f"  System 7z not found: {e}")
            print("  Install: apt-get install p7zip-full")
    except Exception as e:
        print(f"  Extraction failed: {e}")

    return None


def strip_html(html_text):
    if not html_text:
        return ""
    return BeautifulSoup(html_text, "html.parser").get_text("\n", strip=True)


def parse_posts_xml(xml_path, min_q_score, min_a_score, security_filter):
    """
    Stream-parse Posts.xml efficiently.
    Returns (questions dict, answers dict).
    """
    questions = {}
    answers   = {}
    total     = 0

    context = ET.iterparse(xml_path, events=("end",))

    for event, elem in context:
        if elem.tag != "row":
            elem.clear()
            continue

        total += 1
        if total % 500_000 == 0:
            print(f"    {total:,} rows → {len(questions):,} questions, {len(answers):,} answers")

        post_type = elem.get("PostTypeId", "")
        score     = int(elem.get("Score", "0"))
        post_id   = elem.get("Id", "")

        if post_type == "1":  # question
            if score < min_q_score:
                elem.clear()
                continue

            raw_tags = elem.get("Tags", "")
            tags = [t.strip() for t in raw_tags.replace("<", "").split(">") if t.strip()]

            if security_filter and not any(t.lower() in SECURITY_TAGS for t in tags):
                elem.clear()
                continue

            questions[post_id] = {
                "title":    elem.get("Title", ""),
                "body":     elem.get("Body", ""),
                "tags":     tags,
                "score":    score,
                "accepted": elem.get("AcceptedAnswerId", ""),
                "link":     elem.get("Id", ""),
            }

        elif post_type == "2":  # answer
            if score < min_a_score:
                elem.clear()
                continue
            parent = elem.get("ParentId", "")
            if parent not in answers or answers[parent]["score"] < score:
                answers[parent] = {
                    "body":  elem.get("Body", ""),
                    "score": score,
                }

        elem.clear()

    print(f"    Parsed {total:,} rows → {len(questions):,} Q, {len(answers):,} A")
    return questions, answers


def process_site(site_cfg, dump_dir, extract_dir, min_q_score, min_a_score,
                 raw_file, checkpoint_file):
    """Download, extract, parse, and save one SE site."""
    site_name       = site_cfg["name"]
    archive_name    = site_cfg["file"]
    security_filter = site_cfg.get("security_filter", False)
    enabled         = site_cfg.get("enabled", True)

    if not enabled:
        print(f"[se] {site_name} disabled in config.")
        return 0

    cp  = load_checkpoint(checkpoint_file)
    key = f"se_dump_{site_name.replace('.', '_').replace('-', '_')}"
    if cp.get(key):
        print(f"[se] {site_name} already processed.")
        return 0

    # ── Step 1: Download ──────────────────────────────────────────
    archive_path = os.path.join(dump_dir, archive_name)
    download_url = f"{ARCHIVE_BASE}/{archive_name}"

    print(f"\n[se] {site_name}")
    print(f"  Size: ~{site_cfg.get('approx_size_gb', '?')} GB")
    print(f"  Downloading from {download_url}...")

    ok = download_file(download_url, archive_path, site_cfg.get("approx_size_gb"))
    if not ok:
        print(f"[se] Download failed for {site_name}. Skipping.")
        return 0

    # ── Step 2: Extract Posts.xml ─────────────────────────────────
    site_extract_dir = os.path.join(extract_dir, site_name)
    posts_path       = extract_posts_xml(archive_path, site_extract_dir)
    if not posts_path:
        print(f"[se] Extraction failed for {site_name}.")
        return 0

    # ── Step 3: Parse ─────────────────────────────────────────────
    print(f"  Parsing {site_name}...")
    questions, answers = parse_posts_xml(
        posts_path, min_q_score, min_a_score, security_filter
    )

    # ── Step 4: Build training pairs ──────────────────────────────
    print(f"  Building training pairs...")
    batch       = []
    pairs_saved = 0

    for qid, q in tqdm(questions.items(), desc=f"  {site_name}", unit="Q"):
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
            "source": "stackexchange_dump",
            "site":   site_name,
            "id":     qid,
            "url":    f"https://{site_name}/questions/{qid}",
            "title":  q["title"],
            "tags":   q["tags"],
            "text":   text,
        })
        pairs_saved += 1

        if len(batch) >= 2000:
            append_jsonl(raw_file, batch)
            batch = []

    if batch:
        append_jsonl(raw_file, batch)

    # ── Step 5: Cleanup extracted XML (saves disk space) ──────────
    if os.path.exists(posts_path):
        os.remove(posts_path)
        print(f"  Removed {posts_path} (freeing disk space).")

    # mark done
    cp[key] = True
    save_checkpoint(checkpoint_file, cp)
    print(f"[se] {site_name}: {pairs_saved:,} training pairs saved.")
    return pairs_saved


def run(cfg, raw_file, checkpoint_file):
    """
    Main entry point. Downloads and processes all enabled SE sites.
    Resumes automatically if interrupted.
    """
    c = cfg["scrapers"]["stackexchange_dumps"]
    if not c.get("enabled", True):
        print("[se_dumps] Disabled in config.")
        return

    dump_dir      = c.get("dump_dir", "./data/se_dumps")
    extract_dir   = c.get("extract_dir", "./data/se_extracted")
    min_q_score   = c.get("min_question_score", 2)
    min_a_score   = c.get("min_answer_score", 1)
    sites_cfg     = c.get("sites", [])

    ensure_dirs(dump_dir, extract_dir)

    # build site list — merge hardcoded defaults with config overrides
    site_map = {s["name"]: s for s in SITES}
    for s in sites_cfg:
        if s["name"] in site_map:
            site_map[s["name"]].update(s)

    enabled_sites = [s for s in site_map.values() if s.get("enabled", True)]

    total_gb = sum(s.get("approx_size_gb", 0) for s in enabled_sites)
    print(f"\n[se_dumps] {len(enabled_sites)} sites to process.")
    print(f"[se_dumps] Total download size: ~{total_gb:.1f} GB")
    print(f"[se_dumps] Downloads saved to: {dump_dir}")
    print(f"[se_dumps] Processing in order: smallest first\n")

    total_pairs = 0
    for site in sorted(enabled_sites, key=lambda s: s.get("approx_size_gb", 0)):
        pairs = process_site(
            site, dump_dir, extract_dir,
            min_q_score, min_a_score,
            raw_file, checkpoint_file,
        )
        total_pairs += pairs

    print(f"\n[se_dumps] All done. Total pairs saved: {total_pairs:,}")
    print(f"[se_dumps] Archive files kept in {dump_dir} (reuse if you re-run).")
