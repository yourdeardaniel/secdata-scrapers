"""
Metasploit deep scraper.
Clones metasploit-framework and parses every Ruby module file,
extracting structured description, references, targets, and code.
Each module becomes a rich training example combining vulnerability
context, exploit methodology, and working code.
"""
import os
import re
import subprocess
from tqdm import tqdm

from utils import append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs

METASPLOIT_URL = "https://github.com/rapid7/metasploit-framework"


def clone_metasploit(dest):
    ensure_dirs(dest)
    if os.path.exists(os.path.join(dest, ".git")):
        subprocess.run(["git", "-C", dest, "pull", "--quiet"],
                       capture_output=True, timeout=120)
        return True
    print("[metasploit] Cloning metasploit-framework (~3GB)...")
    result = subprocess.run(
        ["git", "clone", "--depth=1", "--filter=blob:limit=5m",
         METASPLOIT_URL, dest],
        timeout=600,
    )
    return result.returncode == 0


def extract_ruby_string(content, key):
    """Extract a string value from Ruby module metadata."""
    # Try %q{...} multiline format
    pattern_mq = rf"'{key}'\s*=>\s*%q\{{(.*?)\}}"
    m = re.search(pattern_mq, content, re.DOTALL)
    if m:
        return m.group(1).strip()

    # Try <<~HEREDOC format
    pattern_hd = rf"'{key}'\s*=>\s*<<[~-]?([A-Z]+)\n(.*?)\n\s*\1"
    m = re.search(pattern_hd, content, re.DOTALL)
    if m:
        return m.group(2).strip()

    # Try single-quoted string
    pattern_sq = rf"'{key}'\s*=>\s*'((?:[^'\\]|\\.)*)'"
    m = re.search(pattern_sq, content)
    if m:
        return m.group(1).strip()

    # Try double-quoted string
    pattern_dq = rf"'{key}'\s*=>\s*\"((?:[^\"\\]|\\.)*)\""
    m = re.search(pattern_dq, content)
    if m:
        return m.group(1).strip()

    return ""


def extract_references(content):
    """Extract CVE, EDB, MSB, URL references from module."""
    refs = []
    for m in re.finditer(
        r"\[\s*'(CVE|MSB|EDB|URL|BID|OSVDB|ZDI|US-CERT-VU)'\s*,\s*'([^']+)'",
        content
    ):
        refs.append(f"{m.group(1)}-{m.group(2)}")
    return refs


def extract_targets(content):
    """Extract target platform/version info."""
    targets = []
    for m in re.finditer(r"'([^']{3,60})'\s*,\s*\{[^}]*'Arch'", content):
        targets.append(m.group(1))
    # fallback: look for Target blocks
    if not targets:
        for m in re.finditer(r"Target\.new\s*\(\s*'([^']+)'", content):
            targets.append(m.group(1))
    return targets[:10]


def extract_check_method(content):
    """Extract the check() method if present — shows fingerprinting logic."""
    m = re.search(r"def check\b(.*?)(?=\n  def |\nend\b)", content, re.DOTALL)
    if m:
        return m.group(1).strip()[:1500]
    return ""


def extract_exploit_method(content):
    """Extract the exploit() or run() method."""
    for method in ("def exploit\b", "def run\b", "def execute\b"):
        m = re.search(rf"{method}(.*?)(?=\n  def |\nend\b)", content, re.DOTALL)
        if m:
            return m.group(1).strip()[:2000]
    return ""


def parse_module(rb_path, module_type, repo_base):
    """Parse a single Metasploit Ruby module file."""
    try:
        with open(rb_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    name        = extract_ruby_string(content, "Name")
    description = extract_ruby_string(content, "Description")

    if not description or len(description) < 50:
        return None

    references = extract_references(content)
    targets    = extract_targets(content)
    check_code = extract_check_method(content)
    exploit_code= extract_exploit_method(content)

    # get platform info
    platform_match = re.search(r"'Platform'\s*=>\s*\[?'?([^'\],]+)", content)
    platform = platform_match.group(1).strip() if platform_match else ""

    # get rank
    rank_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
    disclosure = rank_match.group(1).strip() if rank_match else ""

    # get author
    authors = re.findall(r"Author\.new\s*\(\s*'([^']+)'|'Author'\s*=>\s*\[?'([^']+)'",
                         content)
    author_list = [a[0] or a[1] for a in authors[:5] if a[0] or a[1]]

    rel_path = os.path.relpath(rb_path, repo_base)

    text_parts = [
        f"Metasploit Module: {name}",
        f"Type: {module_type}",
        f"Path: {rel_path}",
    ]
    if platform:
        text_parts.append(f"Platform: {platform}")
    if disclosure:
        text_parts.append(f"Disclosure date: {disclosure}")
    if author_list:
        text_parts.append(f"Authors: {', '.join(author_list)}")
    if references:
        text_parts.append(f"References: {', '.join(references[:10])}")
    if targets:
        text_parts.append(f"Targets: {', '.join(targets)}")

    text_parts.append(f"\nDescription:\n{description}")

    if check_code:
        text_parts.append(f"\nCheck method (fingerprinting):\n{check_code}")
    if exploit_code:
        text_parts.append(f"\nExploit method:\n{exploit_code}")

    return {
        "source":      "metasploit",
        "name":        name,
        "type":        module_type,
        "path":        rel_path,
        "references":  references,
        "targets":     targets,
        "platform":    platform,
        "url":         f"{METASPLOIT_URL}/blob/master/{rel_path}",
        "text":        "\n".join(text_parts),
    }


def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["metasploit_deep"]
    if not c.get("enabled", True):
        print("[metasploit] Disabled.")
        return

    clone_dir    = c.get("clone_dir", "./data/repos/metasploit-framework")
    module_types = c.get("module_types", ["modules/exploits"])

    cp        = load_checkpoint(checkpoint_file)
    done_paths= set(cp.get("metasploit_done", []))

    ok = clone_metasploit(clone_dir)
    if not ok:
        print("[metasploit] Clone failed.")
        return

    # collect all .rb files across requested module directories
    all_rb_files = []
    for mtype in module_types:
        mdir = os.path.join(clone_dir, mtype)
        if not os.path.exists(mdir):
            continue
        for root, dirs, files in os.walk(mdir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname.endswith(".rb"):
                    fpath = os.path.join(root, fname)
                    rel   = os.path.relpath(fpath, clone_dir)
                    mtype_label = mtype.split("/")[-1].rstrip("s")  # exploits→exploit
                    all_rb_files.append((fpath, mtype_label, rel))

    new_files = [(f, t, r) for f, t, r in all_rb_files if r not in done_paths]
    print(f"[metasploit] {len(all_rb_files)} modules total, "
          f"{len(new_files)} to parse.")

    batch = []
    for rb_path, mtype_label, rel in tqdm(new_files, desc="Metasploit modules"):
        doc = parse_module(rb_path, mtype_label, clone_dir)
        if doc:
            batch.append(doc)
        done_paths.add(rel)

        if len(batch) >= 200:
            append_jsonl(raw_file, batch)
            cp["metasploit_done"] = list(done_paths)
            save_checkpoint(checkpoint_file, cp)
            batch = []

    if batch:
        append_jsonl(raw_file, batch)
        cp["metasploit_done"] = list(done_paths)
        save_checkpoint(checkpoint_file, cp)

    print(f"[metasploit] Done. {len(done_paths)} modules.")
