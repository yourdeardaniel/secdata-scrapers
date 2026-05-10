"""
Linux kernel security commit scraper.
Clones the full kernel repo and extracts security-relevant commits
with their diffs — each is a mini vulnerability analysis + fix.
"""
import os
import re
import subprocess
import time
from tqdm import tqdm

from utils import append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs

KERNEL_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"

# Precompiled regex for speed
SECURITY_RE = None


def build_security_re(keywords):
    global SECURITY_RE
    pattern = "|".join(re.escape(k) for k in keywords)
    SECURITY_RE = re.compile(pattern, re.IGNORECASE)


def clone_kernel(dest, shallow=False):
    """Clone or update the Linux kernel repo."""
    ensure_dirs(dest)
    git_dir = os.path.join(dest, ".git")

    if os.path.exists(git_dir):
        print("[kernel] Updating existing clone...")
        subprocess.run(["git", "-C", dest, "fetch", "--quiet"],
                       capture_output=True, timeout=600)
        return True

    print(f"[kernel] Cloning Linux kernel ({'shallow' if shallow else 'full'})...")
    print("  This downloads ~4GB and may take 20–60 minutes.")

    cmd = ["git", "clone"]
    if shallow:
        cmd += ["--depth=10000"]  # last 10k commits only
    cmd += [KERNEL_URL, dest]

    result = subprocess.run(cmd, timeout=7200)  # 2 hour timeout
    return result.returncode == 0


def get_security_commits(dest, keywords, max_commits):
    """
    Get commit hashes where the message matches security keywords.
    Uses git log with grep for efficiency — never loads full repo into memory.
    """
    print("[kernel] Scanning commit history for security keywords...")

    # build grep arguments
    grep_args = []
    for kw in keywords:
        grep_args += ["--grep", kw]

    cmd = [
        "git", "-C", dest, "log",
        "--all",
        "--format=%H|||%s|||%ae|||%ai",  # hash, subject, author email, date
        "--no-merges",
        "-i",  # case insensitive grep
    ] + grep_args + [f"--max-count={max_commits}"]

    result = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=300, cwd=dest)
    if result.returncode != 0:
        print(f"[kernel] git log failed: {result.stderr[:200]}")
        return []

    commits = []
    for line in result.stdout.strip().split("\n"):
        if "|||" not in line:
            continue
        parts = line.split("|||", 3)
        if len(parts) >= 4:
            commits.append({
                "hash":    parts[0].strip(),
                "subject": parts[1].strip(),
                "author":  parts[2].strip(),
                "date":    parts[3].strip()[:10],
            })

    print(f"[kernel] Found {len(commits):,} security-relevant commits.")
    return commits


def get_commit_detail(dest, commit_hash):
    """Get full commit message and diff for a single commit."""
    try:
        # full commit message
        msg_result = subprocess.run(
            ["git", "-C", dest, "log", "--format=%B", "-n", "1", commit_hash],
            capture_output=True, text=True, timeout=30,
        )
        message = msg_result.stdout.strip()

        # diff — limit to 200 lines to keep examples focused
        diff_result = subprocess.run(
            ["git", "-C", dest, "show", "--stat", "--no-color",
             "--diff-filter=M",  # only modified files
             commit_hash],
            capture_output=True, text=True, timeout=30,
        )
        diff_raw = diff_result.stdout.strip()

        # extract changed files and actual diff
        diff_lines = diff_raw.split("\n")
        # keep stat header + up to 150 lines of actual diff
        stat_end = 0
        for i, line in enumerate(diff_lines):
            if line.startswith("diff --git"):
                stat_end = i
                break
        stat    = "\n".join(diff_lines[:stat_end])
        diff    = "\n".join(diff_lines[stat_end:stat_end + 150])

        return message, stat, diff

    except Exception:
        return "", "", ""


def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["kernel_commits"]
    if not c.get("enabled", True):
        print("[kernel] Disabled.")
        return

    clone_dir   = c.get("clone_dir", "./data/kernel")
    shallow     = c.get("shallow", False)
    keywords    = c.get("security_keywords", [])
    max_commits = c.get("max_commits", 300000)

    build_security_re(keywords)

    cp          = load_checkpoint(checkpoint_file)
    done_hashes = set(cp.get("kernel_done_hashes", []))

    # clone or update repo
    dest = os.path.join(clone_dir, "linux")
    ok   = clone_kernel(dest, shallow)
    if not ok:
        print("[kernel] Clone failed.")
        return

    # get all security commits
    commits   = get_security_commits(dest, keywords, max_commits)
    remaining = [c2 for c2 in commits if c2["hash"] not in done_hashes]

    print(f"[kernel] {len(remaining):,} commits to process.")

    batch = []
    for commit in tqdm(remaining, desc="Kernel security commits"):
        h = commit["hash"]
        message, stat, diff = get_commit_detail(dest, h)

        if not message:
            done_hashes.add(h)
            continue

        # extract CVE references
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", message, re.IGNORECASE)

        # extract subsystem from subject line (usually "subsystem: fix description")
        subject = commit["subject"]
        subsystem = ""
        if ":" in subject:
            subsystem = subject.split(":")[0].strip()

        text_parts = [
            f"Linux Kernel Security Commit: {h[:12]}",
            f"Date: {commit['date']}",
            f"Subsystem: {subsystem}" if subsystem else "",
            f"CVEs: {', '.join(cves)}" if cves else "",
            f"\nCommit Message:\n{message[:3000]}",
        ]
        if stat:
            text_parts.append(f"\nFiles Changed:\n{stat[:500]}")
        if diff:
            text_parts.append(f"\nDiff (first 150 lines):\n{diff[:3000]}")

        batch.append({
            "source":    "kernel_commit",
            "hash":      h,
            "subject":   subject,
            "date":      commit["date"],
            "subsystem": subsystem,
            "cves":      cves,
            "url":       f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={h}",
            "text":      "\n".join(p for p in text_parts if p),
        })
        done_hashes.add(h)

        if len(batch) >= 500:
            append_jsonl(raw_file, batch)
            cp["kernel_done_hashes"] = list(done_hashes)
            save_checkpoint(checkpoint_file, cp)
            batch = []

    if batch:
        append_jsonl(raw_file, batch)
        cp["kernel_done_hashes"] = list(done_hashes)
        save_checkpoint(checkpoint_file, cp)

    print(f"[kernel] Done. {len(done_hashes):,} commits processed.")
