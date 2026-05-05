import os, time, subprocess, requests
from pathlib import Path
from tqdm import tqdm
from utils import (
    safe_get,
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    clone_repo,
)

TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".markdown"}
MAX_FILE_SIZE = 500_000

def search_repos(query, token, max_repos):
    headers = {"Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"}
    repos = {}
    page = 1
    while len(repos) < min(max_repos, 1000):
        try:
            r = safe_get("https://api.github.com/search/repositories",
                source="github_repos",
                headers=headers,
                params={"q": query, "sort": "stars", "order": "desc",
                        "per_page": 100, "page": page}, timeout=15)
            if r is None:
                time.sleep(60); continue
            if r.status_code == 403:
                reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
                time.sleep(max(reset - time.time(), 0) + 5)
                continue
            if r.status_code == 422:
                break
            r.raise_for_status()
            items = r.json().get("items", [])
            if not items:
                break
            for item in items:
                repos[item["id"]] = item
            page += 1
            time.sleep(1)
        except Exception as e:
            print(f"\n[github_repos] Search error: {e}")
            break
    return list(repos.values())

def extract_text_files(folder, repo_name, repo_url, stars):
    docs = []
    try:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules",".git")]
            for fname in files:
                if Path(fname).suffix.lower() not in TEXT_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    if len(text) < 150:
                        continue
                    docs.append({"source": "github",
                                 "repo": repo_name, "stars": stars,
                                 "url": repo_url,
                                 "file": os.path.relpath(fpath, folder),
                                 "text": text[:8000]})
                except Exception:
                    pass
    except Exception:
        pass
    return docs

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["github"]
    if not c.get("enabled", True):
        print("[github_repos] Disabled."); return
    token = cfg["api"].get("github_token", "")
    if not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[github_repos] No token — skipping."); return
    max_repos = c.get("max_repos", 500)
    delay = c.get("delay_seconds", 0.5)
    clone_dir = c.get("clone_dir", "./data/repos")
    queries = c.get("queries", [])
    ensure_dirs(clone_dir)
    cp = load_checkpoint(checkpoint_file)
    done_repos = set(cp.get("github_done_repos", []))
    all_repos = {}
    for query in queries:
        for repo in search_repos(query, token, max_repos):
            all_repos[repo["id"]] = repo
        time.sleep(1)
    to_process = sorted([r for r in all_repos.values()
                         if str(r["id"]) not in done_repos],
                        key=lambda x: x.get("stargazers_count", 0), reverse=True)[:max_repos]
    print(f"[github_repos] {len(to_process)} repos to process.")
    for repo in tqdm(to_process, desc="GitHub repos"):
        rid = str(repo["id"])
        dest = os.path.join(clone_dir, f"repo_{rid}")
        if not os.path.exists(dest):
            ok = clone_repo(repo["clone_url"], dest)
            if not ok:
                done_repos.add(rid); continue
        docs = extract_text_files(dest, repo["full_name"], repo["html_url"],
                                  repo.get("stargazers_count", 0))
        if docs:
            append_jsonl(raw_file, docs)
        done_repos.add(rid)
        cp["github_done_repos"] = list(done_repos)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)
    print(f"[github_repos] Done. {len(done_repos)}")
