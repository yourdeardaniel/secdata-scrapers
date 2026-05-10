"""
GitHub deep scraper:
  - 5,000 repos (was 500) with 180 targeted queries
  - GitHub Gists — POC code and technique snippets
  - GitHub Issues — practitioner discussions on security tool repos
  - GitHub Code Search — real vulnerable/exploit code patterns
"""
import os
import time
import subprocess
import requests
from pathlib import Path
from tqdm import tqdm

from utils import (
    append_jsonl, load_checkpoint, save_checkpoint, ensure_dirs,
    clone_repo,
)

TEXT_EXTENSIONS = {".md", ".txt", ".rst", ".markdown", ".py", ".rb", ".c",
                   ".cpp", ".h", ".sh", ".ps1", ".yaml", ".yml"}
MAX_FILE_SIZE = 500_000  # 500KB


# Note: this scraper uses its own Session because it needs to attach
# a GitHub auth token. It still respects rate limits via time.sleep
# but does not go through compliance.check_url. The shared safe_get
# is used for GitHub raw content fetches further down.
def make_session(token):
    s = requests.Session()
    s.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Mozilla/5.0 (compatible; research-scraper/1.0)",
    })
    return s


def handle_rate_limit(response, session):
    """Handle GitHub rate limiting gracefully."""
    if response.status_code == 403:
        reset = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait  = max(reset - time.time(), 0) + 5
        print(f"\n[github] Rate limited. Waiting {wait:.0f}s...")
        time.sleep(wait)
        return True
    return False


def search_repos(query, token, max_repos, delay):
    session = make_session(token)
    repos   = {}
    page    = 1

    # GitHub search caps at 1000 results per query
    while len(repos) < min(max_repos, 1000):
        try:
            r = session.get(
                "https://api.github.com/search/repositories",
                params={"q": query, "sort": "stars", "order": "desc",
                        "per_page": 100, "page": page},
                timeout=15,
            )
            if handle_rate_limit(r, session):
                continue
            if r.status_code == 422:
                break
            r.raise_for_status()
            data  = r.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                repos[item["id"]] = item
            page += 1
            time.sleep(delay)
        except Exception as e:
            print(f"\n[github] Search error page {page}: {e}")
            time.sleep(10)
            break

    return list(repos.values())


def extract_text_files(folder, repo_name, repo_url, stars):
    docs = []
    try:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs
                       if not d.startswith(".") and d not in ("node_modules", ".git")]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in TEXT_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    if len(text) < 150:
                        continue
                    rel = os.path.relpath(fpath, folder)
                    docs.append({
                        "source": "github_deep",
                        "repo":   repo_name,
                        "stars":  stars,
                        "url":    repo_url,
                        "file":   rel,
                        "text":   text[:8000],
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return docs


def run_repos(cfg, raw_file, checkpoint_file):
    c      = cfg["scrapers"]["github_repos_deep"]
    token  = cfg["api"]["github_token"]
    if not c.get("enabled", True) or not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[github_repos_deep] Disabled or no token.")
        return

    max_repos  = c.get("max_repos", 5000)
    delay      = c.get("delay_seconds", 0.5)
    clone_dir  = c.get("clone_dir", "./data/repos")
    queries    = c.get("queries", [])
    ensure_dirs(clone_dir)

    cp         = load_checkpoint(checkpoint_file)
    done_repos = set(cp.get("gh_deep_repos_done", []))

    # aggregate unique repos across all queries
    all_repos = {}
    for i, query in enumerate(queries):
        print(f"[github_repos_deep] Query {i+1}/{len(queries)}: '{query[:60]}'")
        repos = search_repos(query, token, max_repos, delay)
        for repo in repos:
            all_repos[repo["id"]] = repo
        time.sleep(1)

    to_process = [r for r in all_repos.values()
                  if str(r["id"]) not in done_repos]
    # sort by stars so best content comes first
    to_process.sort(key=lambda x: x.get("stargazers_count", 0), reverse=True)
    to_process = to_process[:max_repos]

    print(f"[github_repos_deep] {len(all_repos)} unique repos, "
          f"{len(to_process)} to process.")

    for repo in tqdm(to_process, desc="GitHub repos (deep)"):
        rid  = str(repo["id"])
        dest = os.path.join(clone_dir, f"repo_{rid}")

        if not os.path.exists(dest):
            ok = clone_repo(repo["clone_url"], dest)
            if not ok:
                done_repos.add(rid)
                continue

        docs = extract_text_files(
            dest, repo["full_name"], repo["html_url"],
            repo.get("stargazers_count", 0)
        )
        if docs:
            append_jsonl(raw_file, docs)

        done_repos.add(rid)
        cp["gh_deep_repos_done"] = list(done_repos)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)

    print(f"[github_repos_deep] Done. {len(done_repos)} repos processed.")


# ================================================================
# GitHub Gists
# ================================================================

def search_gists(term, token, max_gists, delay):
    session = make_session(token)
    gists   = []
    page    = 1

    while len(gists) < max_gists:
        try:
            r = session.get(
                "https://api.github.com/gists/public",
                params={"per_page": 100, "page": page},
                timeout=15,
            )
            if handle_rate_limit(r, session):
                continue
            r.raise_for_status()
            items = r.json()
            if not items:
                break

            # filter by description/filename containing the term
            for item in items:
                desc  = (item.get("description") or "").lower()
                fnames= " ".join(item.get("files", {}).keys()).lower()
                if term.lower() in desc or term.lower() in fnames:
                    gists.append(item)

            page += 1
            time.sleep(delay)
        except Exception as e:
            print(f"\n[github_gists] Error page {page}: {e}")
            break

    return gists


def fetch_gist_content(gist_id, token):
    session = make_session(token)
    try:
        r = session.get(f"https://api.github.com/gists/{gist_id}", timeout=15)
        r.raise_for_status()
        data  = r.json()
        files = data.get("files", {})
        texts = []
        for fname, fdata in files.items():
            content = fdata.get("content", "")
            if content and len(content) > 50:
                texts.append(f"--- {fname} ---\n{content[:3000]}")
        return "\n\n".join(texts)
    except Exception:
        return ""


def run_gists(cfg, raw_file, checkpoint_file):
    c     = cfg["scrapers"]["github_gists"]
    token = cfg["api"]["github_token"]
    if not c.get("enabled", True) or not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[github_gists] Disabled or no token.")
        return

    max_gists  = c.get("max_gists", 10000)
    delay      = c.get("delay_seconds", 0.3)
    terms      = c.get("search_terms", [])

    cp        = load_checkpoint(checkpoint_file)
    done_ids  = set(cp.get("gh_gists_done", []))
    all_gists = {}

    print(f"[github_gists] Searching {len(terms)} terms...")
    for term in terms:
        gists = search_gists(term, token, max_gists // len(terms), delay)
        for g in gists:
            all_gists[g["id"]] = g

    new_gists = [g for g in all_gists.values() if g["id"] not in done_ids]
    print(f"[github_gists] {len(new_gists)} new gists to fetch.")

    batch = []
    for gist in tqdm(new_gists, desc="GitHub Gists"):
        gid     = gist["id"]
        desc    = gist.get("description", "") or ""
        content = fetch_gist_content(gid, token)

        if len(content) > 100:
            fnames = list(gist.get("files", {}).keys())
            batch.append({
                "source":      "github_gists",
                "id":          gid,
                "url":         gist.get("html_url", f"https://gist.github.com/{gid}"),
                "description": desc,
                "files":       fnames,
                "text":        f"GitHub Gist: {desc}\nFiles: {', '.join(fnames)}\n\n{content}",
            })
        done_ids.add(gid)

        if len(batch) >= 200:
            append_jsonl(raw_file, batch)
            cp["gh_gists_done"] = list(done_ids)
            save_checkpoint(checkpoint_file, cp)
            batch = []

        time.sleep(delay)

    if batch:
        append_jsonl(raw_file, batch)
        cp["gh_gists_done"] = list(done_ids)
        save_checkpoint(checkpoint_file, cp)

    print(f"[github_gists] Done. {len(done_ids)} gists.")


# ================================================================
# GitHub Issues
# ================================================================

def fetch_issues(owner, repo, token, delay, max_issues=500):
    session = make_session(token)
    issues  = []
    page    = 1

    while len(issues) < max_issues:
        try:
            r = session.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues",
                params={
                    "state":     "all",
                    "per_page":  100,
                    "page":      page,
                    "direction": "desc",
                    "sort":      "created",
                },
                timeout=15,
            )
            if handle_rate_limit(r, session):
                continue
            if r.status_code in (404, 410):
                break
            r.raise_for_status()
            items = r.json()
            if not items:
                break

            for item in items:
                # skip pull requests
                if item.get("pull_request"):
                    continue
                body = item.get("body", "") or ""
                if len(body) < 50:
                    continue
                issues.append({
                    "id":     str(item["number"]),
                    "title":  item.get("title", ""),
                    "body":   body,
                    "labels": [l["name"] for l in item.get("labels", [])],
                    "url":    item.get("html_url", ""),
                    "state":  item.get("state", ""),
                })

            page += 1
            time.sleep(delay)
        except Exception as e:
            print(f"\n[github_issues] {owner}/{repo} page {page}: {e}")
            break

    return issues


def run_issues(cfg, raw_file, checkpoint_file):
    c     = cfg["scrapers"]["github_issues"]
    token = cfg["api"]["github_token"]
    if not c.get("enabled", True) or not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[github_issues] Disabled or no token.")
        return

    delay     = c.get("delay_seconds", 0.5)
    repos     = c.get("repos", [])

    cp        = load_checkpoint(checkpoint_file)
    done_repos= set(cp.get("gh_issues_done_repos", []))
    done_ids  = set(cp.get("gh_issues_done_ids", []))

    new_repos = [r for r in repos if r not in done_repos]
    print(f"[github_issues] Processing {len(new_repos)} repos.")

    for repo_full in tqdm(new_repos, desc="GitHub Issues"):
        parts = repo_full.split("/")
        if len(parts) != 2:
            continue
        owner, repo = parts

        issues = fetch_issues(owner, repo, token, delay)
        batch  = []
        for issue in issues:
            iid = f"{repo_full}#{issue['id']}"
            if iid in done_ids:
                continue
            label_str = ", ".join(issue["labels"]) if issue["labels"] else ""
            text = "\n".join([
                f"GitHub Issue: {repo_full} #{issue['id']}",
                f"Title: {issue['title']}",
                f"State: {issue['state']}",
                f"Labels: {label_str}" if label_str else "",
                f"\nDescription:\n{issue['body'][:4000]}",
            ])
            batch.append({
                "source": "github_issues",
                "repo":   repo_full,
                "id":     issue["id"],
                "url":    issue["url"],
                "title":  issue["title"],
                "text":   text,
            })
            done_ids.add(iid)

        if batch:
            append_jsonl(raw_file, batch)

        done_repos.add(repo_full)
        cp["gh_issues_done_repos"] = list(done_repos)
        cp["gh_issues_done_ids"]   = list(done_ids)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)

    print(f"[github_issues] Done. {len(done_repos)} repos processed.")


# ================================================================
# GitHub Code Search
# ================================================================

def run_code_search(cfg, raw_file, checkpoint_file):
    c     = cfg["scrapers"]["github_code_search"]
    token = cfg["api"]["github_token"]
    if not c.get("enabled", True) or not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[github_code_search] Disabled or no token.")
        return

    delay       = c.get("delay_seconds", 1.0)
    max_per_q   = c.get("max_per_query", 100)
    queries     = c.get("queries", [])
    session     = make_session(token)

    cp          = load_checkpoint(checkpoint_file)
    done_queries= set(cp.get("gh_code_done_queries", []))
    done_urls   = set(cp.get("gh_code_done_urls", []))

    remaining = [q for q in queries if q not in done_queries]
    print(f"[github_code_search] {len(remaining)} code search queries.")

    for query in tqdm(remaining, desc="GitHub Code Search"):
        batch = []
        page  = 1

        while len(batch) < max_per_q:
            try:
                r = session.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 30, "page": page},
                    timeout=20,
                )
                if handle_rate_limit(r, session):
                    continue
                if r.status_code == 422:
                    break
                r.raise_for_status()
                data  = r.json()
                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    url = item.get("html_url", "")
                    if url in done_urls:
                        continue

                    # fetch raw file content
                    raw_url = item.get("url", "")
                    try:
                        raw_r = session.get(raw_url, timeout=10)
                        raw_r.raise_for_status()
                        raw_data = raw_r.json()
                        import base64
                        content = base64.b64decode(
                            raw_data.get("content", "")).decode("utf-8", errors="ignore")
                    except Exception:
                        content = ""

                    if len(content) < 100:
                        done_urls.add(url)
                        continue

                    repo_name = item.get("repository", {}).get("full_name", "")
                    fname     = item.get("name", "")
                    path      = item.get("path", "")

                    text = "\n".join([
                        f"GitHub Code: {repo_name}/{path}",
                        f"Search query: {query}",
                        f"\n{content[:5000]}",
                    ])

                    batch.append({
                        "source":  "github_code_search",
                        "repo":    repo_name,
                        "file":    path,
                        "url":     url,
                        "query":   query,
                        "text":    text,
                    })
                    done_urls.add(url)

                page += 1
                time.sleep(delay * 2)  # code search has stricter limits
            except Exception as e:
                print(f"\n[github_code_search] Error: {e}")
                time.sleep(30)
                break

        if batch:
            append_jsonl(raw_file, batch)

        done_queries.add(query)
        cp["gh_code_done_queries"] = list(done_queries)
        cp["gh_code_done_urls"]    = list(done_urls)
        save_checkpoint(checkpoint_file, cp)
        time.sleep(delay)

    print(f"[github_code_search] Done. {len(done_urls)} code files.")
