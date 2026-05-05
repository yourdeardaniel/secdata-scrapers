import time, requests
from tqdm import tqdm
from utils import (
    safe_post,
    append_jsonl, load_checkpoint, save_checkpoint,
)

GRAPHQL_URL = "https://api.github.com/graphql"
QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem, $cursor: String) {
  securityVulnerabilities(first: 100 after: $cursor ecosystem: $ecosystem
    orderBy: { field: UPDATED_AT direction: DESC }) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId summary description severity publishedAt
        cvss { score }
        cwes(first: 5) { nodes { cweId name } }
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

def fetch_page(ecosystem, cursor, token):
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    for attempt in range(3):
        try:
            r = safe_post(GRAPHQL_URL,
                source="github_advisories",
                json={"query": QUERY, "variables": {"ecosystem": ecosystem.upper(), "cursor": cursor}},
                headers=headers, timeout=20)
            if r is None:
                return None
            return r.json()
        except Exception:
            time.sleep(10)
    return None

def parse_node(node):
    advisory = node.get("advisory") or {}
    package = node.get("package") or {}
    ghsa_id = advisory.get("ghsaId", "")
    summary = advisory.get("summary", "") or ""
    desc = advisory.get("description", "") or ""
    if not desc and not summary:
        return None
    severity = advisory.get("severity", "") or ""
    cvss_obj = advisory.get("cvss") or {}
    cvss_score = str(cvss_obj.get("score", "")) if cvss_obj else ""
    cwes = [f"{c.get('cweId','')}: {c.get('name','')}"
            for c in (advisory.get("cwes") or {}).get("nodes", []) or []]
    pkg_name = package.get("name", "") or ""
    ecosystem = package.get("ecosystem", "") or ""
    vuln_range = node.get("vulnerableVersionRange", "") or ""
    patched_obj = node.get("firstPatchedVersion")
    patched = patched_obj.get("identifier", "") if patched_obj else "unpatched"
    parts = [f"GitHub Security Advisory: {ghsa_id}"]
    if pkg_name: parts.append(f"Package: {pkg_name} ({ecosystem})")
    if severity: parts.append(f"Severity: {severity}" + (f" (CVSS {cvss_score})" if cvss_score else ""))
    if cwes: parts.append(f"CWE: {', '.join(cwes)}")
    if vuln_range: parts.append(f"Vulnerable versions: {vuln_range}")
    if patched: parts.append(f"Patched in: {patched}")
    if summary: parts.append(f"\nSummary: {summary}")
    if desc: parts.append(f"\nDetails:\n{desc[:3000]}")
    return {"source": "github_advisory", "id": ghsa_id,
            "url": f"https://github.com/advisories/{ghsa_id}",
            "severity": severity, "ecosystem": ecosystem,
            "text": "\n".join(parts)}

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["github_advisories"]
    if not c.get("enabled", True):
        print("[ghsa] Disabled."); return
    token = cfg["api"].get("github_token", "")
    if not token or token == "YOUR_GITHUB_TOKEN_HERE":
        print("[ghsa] No token — skipping."); return
    max_per = c.get("max_per_ecosystem", 2000)
    delay = c.get("delay_seconds", 0.5)
    ecosystems = [e.upper() for e in c.get("ecosystems", [])]
    cp = load_checkpoint(checkpoint_file)
    done_ecosys = set(cp.get("ghsa_done_ecosystems", []))
    for ecosystem in [e for e in ecosystems if e not in done_ecosys]:
        cursor = None
        count = 0
        print(f"[ghsa] {ecosystem}...")
        with tqdm(total=max_per, desc=f"  {ecosystem}") as pbar:
            while count < max_per:
                data = fetch_page(ecosystem, cursor, token)
                if not data:
                    break
                vuln_data = (data.get("data") or {}).get("securityVulnerabilities") or {}
                nodes = vuln_data.get("nodes", []) or []
                page_info = vuln_data.get("pageInfo") or {}
                batch = [p for n in nodes for p in [parse_node(n)] if p]
                if batch:
                    append_jsonl(raw_file, batch)
                    count += len(batch)
                    pbar.update(len(batch))
                if not page_info.get("hasNextPage"):
                    break
                cursor = page_info.get("endCursor")
                time.sleep(delay)
        done_ecosys.add(ecosystem)
        cp["ghsa_done_ecosystems"] = list(done_ecosys)
        save_checkpoint(checkpoint_file, cp)
    print("[ghsa] Done.")
