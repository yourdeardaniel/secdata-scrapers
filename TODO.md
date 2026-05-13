# TODO

Known limitations and optional improvements. None of these are blocking —

## Recently fixed
- **arxiv-full**: was failing on every request with HTTP 429. Now has
  exponential backoff (30s → 600s cap), a polite User-Agent identifying
  the scraper, and only marks a search term "done" if it actually got
  papers. Fixed in `scrapers/academic_deep.py`.
- **Vendor (Ubuntu + Red Hat)**: Ubuntu endpoint changed to use
  `offset`/`limit` pagination instead of `details=1`, returning 422 on
  the old URL. Red Hat moved from `/labs/securitydataapi/` to
  `/hydra/rest/securitydata/`, returning 404 on the old URL. Both
  also had a "mark done even on failure" bug that prevented retries.
  Fixed in `scrapers/misc_sources.py`.
- **MSRC**: was hitting `/updates/{id}` with numeric months like
  `2024-01` — but the API uses three-letter month abbreviations
  (`2024-Jan`) AND the vulnerability data lives at `/cvrf/{id}` not
  `/updates/{id}`. Every request 404'd, every month got marked done,
  zero docs across all years. Fixed in `scrapers/misc_sources.py`.

the scraper works fine without addressing any of them. Come back when
you have time.

---

## Broken upstream sources (skip for now)

### CTFtime — returns 0 documents
**Status:** Index pages load successfully (500 pages, all HTTP 200), but
zero writeup URLs are extracted from them.

**Likely cause:** CTFtime changed their HTML structure or URL patterns.
The CSS selector in `scrapers/ctftime.py` `get_writeup_urls()` filters for
`href.startswith("/writeup/") and href.count("/") == 2`, which no longer
matches anything on the current site.

**To fix:**
1. Visit https://ctftime.org/writeups/ in a browser
2. Inspect the HTML of one of the writeup links — note the actual URL pattern
3. Update the selector logic in `scrapers/ctftime.py` to match
4. Re-run `python3 main.py --ctftime`

**Estimated yield if fixed:** ~3% of total dataset (~40,000 documents).

---

### HackerOne — returns 0 documents
**Status:** GraphQL endpoint at hackerone.com/graphql responds, but
queries return zero results.

**Likely cause:** HackerOne tightened their public Hacktivity API in
2023-2024. Anonymous queries now return empty results without erroring.
Bulk access requires authentication.

**To fix:**
- Option A (preferred): Create a HackerOne account, generate an API token,
  add `hackerone_token` field to config.yaml, and modify `scrapers/hackerone.py`
  to send the token in the Authorization header
- Option B: Switch to scraping individual public disclosure URLs one-by-one
  via the regular site (much slower, weeks at HackerOne's rate limit)

**Estimated yield if fixed:** ~5% of total dataset (~50,000 documents).

---

### OSV — returns 0 documents per ecosystem
**Status:** All 9 OSV ecosystems return 0 vulnerabilities (PyPI, npm,
Go, Maven, RubyGems, crates.io, NuGet, Packagist, Linux).

**Cause:** The scraper calls `POST /v1/query` with just `{"ecosystem": "PyPI"}`
which is the wrong API usage. The `/v1/query` endpoint is designed for
specific package lookups (e.g. "vulns affecting django"), not bulk
ecosystem listings. OSV silently returns empty results for invalid queries.

**To fix:** Rewrite `scrapers/osv.py` to use the OSV bulk download bucket:
- Each ecosystem has a downloadable ZIP at
  `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`
- e.g. `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`
- Extract the JSON files from each ZIP
- Parse with the existing `parse_vuln()` function (that part still works)

**Priority:** Low. OSV's data overlaps ~80% with NVD + GHSA which are
already scraped. The unique content is ~5-10K Linux distro advisories
and OSS-Fuzz findings.

**Estimated yield if fixed:** ~30-50K additional documents (most
duplicating NVD/GHSA after dedup).

---

## Configuration improvements

### Unix.SE security filter too narrow
**Status:** `--se-dumps` processed unix.stackexchange.com successfully
(593,538 rows parsed) but kept 0 questions because the SECURITY_TAGS
filter list is too narrow for how Unix.SE users tag posts.

**Where:** `scrapers/stackexchange_dumps.py` — `SECURITY_TAGS` constant.

**To fix (option 1 — recommended):** Expand SECURITY_TAGS to include
unix power-user tags that often cover security content:
- `iptables`, `firewall`, `selinux`, `apparmor`, `permissions`
- `sudo`, `setuid`, `chroot`, `containers`
- `gpg`, `openssl`, `keyring`, `gnome-keyring`
- `audit`, `auditd`, `logging`, `syslog`

**To fix (option 2 — get more data, lower quality):** In
`config.yaml.example` change unix.stackexchange.com's `security_filter: true`
to `false`. This includes all questions regardless of tag, which gets
much more data but a lot will be off-topic (general Linux Q&A).

**After fixing:** Existing 51,258 SE pairs are checkpointed and will be
skipped on re-run. Only the fixed site will reprocess. Re-run with
`python3 main.py --se-dumps`.

**Estimated yield if fixed:** ~10,000-50,000 additional Unix.SE pairs
depending on how aggressively the filter is expanded.

---

## Other followups

(Add new items as you find them)

-
