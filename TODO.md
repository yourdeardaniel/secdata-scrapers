# TODO

Known limitations and optional improvements. None of these are blocking —
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
