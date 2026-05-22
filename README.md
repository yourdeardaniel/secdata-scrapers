# secdata-scrapers

Collects raw cybersecurity research documents from public sources for use
in AI training dataset construction. The scraper covers **143 source flags
spanning ~192 underlying data sources** (some flags scrape multiple repos,
e.g. `--yara` runs across 7 YARA rule repositories).

**Requires Python 3.9 or newer.** Tested on 3.9, 3.10, 3.11, 3.12.

**This tool collects raw text. It does not generate training examples.**
For the conversion pipeline, see
[secdata-pipeline](https://github.com/yourdeardaniel/secdata-pipeline).

---

## Output

A full run of this scraper produced
[secdata-raw](https://huggingface.co/datasets/deardaniel/secdata-raw):
**4,051,139 documents** from 50+ working sources, released on Hugging Face
under CC BY-SA 4.0. The dataset card on Hugging Face has the full breakdown
and source manifest. Headline numbers:

| Category | Sources | Documents |
|---|---|---:|
| Curated GitHub security repos (10,000 highest-starred) | `gh-repos-deep` | 3,469,231 |
| NVD CVE database | `nvd` | 320,557 |
| Stack Exchange archives (security, RE, crypto) | `se-dumps` | 51,256 |
| ExploitDB | `exploitdb` | 47,021 |
| Red Hat security advisories | `vendor` | 43,063 |
| Linux kernel security commits | `kernel` | 38,771 |
| Microsoft Security Response Center | `msrc` | 21,458 |
| YARA detection rules (7 repos) | `yara` | 20,226 |
| GitHub Security Advisories (7 ecosystems) | `ghsa` | 15,757 |
| Sigma detection rules | `sigma` | 7,348 |
| Metasploit modules | `metasploit` | 4,569 |
| MITRE ATT&CK + CAPEC + CWE | `attack`, `capec`, `cwe` | 3,854 |
| Atomic Red Team | `atomic-red` | 2,138 |
| OWASP guides (MASTG, API, WSTG) | `owasp-*` | 1,653 |
| Plus 30+ specialty sources | (various) | ~3,500 |
| **Total** | | **4,051,139** |

Specialty sources cover cloud security, mobile security, cryptography,
forensics, AI/ML security, pentest methodology, network/protocol security,
and reverse engineering training.

---

## Quick start

```bash
# 1. Clone and install
git clone https://github.com/yourdeardaniel/secdata-scrapers
cd secdata-scrapers
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp config.yaml.example config.yaml
nano config.yaml   # add your GitHub token (free: github.com/settings/tokens)
                   # plus optional NVD and AlienVault keys for higher rate limits

# 3. Read the ethical use guidelines
cat ETHICAL_USE.md

# 4. See what's available
python3 main.py --estimate

# 5. Run fast sources first (~2 hours)
python3 main.py --fast

# 6. Check progress
python3 main.py --stats

# 7. Run Stack Exchange dumps (highest ROI, auto-downloads)
python3 main.py --se-dumps

# 8. Run everything else (takes days, use tmux)
tmux new -s scrape
source venv/bin/activate
python3 main.py --nvd --exploitdb --ghsa --kernel --vendor --msrc
python3 main.py --gh-repos-deep --metasploit --yara --sigma
```

The full set of source flags is available via `python3 main.py --help`.

---

## Disk requirements

A complete run is disk-heavy because some sources clone large Git
repositories before extracting content.

| Data | Size |
|---|---|
| Stack Exchange dump archives | ~6-90 GB depending on which sites |
| Cloned GitHub repos (gh-repos-deep) | up to 25 GB during scraping |
| Linux kernel clone | ~4 GB |
| `raw_docs.jsonl` final output | ~5-6 GB |
| Logs and checkpoints | ~1 GB |
| **Total recommended free space** | **150 GB** |

The `gh-repos-deep` scraper now cleans up cloned repos after extracting
their markdown content, so peak disk usage during the run is much lower
than the cumulative footprint of all cloned repos.

---

## How long it takes

A complete scrape of all working sources takes roughly **5-7 days** on a
modest VPS (4 cores, 8GB RAM, 100Mbps connection). Most of that time is
the `--gh-repos-deep` source, which clones and extracts documentation from
10,000 GitHub repositories. The smaller structured sources (NVD, MITRE,
Stack Exchange archives) take hours each.

The scraper is fully resumable — every source maintains its own checkpoint
file. Killing and restarting picks up where it left off.

---

## Safety features

- **robots.txt compliance** — checked automatically before each domain
- **Hard rate limits** — per-domain minimum delays that cannot be overridden
- **API endpoint allowlist** — `utils/compliance.py` prevents accidental
  requests to non-approved paths
- **Credential scrubbing** — API keys, tokens, and PII removed before
  saving. Documents include a `_had_credentials_scrubbed` field indicating
  whether scrubbing occurred
- **Audit logging** — every URL accessed logged to
  `data/audit/scrape_audit.log`
- **Domain blocklist** — paywalled and explicitly restricted sites blocked
- **Operational attack content pre-filtering** — documents that read as
  raw attack instructions without educational framing are skipped at
  collection (light prefilter; full safety treatment happens in the
  conversion pipeline)

See [ETHICAL_USE.md](ETHICAL_USE.md) for full documentation.

---

## Output format

`data/raw/raw_docs.jsonl` — one JSON object per line. The schema varies
by source (intentional: see the Hugging Face dataset card for rationale),
but all documents share `source`, `text`, and `url` fields:

```json
{
  "source": "nvd",
  "id": "CVE-2021-44228",
  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "text": "CVE: CVE-2021-44228\nPublished: 2021-12-10\n..."
}
```

The pipeline that consumes this data
([secdata-pipeline](https://github.com/yourdeardaniel/secdata-pipeline))
handles the multi-schema structure when converting to training examples.

Transfer the output to your conversion VPS or upload directly to Hugging
Face:

```bash
# Option A: transfer to another VPS
bash scripts/transfer_send.sh raw    # on the scraper machine
bash scripts/transfer_receive.sh IP 8888 raw    # on the receiving machine

# Option B: upload to Hugging Face
hf upload your-username/your-dataset data/raw \
    --repo-type dataset \
    --include "raw_docs.jsonl"
```

---

## Known issues and broken sources

This scraper hits 192 different sources. Some are broken upstream, some
have partial coverage, and the v1.0 run documented exactly which. The
pipeline handles failures gracefully — failures are logged and the scraper
continues — but you should know what to expect.

The authoritative list is in [TODO.md](TODO.md). Summary:

### Recently fixed

- **MSRC** — was 404'ing all requests because of an endpoint/format
  mismatch (numeric month vs three-letter abbreviation, `/updates/{id}`
  vs `/cvrf/{id}`). Now yields ~21K advisories.
- **Red Hat vendor advisories** — endpoint had moved; old URL returned
  404. Now yields ~43K advisories.

### Partial coverage

- **Ubuntu Security Notices** — fix applied (correct API params) but
  Ubuntu's CDN intermittently returns HTTP 504, which currently aborts
  the run rather than retrying. ~320 advisories captured per attempt.
  Fix needed: retry-with-backoff on 504, similar to arxiv's 429 handling.
- **arXiv full-text** — has polite User-Agent and exponential backoff,
  but bursts of failed requests still get the IP throttled for hours.
  Practical workaround: run from a different IP. Only 16 papers captured
  in the v1.0 run; expected yield with a fresh IP is ~15-25K.

### Broken upstream

- **CTFtime** — CSS selectors no longer match the site structure. Returns
  0 documents. Estimated yield if fixed: ~40,000 docs.
- **HackerOne** — public API tightened in 2023-2024; bulk anonymous
  queries now return empty. Requires authenticated access.
- **OSV** — current scraper uses wrong API approach. Should switch to
  the bulk download bucket at
  `osv-vulnerabilities.storage.googleapis.com`. Low priority due to high
  overlap with NVD/GHSA.
- **Project Zero issues** — Google migrated their tracker to
  issues.chromium.org. The P0 blog (`--p0`) is unaffected.
- **Chromium issue tracker** — same migration as P0 issues.

### Sources that work reliably

All MITRE sources (ATT&CK, CAPEC, D3FEND, CWE), NVD, GitHub Advisories
(with token), Stack Exchange dumps, all Git-based sources (YARA, Sigma,
Atomic Red Team, kernel, etc.), OWASP repositories, Red Hat, MSRC,
ExploitDB.

### PRs welcome

Each broken source has a documented fix path in TODO.md. If you'd like to
contribute, those are good first issues. Open an issue mentioning which
item you're tackling to avoid duplicate work.

---

## Sources you may want to skip

If you have limited disk space or want a smaller initial dataset:

- Skip `--gh-repos-deep` — 10,000 repos, peak ~25GB disk during scrape,
  ~5 days runtime. Without this, the dataset shrinks from 4M docs to
  ~600K but consists entirely of structured high-signal sources.
- Skip `--kernel` — 39K commits, ~4GB clone, ~12 minutes after the fix
  for the double-path bug, but still a substantial download.
- Skip `--se-dumps` for `stackoverflow` — 80GB additional download. The
  other Stack Exchange sites (security, RE, crypto) are much smaller and
  more relevant.

Disable sources in `config.yaml` rather than removing scraper code.

---

## License

**Code:** MIT — see [LICENSE](LICENSE).

**Collected data:** Each source has its own license. Most importantly,
**Stack Exchange content is CC BY-SA 4.0**, which has share-alike
implications for any dataset you publish. Read
[LICENSING_NOTES.md](LICENSING_NOTES.md) before redistributing collected
data or releasing a derivative dataset.

The scrapers tag every Stack Exchange document with
`"license": "CC-BY-SA-4.0"` so attribution metadata is preserved through
the conversion pipeline. The full secdata-raw release uses CC BY-SA 4.0
overall to satisfy this requirement.

---

## Versioning

- **v1.0.0** — Initial public release of the scraper (143 source flags
  across ~192 sources). The first complete run produced secdata-raw v1.0
  (4,051,139 documents on Hugging Face).
- See [CHANGELOG.md](CHANGELOG.md) for details.

---

## Related repositories

- [secdata-raw](https://huggingface.co/datasets/deardaniel/secdata-raw) —
  the 4M-document raw corpus produced by this scraper, on Hugging Face
- [secdata-pipeline](https://github.com/yourdeardaniel/secdata-pipeline) —
  the LLM-based conversion pipeline that turns raw documents into
  instruction-tuning examples, with a three-layer safety architecture

---

## Contributing

PRs welcome, especially for:

- The broken sources documented in TODO.md (Ubuntu 504 retry, OSV bulk
  download, CTFtime selectors, HackerOne authenticated access)
- Additional scrapers for sources not yet covered
- Bug fixes and rate-limit tuning for existing sources
- Documentation improvements

For bug reports or methodology questions, open an issue.
