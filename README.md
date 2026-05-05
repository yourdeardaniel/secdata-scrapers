# secdata-scrapers

Collects raw cybersecurity research documents from **192 public sources** (143 scraper modules — some modules wrap multiple data sources, e.g. `--yara` runs across 7 YARA rule repositories) for use in AI training dataset construction.

**Requires Python 3.9 or newer.** Tested on 3.9, 3.10, 3.11, 3.12.

**This tool collects raw text. It does not generate training examples.**
For the conversion pipeline, see [secdata-pipeline](https://github.com/your-username/secdata-pipeline).

---

## What it collects

| Category | Sources | Raw docs |
|---|---|---|
| Vulnerability databases | NVD, GHSA, OSV, MSRC, CISA, Bugzilla | ~249,000 |
| Q&A (Stack Exchange dumps) | security, RE, crypto, unix | ~270,000 |
| Linux kernel commits | Security-tagged commits with diffs | ~200,000 |
| GitHub (deep) | 5,000 repos, gists, issues, code search | ~200,000 |
| Threat intelligence | OTX, ThreatFox, URLhaus, MalwareBazaar | ~92,500 |
| Detection rules | YARA (7 repos), Sigma (4 repos), Suricata | ~68,000 |
| CTF and writeups | CTFtime, GitHub repos, Gists, 0xdf | ~56,000 |
| Academic papers | arXiv (full), USENIX, NDSS, IEEE S&P, ACM CCS | ~22,500 |
| CERT/CC vuln notes | Structured vulnerability analysis | ~10,000 |
| Security blogs | 40+ research blogs and feeds | ~16,000 |
| ... | 192 sources total | **~1,374,960** |

Full source list: `python3 main.py --estimate`

---

## Quick start

```bash
# 1. Clone and install
git clone https://github.com/your-username/secdata-scrapers
cd secdata-scrapers
pip install -r requirements.txt

# 2. Configure
cp config.yaml.example config.yaml
nano config.yaml   # add your GitHub token (free: github.com/settings/tokens)

# 3. Read the ethical use guidelines
cat ETHICAL_USE.md

# 4. Run fast sources first (~2 hours)
python main.py --fast

# 5. Check progress
python main.py --stats

# 6. Run Stack Exchange dumps (highest ROI, auto-downloads)
python main.py --se-dumps

# 7. Run everything else (takes weeks, use tmux)
tmux new -s scrape
python main.py --nvd --ctftime --github --hackerone --exploitdb
python main.py --gh-repos-deep --kernel --arxiv-full
```

---

## Disk requirements

| Data | Size |
|---|---|
| SE dump archives | ~6–90 GB |
| Cloned repos | ~25 GB |
| Linux kernel clone | ~4 GB |
| raw_docs.jsonl output | ~8–15 GB |
| **Total recommended** | **150 GB** |

---

## Safety features

- **robots.txt compliance** — checked automatically before each domain
- **Hard rate limits** — per-domain minimum delays that cannot be overridden
- **Credential scrubbing** — API keys, tokens, and PII removed before saving
- **Audit logging** — every URL accessed logged to `data/audit/scrape_audit.log`
- **Domain blocklist** — paywalled and explicitly restricted sites blocked

See [ETHICAL_USE.md](ETHICAL_USE.md) for full documentation.

---

## Output

`data/raw/raw_docs.jsonl` — one JSON object per line:

```json
{
  "source": "nvd",
  "id": "CVE-2021-44228",
  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  "text": "CVE: CVE-2021-44228\nPublished: 2021-12-10\n..."
}
```

Transfer this file to your conversion VPS:
```bash
bash scripts/transfer_send.sh raw    # on this machine
bash scripts/transfer_receive.sh IP 8888 raw    # on H100
```

---

## License

**Code:** MIT — see [LICENSE](LICENSE).

**Collected data:** Each source has its own license. Most importantly,
**Stack Exchange content (a large portion of the dataset) is CC BY-SA 4.0**,
which has share-alike implications for any dataset you publish. Read
[LICENSING_NOTES.md](LICENSING_NOTES.md) before redistributing collected
data or releasing a derivative dataset.

The scrapers automatically tag every Stack Exchange document with
`"license": "CC-BY-SA-4.0"` so attribution metadata is preserved through
the conversion pipeline.
