# Ethical Use Guidelines

This tool collects publicly available security research content from 192 documented sources.
Before running it, read and agree to the following.

## What this tool does

- Requests publicly accessible web pages and APIs
- Respects `robots.txt` on all domains (checked automatically before each request)
- Enforces minimum delays between requests per domain (hardcoded, cannot be overridden)
- Logs every URL accessed in `data/audit/scrape_audit.log`
- Strips credentials and PII from collected content before saving

## What you are responsible for

**Terms of service compliance.** This tool accesses public content, but some sources have
terms of service that restrict automated access. Review the ToS for any source you
intend to scrape before running it. Key sources with notable ToS:

| Source | ToS notes |
|---|---|
| GitHub API | Requires authentication token. No more than 5,000 req/hr. |
| NVD | Requests 6-second delay without API key. Get a free key at nvd.nist.gov. |
| HackerOne | Public GraphQL API. Reasonable use only. |
| Stack Exchange | API has quota limits. Dump files have no restrictions. |
| Archive.org | Public content, requests courtesy delays. |

**Volume.** Running `--all` generates millions of HTTP requests over weeks.
Do not run this against sources at rates that could degrade their service.

**Legitimate purpose.** This tool exists to build security research datasets
for AI training. Do not use it to harvest personal information, scrape
proprietary content, or circumvent access controls.

**Local laws.** Ensure your use complies with applicable laws in your jurisdiction,
including the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK),
and equivalent legislation elsewhere.

## Reporting issues

If a source has asked to be removed from this pipeline, open an issue on the
GitHub repository and it will be removed from the next release.
