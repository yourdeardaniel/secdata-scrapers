# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — Initial public release

### Features
- 143 scraper modules covering 192 underlying public security data sources
- Categories: vulnerability databases, threat intelligence, CTF writeups,
  exploit development, malware analysis, academic research, kernel security,
  detection rules, threat hunting, mobile security, cloud security,
  cryptography, and more
- Stack Exchange archive download and processing (security, RE, crypto, unix)
- Automatic robots.txt compliance for all HTTP requests
- Per-domain rate limit floors that cannot be overridden by config
- Audit logging of every URL accessed
- Credential and PII scrubbing before any document is written to disk
- Operational attack content pre-filtering
- Resumable scraping via per-source checkpoints

### Infrastructure
- Single shared HTTP session for connection reuse
- Single shared `safe_get` helper that all scrapers use
- Single shared `clone_repo` helper for Git-based sources
- Atomic checkpoint writes (no corruption on crash)
- Stable document IDs based on URL or content hash

### Output
- Raw documents in JSONL format with metadata: source, URL, license, text
- Stack Exchange documents tagged with `"license": "CC-BY-SA-4.0"`
- Compatible with secdata-pipeline for instruction-tuning conversion
