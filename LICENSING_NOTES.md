# Licensing Notes for Collected Data

The `secdata-scrapers` code is MIT licensed. **The data this tool collects
is not.** Every source has its own license that applies to anything you
do with the collected data — including using it to train an AI model,
redistributing it, or releasing a derivative dataset.

If you publish a dataset or model trained on data collected by this tool,
you must comply with each source's license. This document summarises the
major licenses so you can make informed decisions.

## Stack Exchange (security, RE, crypto, unix dumps + API)

**License:** Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)
(content posted before 2018-05-02 may be CC BY-SA 3.0)

**Requirements:**
- **Attribution:** When you redistribute the data or derivative works
  (including a fine-tuned model trained on it), you must credit Stack
  Exchange and link to the original posts where practical.
- **Share-Alike:** Any redistributed dataset must also be licensed
  CC BY-SA 4.0. **This includes datasets uploaded to HuggingFace.**

**Practical implication:** If you release a HuggingFace dataset that
includes processed Stack Exchange Q&A, the dataset must be CC BY-SA 4.0.
Models fine-tuned on that data may be subject to share-alike terms
depending on jurisdiction — this is unsettled legal territory.

The scrapers tag every Stack Exchange document with
`"license": "CC-BY-SA-4.0"` so you can filter or attribute appropriately.

## NVD, CISA, CWE, CAPEC, NIST publications

**License:** Public domain (US government works)

**Requirements:** None for content authored by US government.
Some advisories quote third-party content which retains its original
license — uncommon but worth noting.

## MITRE ATT&CK, D3FEND, MITRE CAPEC, CWE

**License:** Free for any use under the MITRE Public Disclosure
(includes commercial use). Attribution requested but not required.

## OWASP (WSTG, Cheat Sheets, MASTG, MASVS, API Security)

**License:** Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)
or Apache 2.0 depending on the project.

**Requirements:** Same share-alike implications as Stack Exchange for
the CC BY-SA-licensed parts.

## arXiv papers

**License:** Varies. Author-specific. arXiv supports CC BY, CC BY-SA,
CC BY-NC-SA, and "non-exclusive distribution" licenses.

**Practical implication:** A safe assumption is that arXiv abstracts
can be processed for research, but redistributing full PDFs as part
of a dataset requires checking each paper's license. This pipeline
extracts text rather than redistributing PDFs, which is generally
considered fair use for research, but talk to a lawyer if your
deployment is commercial.

## GitHub repositories

**License:** Each repository has its own license. Common ones:
- MIT, Apache 2.0, BSD: redistribute freely with attribution
- GPL, AGPL: derivative works must be open-sourced under same license
- No license: technically all rights reserved — using such repos
  for training data is legally questionable

The scrapers don't currently filter out unlicensed repos.
**Recommendation:** Manually review which repos are scraped via
`config.yaml` and avoid those without explicit licenses if you plan
to publish a dataset.

## Vendor advisories (Microsoft MSRC, Red Hat, Ubuntu, Mozilla, etc.)

**License:** Varies. Generally permitted to redistribute for
informational/research purposes with attribution. Some vendors
restrict commercial redistribution.

## Academic conference papers (USENIX, NDSS, IEEE S&P, ACM CCS)

**License:** Author retains copyright. Most authors permit research
use but redistribution as a dataset is in a grey area. The pipeline
extracts text excerpts which is more defensible than redistributing
full PDFs.

## CTF writeups, blog posts (CTFtime, Pentester.land, individual blogs)

**License:** Varies wildly. Many bloggers don't specify a license at all.
**Recommendation:** For a publicly released dataset, consider documenting
which sources contributed and providing opt-out instructions for content
authors who don't want their work in your dataset.

## Threat intelligence feeds (AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar)

**License:** Varies. Most explicitly permit research use:
- AlienVault OTX: free for non-commercial research
- abuse.ch services (ThreatFox, URLhaus, MalwareBazaar): free for any use
  with attribution

## YARA / Sigma rules

**License:** Most YARA and Sigma rule repositories use permissive licenses
(MIT, BSD, Apache 2.0). Some use GPL. Each rule repository's license
applies to rules from that repo.

## Recommendations for dataset releases

1. **Choose a license that's compatible with the strictest source.**
   For a dataset including Stack Exchange content, that means CC BY-SA 4.0.

2. **Maintain attribution metadata.** This pipeline preserves `source` and
   `url` fields on every document. Don't strip these when releasing the
   dataset — they're often what makes attribution possible.

3. **Document opt-out procedures.** If you publish on HuggingFace, include
   a `dataset_card.md` section explaining how content authors can request
   removal of their contributions.

4. **Consult a lawyer if commercial.** This document is informational and
   not legal advice. If you're commercialising a model trained on this
   data, get proper legal review.
