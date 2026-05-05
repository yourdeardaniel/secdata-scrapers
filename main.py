#!/usr/bin/env python3
"""
secdata-scrapers — Cybersecurity Dataset Scraper
=================================================
Collects raw security documents from 192 public sources.
Output: data/raw/raw_docs.jsonl

This tool collects publicly available security research content.
It does NOT generate training examples — see secdata-pipeline for that.

Usage:
    python main.py --stats            show current collection progress
    python main.py --estimate         show source list and expected volume
    python main.py --check-compliance run compliance checks on all domains
    python main.py --SOURCE_FLAG      run individual source(s)
    python main.py --all              run all sources (weeks-long operation)

Run 'python main.py --help' for all source flags.

ETHICAL USE:
  This scraper respects robots.txt, enforces minimum delays per domain,
  and maintains an audit log of all URLs accessed. Only run against
  sources you have a legitimate reason to access. See ETHICAL_USE.md.
"""
import argparse, os, sys, yaml
from utils import ensure_dirs, count_lines, init_audit_log
from scrapers import (
    ctftime, github_repos, hackerone, exploitdb, rss_feeds,
    nvd, github_advisories, arxiv, mitre_attack, stackexchange_api,
    osv, misc_sources, skill_sources,
    github_deep, academic_deep, stackexchange_downloader,
    kernel_commits, metasploit_deep, detection_rules, bugzilla,
    specialty_sources, network_sources, gap_sources, advanced_sources,
)

ALL_SOURCES = [
    # ── Base sources ──────────────────────────────────────────────
    ("ctftime",           ctftime.run,                           "CTFtime writeups"),
    ("github",            github_repos.run,                      "GitHub repos (500)"),
    ("hackerone",         hackerone.run,                         "HackerOne reports"),
    ("exploitdb",         exploitdb.run,                         "Exploit-DB"),
    ("rss",               rss_feeds.run,                         "RSS security blogs"),
    ("nvd",               nvd.run,                               "NVD CVE database"),
    ("ghsa",              github_advisories.run,                 "GitHub Advisories"),
    ("arxiv",             arxiv.run,                             "arXiv abstracts"),
    ("attack",            mitre_attack.run,                      "MITRE ATT&CK"),
    ("stackexchange",     stackexchange_api.run,                 "StackExchange API"),
    ("osv",               osv.run,                               "OSV.dev"),
    ("packetstorm",       misc_sources.run_packetstorm,          "Packetstorm"),
    ("phrack",            misc_sources.run_phrack,               "Phrack magazine"),
    ("sans-isc",          misc_sources.run_sans_isc,             "SANS ISC diaries"),
    ("capec",             misc_sources.run_mitre_capec,          "MITRE CAPEC"),
    ("malpedia",          misc_sources.run_malpedia,             "Malpedia"),
    ("cisa",              misc_sources.run_cisa,                 "CISA advisories+KEV"),
    ("msrc",              misc_sources.run_msrc,                 "MSRC advisories"),
    ("vendor",            misc_sources.run_vendor_advisories,    "Vendor advisories"),
    ("alienvault",        misc_sources.run_alienvault,           "AlienVault OTX"),
    ("nsa",               misc_sources.run_nsa,                  "NSA advisories"),
    ("portswigger",       misc_sources.run_portswigger,          "PortSwigger Academy"),
    ("cisa-ics",          misc_sources.run_cisa_ics,             "CISA ICS advisories"),
    ("vxug",              misc_sources.run_vx_underground,       "VX-Underground"),
    ("nist",              misc_sources.run_nist,                 "NIST publications"),
    ("pentest-reports",   skill_sources.run_pentest_reports,     "Pentest reports"),
    ("owasp-wstg",        skill_sources.run_owasp_wstg,          "OWASP WSTG"),
    ("ptes",              skill_sources.run_ptes,                "PTES"),
    ("pentester-land",    skill_sources.run_pentester_land,      "Pentester.land"),
    ("sans-rr",           skill_sources.run_sans_reading_room,   "SANS Reading Room"),
    ("ropemporium",       skill_sources.run_ropemporium,         "ROPemporium"),
    ("ir0nstone",         skill_sources.run_ir0nstone,           "ir0nstone"),
    ("nightmare",         skill_sources.run_nightmare,           "nightmare course"),
    ("how2heap",          skill_sources.run_how2heap,            "how2heap"),
    ("exploit-edu",       skill_sources.run_exploit_education,   "exploit.education"),
    ("liveoverflow",      skill_sources.run_liveoverflow,        "LiveOverflow"),
    ("pwn-college",       skill_sources.run_pwn_college,         "pwn.college"),
    ("malwareunicorn",    skill_sources.run_malwareunicorn,      "MalwareUnicorn"),
    ("hasherezade",       skill_sources.run_hasherezade,         "hasherezade blog"),
    ("0xdf",              skill_sources.run_zeroxdf,             "0xdf blog"),
    ("flareon",           skill_sources.run_flareon,             "FlareOn writeups"),
    ("ghidra",            skill_sources.run_ghidra_course,       "Ghidra course"),
    ("opensectraining",   skill_sources.run_opensecuritytraining,"OpenSecTraining2"),
    ("malwarebazaar",     skill_sources.run_malwarebazaar,       "MalwareBazaar"),
    ("anyrun",            skill_sources.run_anyrun,              "ANY.RUN"),
    ("mta",               skill_sources.run_malware_traffic_analysis,"MTA"),
    ("ired-team",         skill_sources.run_ired_team,           "ired.team"),
    ("cobalt-strike",     skill_sources.run_cobalt_strike_docs,  "Cobalt Strike blog"),
    ("urlhaus",           skill_sources.run_urlhaus,             "URLhaus"),
    ("threatfox",         skill_sources.run_threatfox,           "ThreatFox"),
    # ── Deep GitHub ───────────────────────────────────────────────
    ("gh-repos-deep",     github_deep.run_repos,                 "GitHub repos deep"),
    ("gh-gists",          github_deep.run_gists,                 "GitHub Gists"),
    ("gh-issues",         github_deep.run_issues,                "GitHub Issues"),
    ("gh-code",           github_deep.run_code_search,           "GitHub Code Search"),
    # ── Academic deep ─────────────────────────────────────────────
    ("arxiv-full",        academic_deep.run_arxiv_fulltext,      "arXiv full PDFs"),
    ("usenix",            academic_deep.run_usenix,              "USENIX Security"),
    ("ndss",              academic_deep.run_ndss,                "NDSS"),
    ("ieee-sp",           academic_deep.run_ieee_sp,             "IEEE S&P"),
    ("acm-ccs",           academic_deep.run_acm_ccs,             "ACM CCS"),
    # ── Stack Exchange dumps ──────────────────────────────────────
    ("se-dumps",          stackexchange_downloader.run,          "SE dumps (auto-download)"),
    # ── Systems ───────────────────────────────────────────────────
    ("kernel",            kernel_commits.run,                    "Linux kernel commits"),
    ("metasploit",        metasploit_deep.run,                   "Metasploit modules"),
    # ── Detection ─────────────────────────────────────────────────
    ("yara",              detection_rules.run_yara_rules,        "YARA rules"),
    ("sigma",             detection_rules.run_sigma_rules,       "Sigma rules"),
    ("cwe",               detection_rules.run_cwe_full,          "CWE database"),
    # ── Bug trackers ──────────────────────────────────────────────
    ("mozilla",           bugzilla.run_mozilla,                  "Mozilla Bugzilla"),
    ("chromium",          bugzilla.run_chromium,                 "Chromium bugs"),
    # ── Specialty (v2) ────────────────────────────────────────────
    ("iacr",              specialty_sources.run_iacr_eprint,     "IACR ePrint"),
    ("cryptohack",        specialty_sources.run_cryptohack,      "CryptoHack"),
    ("cryptopals",        specialty_sources.run_cryptopals,      "Cryptopals"),
    ("boneh-crypto",      specialty_sources.run_dan_boneh_crypto,"Dan Boneh crypto"),
    ("mtc3",              specialty_sources.run_mystery_twister, "MysteryTwister"),
    ("cloudflare-blog",   specialty_sources.run_cloudflare_blog, "Cloudflare blog"),
    ("ripe-blog",         specialty_sources.run_ripe_ncc_blog,   "RIPE NCC blog"),
    ("zeek",              specialty_sources.run_zeek_documentation,"Zeek docs"),
    ("suricata",          specialty_sources.run_suricata_rules,  "Suricata rules"),
    ("atomic",            specialty_sources.run_atomic_red_team, "Atomic Red Team"),
    ("lolbas",            specialty_sources.run_lolbas,          "LOLBAS"),
    ("gtfobins",          specialty_sources.run_gtfobins,        "GTFOBins"),
    ("d3fend",            specialty_sources.run_mitre_d3fend,    "MITRE D3FEND"),
    ("thp",               specialty_sources.run_threat_hunter_playbook,"THP"),
    ("loldrivers",        specialty_sources.run_loldrivers,      "LOLDrivers"),
    ("flaws",             specialty_sources.run_flaws_cloud,     "flaws.cloud"),
    ("cloudgoat",         specialty_sources.run_cloudgoat,       "CloudGoat+Pacu"),
    ("wiz",               specialty_sources.run_wiz_research,    "Wiz Research"),
    ("csa",               specialty_sources.run_cloud_security_alliance,"CSA"),
    ("cloudsecdocs",      specialty_sources.run_cloudsecdocs,    "CloudSecDocs"),
    # ── Network (v3) ──────────────────────────────────────────────
    ("nmap-docs",         network_sources.run_nmap_documentation,"Nmap docs+NSE"),
    ("shodan",            network_sources.run_shodan_research,   "Shodan research"),
    ("masscan",           network_sources.run_masscan_recon_tools,"Masscan+recon"),
    ("wireshark",         network_sources.run_wireshark_documentation,"Wireshark"),
    ("packetlife",        network_sources.run_packetlife,        "PacketLife"),
    ("cis-network",       network_sources.run_cis_benchmarks,    "CIS Benchmarks"),
    ("disa-stigs",        network_sources.run_disa_stigs,        "DISA STIGs"),
    ("manrs",             network_sources.run_manrs_routing_security,"MANRS"),
    ("nist-network",      network_sources.run_nist_network_publications,"NIST network"),
    ("caida",             network_sources.run_caida_research,    "CAIDA research"),
    ("team-cymru",        network_sources.run_team_cymru,        "Team Cymru"),
    ("honeynet",          network_sources.run_honeynet_project,  "Honeynet Project"),
    ("shadowserver",      network_sources.run_shadowserver,      "Shadowserver"),
    # ── Gap fills (v4) ────────────────────────────────────────────
    ("mastg",             gap_sources.run_owasp_mastg,           "OWASP MASTG+MASVS"),
    ("hacktricks-mobile", gap_sources.run_hacktricks_mobile,     "HackTricks mobile"),
    ("mobile-repos",      gap_sources.run_mobile_security_repos, "Mobile security repos"),
    ("dfir",              gap_sources.run_dfir_report,           "The DFIR Report"),
    ("volatility",        gap_sources.run_volatility_docs,       "Volatility 3"),
    ("forensic-tools",    gap_sources.run_forensic_tools_docs,   "Forensic tools"),
    ("owasp-api",         gap_sources.run_owasp_api_security,    "OWASP API Security"),
    ("cicd-sec",          gap_sources.run_cicd_security,         "CI/CD security"),
    ("ai-ml-sec",         gap_sources.run_ai_ml_security,        "AI/ML security"),
    ("azure-sec",         gap_sources.run_azure_security,        "Azure AD security"),
    ("gcp-sec",           gap_sources.run_gcp_security,          "GCP security"),
    ("vuln-research",     gap_sources.run_vuln_research_methodology,"Vuln research method"),
    ("wireless",          gap_sources.run_wireless_security,     "Wireless+RF security"),
    ("k8s-sec",           gap_sources.run_k8s_container_security,"K8s+container sec"),
    ("secure-coding",     gap_sources.run_secure_coding,         "Secure coding+AppSec"),
    # ── Advanced (v5) ─────────────────────────────────────────────
    ("mandiant",          advanced_sources.run_mandiant_blog,    "Mandiant blog"),
    ("msft-sec",          advanced_sources.run_microsoft_security_blog,"MSFT DART blog"),
    ("13cubed",           advanced_sources.run_13cubed,          "13Cubed forensics"),
    ("win-artifacts",     advanced_sources.run_windows_artifact_guide,"Win artifact guide"),
    ("linux-forensics",   advanced_sources.run_linux_forensics,  "Linux forensics"),
    ("ir-playbooks",      advanced_sources.run_ir_playbooks,     "IR playbooks"),
    ("sans-dfir",         advanced_sources.run_sans_dfir,        "SANS DFIR blog"),
    ("ncc-group",         advanced_sources.run_ncc_group_research,"NCC Group research"),
    ("synacktiv",         advanced_sources.run_synacktiv_blog,   "Synacktiv blog"),
    ("zdi",               advanced_sources.run_zdi_blog,         "ZDI blog"),
    ("orange-tsai",       advanced_sources.run_orange_tsai_blog, "Orange Tsai blog"),
    ("quarkslab",         advanced_sources.run_quarkslab_blog,   "Quarkslab blog"),
    ("certcc",            advanced_sources.run_certcc_vulnerability_notes,"CERT/CC vuln notes"),
    ("qualys",            advanced_sources.run_qualys_research,  "Qualys Security Labs"),
    ("ps-research",       advanced_sources.run_portswigger_research,"PortSwigger research"),
    ("ret2",              advanced_sources.run_ret2_curriculum,  "ret2+RPISEC"),
    ("p0-issues",         advanced_sources.run_p0_issue_tracker, "P0 issue tracker"),
    ("browser-sec",       advanced_sources.run_browser_security, "Browser security"),
    ("fileless",          advanced_sources.run_fileless_malware, "Fileless malware"),
    ("edr-evasion",       advanced_sources.run_edr_evasion,      "EDR evasion"),
    ("soc-ops",           advanced_sources.run_soc_workflow,     "SOC workflow"),
    ("siem-impl",         advanced_sources.run_siem_implementation,"SIEM implementation"),
    ("pqc",               advanced_sources.run_post_quantum_crypto,"Post-quantum crypto"),
    ("serverless",        advanced_sources.run_serverless_security,"Serverless security"),
    ("purple",            advanced_sources.run_purple_team,      "Purple team method"),
    ("crypto-impl",       advanced_sources.run_crypto_impl_bugs, "Crypto impl bugs"),
    ("bin-audit",         advanced_sources.run_binary_auditing,  "Binary auditing"),
    ("rootkit-uefi",      advanced_sources.run_rootkit_uefi,     "Rootkit+UEFI"),
]

FAST_FIRST = [
    "cwe","capec","attack","yara","sigma","metasploit","pentest-reports",
    "owasp-wstg","ptes","nightmare","how2heap","flareon","ghidra",
    "malwareunicorn","lolbas","gtfobins","loldrivers","atomic",
    "cryptopals","boneh-crypto","flaws","cloudgoat","mastg","win-artifacts",
    "forensic-tools","owasp-api","secure-coding","ret2","edr-evasion",
    "siem-impl","pqc","serverless","crypto-impl","bin-audit","linux-forensics",
    "ir-playbooks","mobile-repos","ai-ml-sec","k8s-sec","wireless",
]


def load_config(path):
    with open(path) as f: return yaml.safe_load(f)


def setup_paths(cfg):
    raw_dir = cfg["output"]["raw_dir"]
    ensure_dirs(raw_dir, os.path.dirname(cfg["output"]["checkpoint_file"]),
                "./data/audit")
    init_audit_log("./data/audit/scrape_audit.log")
    return {
        "raw":        os.path.join(raw_dir, "raw_docs.jsonl"),
        "checkpoint": cfg["output"]["checkpoint_file"],
    }


def print_stats(paths):
    n = count_lines(paths["raw"])
    print(f"\n=== Scraper Stats ===")
    print(f"  Raw documents: {n:,}")
    print(f"  Output file:   {paths['raw']}")
    if n > 0:
        est = int(n * 0.348)
        print(f"  Estimated clean examples after pipeline: ~{est:,}")
    print()


def print_estimate():
    print(f"\n=== secdata-scrapers — {len(ALL_SOURCES)} sources ===\n")
    for flag, _, name in ALL_SOURCES:
        print(f"  --{flag:<22} {name}")
    print(f"\n  Total raw documents expected: ~1,374,960")
    print(f"  Disk required: ~150 GB")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="secdata-scrapers — collect raw security documents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config",   default="config.yaml")
    parser.add_argument("--stats",    action="store_true")
    parser.add_argument("--estimate", action="store_true")
    parser.add_argument("--se-help",  action="store_true",
                        help="Stack Exchange dump download instructions")
    parser.add_argument("--fast",     action="store_true",
                        help="Run all fast sources first (~2 hours total)")
    parser.add_argument("--all",      action="store_true",
                        help="Run all 192 sources (takes weeks)")

    for flag, _, _ in ALL_SOURCES:
        parser.add_argument(f"--{flag}", action="store_true",
                            dest=flag.replace("-","_"))
    args = parser.parse_args()

    if args.estimate:
        print_estimate(); return

    if args.se_help:
        print("\nStack Exchange dumps auto-download when you run --se-dumps")
        print("Files saved to data/se_dumps/ (~6 GB total)")
        print("To also include stackoverflow (80 GB): set enabled:true in config.yaml\n")
        return

    if not os.path.exists(args.config):
        print(f"Config not found: {args.config}"); sys.exit(1)

    cfg   = load_config(args.config)
    paths = setup_paths(cfg)

    if args.stats:
        print_stats(paths); return

    # Build dispatch map
    dispatch = {flag: fn for flag, fn, _ in ALL_SOURCES}

    if args.fast:
        for flag in FAST_FIRST:
            if flag in dispatch:
                print(f"\n{'='*50}\n{flag}\n{'='*50}")
                dispatch[flag](cfg, paths["raw"], paths["checkpoint"])
        print_stats(paths); return

    if args.all:
        for flag, fn, name in ALL_SOURCES:
            print(f"\n{'='*50}\n{name}\n{'='*50}")
            fn(cfg, paths["raw"], paths["checkpoint"])
        print_stats(paths); return

    # Individual flags
    ran = 0
    for flag, fn, _ in ALL_SOURCES:
        if getattr(args, flag.replace("-","_"), False):
            print(f"\n{'='*50}\n{flag}\n{'='*50}")
            fn(cfg, paths["raw"], paths["checkpoint"])
            ran += 1

    if ran:
        print_stats(paths)
    else:
        print_estimate()
        print_stats(paths)
        print("Specify --fast, --all, or individual source flags to start.\n")


if __name__ == "__main__":
    main()
