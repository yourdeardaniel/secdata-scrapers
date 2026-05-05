import requests
from tqdm import tqdm
from utils import append_jsonl, load_checkpoint, save_checkpoint, SESSION, safe_get

STIX_URLS = {
    "enterprise-attack": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile-attack": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics-attack": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}

def parse_bundle(bundle, domain):
    objects = bundle.get("objects", [])
    results = []
    mitigations = {o["id"]: o.get("description", "") for o in objects if o.get("type") == "course-of-action"}
    rel_map = {}
    for o in objects:
        if o.get("type") != "relationship":
            continue
        tgt = o.get("target_ref", "")
        rel_map.setdefault(tgt, []).append({"type": o.get("relationship_type",""), "src": o.get("source_ref","")})
    for obj in tqdm(objects, desc=f"  {domain}", leave=False):
        otype = obj.get("type", "")
        if otype == "attack-pattern":
            name = obj.get("name", "")
            desc = obj.get("description", "")
            if not desc:
                continue
            ext = obj.get("external_references", [])
            tech_id = next((e.get("external_id","") for e in ext if e.get("source_name")=="mitre-attack"), "")
            url = next((e.get("url","") for e in ext if e.get("source_name")=="mitre-attack"), "")
            phases = [p.get("phase_name","") for p in obj.get("kill_chain_phases",[])]
            platforms = obj.get("x_mitre_platforms", [])
            detection = obj.get("x_mitre_detection", "")
            data_srcs = obj.get("x_mitre_data_sources", [])
            mit_texts = [mitigations[r["src"]] for r in rel_map.get(obj.get("id",""),[])
                         if r["type"]=="mitigates" and r["src"] in mitigations]
            parts = [f"MITRE ATT&CK: {tech_id} — {name}",
                     f"Domain: {domain}", f"Tactics: {', '.join(phases)}",
                     f"Platforms: {', '.join(platforms)}", f"\nDescription:\n{desc}"]
            if detection: parts.append(f"\nDetection:\n{detection}")
            if data_srcs: parts.append(f"\nData sources: {', '.join(data_srcs[:10])}")
            if mit_texts: parts.append(f"\nMitigation:\n{mit_texts[0][:400]}")
            results.append({"source": "mitre_attack", "domain": domain,
                            "technique_id": tech_id, "name": name, "url": url,
                            "text": "\n".join(parts)})
        elif otype in ("malware", "tool"):
            name = obj.get("name", "")
            desc = obj.get("description", "")
            if not desc or len(desc) < 50:
                continue
            parts = [f"MITRE ATT&CK {otype.title()}: {name}", f"\n{desc}"]
            results.append({"source": "mitre_attack", "domain": domain,
                            "type": otype, "name": name, "text": "\n".join(parts)})
        elif otype == "intrusion-set":
            name = obj.get("name", "")
            desc = obj.get("description", "")
            if not desc or len(desc) < 50:
                continue
            aliases = obj.get("aliases", [])
            parts = [f"MITRE ATT&CK Threat Group: {name}"]
            if aliases: parts.append(f"Aliases: {', '.join(aliases)}")
            parts.append(f"\n{desc}")
            results.append({"source": "mitre_attack", "domain": domain,
                            "type": "threat_group", "name": name, "text": "\n".join(parts)})
    return results

def run(cfg, raw_file, checkpoint_file):
    c = cfg["scrapers"]["mitre_attack"]
    if not c.get("enabled", True):
        print("[mitre_attack] Disabled."); return
    cp = load_checkpoint(checkpoint_file)
    done_domains = set(cp.get("mitre_attack_done", []))
    for domain in [d for d in c.get("domains", []) if d not in done_domains]:
        url = STIX_URLS.get(domain)
        if not url:
            continue
        print(f"[mitre_attack] Downloading {domain}...")
        try:
            r = safe_get(url, timeout=60)
            r.raise_for_status()
            docs = parse_bundle(r.json(), domain)
            if docs:
                append_jsonl(raw_file, docs)
                print(f"[mitre_attack] {domain}: {len(docs)}")
            done_domains.add(domain)
            cp["mitre_attack_done"] = list(done_domains)
            save_checkpoint(checkpoint_file, cp)
        except Exception as e:
            print(f"[mitre_attack] Failed {domain}: {e}")
    print("[mitre_attack] Done.")
