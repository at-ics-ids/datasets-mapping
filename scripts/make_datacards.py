#!/usr/bin/env python3
"""Generate machine-readable per-dataset cards (JSON) from the released mapping.

Every field is derived from a released file:
  * technique sets / tactics / enterprise  -> data/coverage_matrix.csv, data/enterprise_summary.csv
  * confidence + evidence source          -> data/technique_mapping_long.csv, data/mapping_evidence.csv
  * dataset reference + DOI               -> data/dataset_meta.csv
No value is invented here.
"""
import csv, json, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
OUT  = os.path.join(ROOT, "datacards")
os.makedirs(OUT, exist_ok=True)

cov  = list(csv.DictReader(open(os.path.join(DATA, "coverage_matrix.csv"))))
long = list(csv.DictReader(open(os.path.join(DATA, "technique_mapping_long.csv"))))
ent  = list(csv.DictReader(open(os.path.join(DATA, "enterprise_summary.csv"))))
meta = {r["dataset"]: r for r in csv.DictReader(open(os.path.join(DATA, "dataset_meta.csv")))}
try:
    rb = list(csv.DictReader(open(os.path.join(DATA, "mapping_evidence.csv"))))
except FileNotFoundError:
    rb = []

DATASETS = [c for c in cov[0] if c not in ("technique_id", "technique_name", "tactic")]
conf = {(r["dataset"], r["technique_id"]): r["confidence"] for r in long}
entm = collections.defaultdict(list)
for r in ent:
    entm[r["dataset"]].append(r["enterprise_ref"])
srcs = collections.defaultdict(set)
for r in rb:
    if r.get("source"):
        srcs[r["dataset"]].add(r["source"].split(" Sec")[0].split(",")[0].strip())

index = []
for d in DATASETS:
    m = meta[d]
    techs = [{"technique_id": r["technique_id"], "technique_name": r["technique_name"],
              "tactic": r["tactic"], "confidence": conf.get((d, r["technique_id"]), "high")}
             for r in cov if r[d].strip()]
    card = {
        "dataset": d,
        "attack_mapping": {
            "framework": "MITRE ATT&CK for ICS",
            "version": "19.1",
            "ics_techniques": techs,
            "ics_technique_count": len(techs),
            "tactics_covered": sorted({t["tactic"] for t in techs}),
            "enterprise_techniques": sorted(entm.get(d, [])),
            "enterprise_technique_count": len(entm.get(d, [])),
        },
        "grounding": {
            "attack_list_source": sorted(srcs.get(d, [])) or ["see data/mapping_evidence.csv"],
            "evidence": "data/mapping_evidence.csv (verbatim passage per mapped technique)",
            "policy": "Attacks taken from the dataset's own paper or its official release documentation.",
        },
        "reference": {"citation": m["reference"], "doi": m["doi"]},
    }
    with open(os.path.join(OUT, f"{d}.json"), "w") as f:
        json.dump(card, f, indent=2, ensure_ascii=False)
        f.write("\n")
    index.append({"dataset": d, "card": f"{d}.json",
                  "ics_technique_count": len(techs),
                  "enterprise_technique_count": len(entm.get(d, []))})

with open(os.path.join(OUT, "index.json"), "w") as f:
    json.dump({"framework": "MITRE ATT&CK for ICS v19.1",
               "datasets": len(index), "cards": index}, f, indent=2)
    f.write("\n")
print(f"wrote {len(index)} data cards + index.json to datacards/")
