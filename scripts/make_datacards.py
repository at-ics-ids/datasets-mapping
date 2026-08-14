#!/usr/bin/env python3
"""Generate machine-readable per-dataset cards (JSON) from the released mapping.

Every field is derived from a released file:
  * technique sets / tactics / enterprise  -> data/coverage_matrix.csv, data/enterprise_summary.csv
  * confidence + evidence source          -> data/technique_mapping_long.csv, data/mapping_evidence.csv
  * dataset reference + DOI               -> data/dataset_meta.csv
No value is invented here.
"""
import csv, json, os, re, collections

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

# Coverage is reported at parent-technique grain; a parent's grade is `high` if any of
# its assignments in that dataset is high, otherwise `medium`. No default: a missing
# lookup is a bug, not a value to invent.
TACTICS = collections.defaultdict(list)
for r in csv.DictReader(open(os.path.join(DATA, "attack_ics_v19_1_technique_tactics.csv"))):
    TACTICS[r["technique_id"]].append(r["tactic"])
def _p(t): return t.split(".")[0]
_grades = collections.defaultdict(set)
for r in long:
    if r["confidence"] in ("high", "medium"):
        _grades[(r["dataset"], _p(r["technique_id"]))].add(r["confidence"])
def grade(d, tid):
    g = _grades[(d, _p(tid))]
    if not g:
        raise KeyError(f"{d}/{tid}: no confidence recorded in technique_mapping_long.csv")
    return "high" if "high" in g else "medium"
entm = collections.defaultdict(list)
for r in ent:
    entm[r["dataset"]].append(r["enterprise_ref"])
# grounding.attack_list_source names the WORK, not the page. The per-cell `source`
# column of mapping_evidence.csv keeps the exact locator (section, figure, table).
# Rows that were rejected (`removed`) or that carry no ATT&CK identifier (`unmapped`)
# are excluded: a card must not cite evidence for a mapping it does not contain.
_YEAR = re.compile(r"^(.*?\b(?:19|20)\d{2}\b)")
def cite(src):
    m = _YEAR.match(src.strip())
    out = (m.group(1) if m else src).strip(" +,;")
    if out.count("(") > out.count(")"):
        out += ")"
    return out

CITED = ("high", "medium", "enterprise")
srcs = collections.defaultdict(set)
for r in rb:
    if r.get("source") and r["confidence"] in CITED:
        srcs[r["dataset"]].add(cite(r["source"]))

index = []
for d in DATASETS:
    m = meta[d]
    techs = [{"technique_id": r["technique_id"], "technique_name": r["technique_name"],
              "tactics": TACTICS[_p(r["technique_id"])], "confidence": grade(d, r["technique_id"])}
             for r in cov if r[d].strip()]
    card = {
        "dataset": d,
        "attack_mapping": {
            "framework": "MITRE ATT&CK for ICS",
            "version": "19.1",
            "ics_techniques": techs,
            "ics_technique_count": len(techs),
            "tactics_covered": sorted({x for t in techs for x in t["tactics"]}),
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
