#!/usr/bin/env python3
"""Reproducible analysis of the grounded technique-level ATT&CK-for-ICS mapping.

Source of truth: technique_mapping_long.csv (human-reviewed; every row carries a
confidence and, where applicable, a justification and an enterprise_ref). This
script derives the coverage matrix, technique frequency, per-tactic coverage and
the ICS/Enterprise split that feed Figures 1-3 and Table II. Nothing is invented.

Rows whose confidence is 'enterprise' map to ATT&CK Enterprise and
are reported as a SEPARATE tally; rows 'out-of-scope' are excluded. ICS coverage
counts only rows with confidence in {high, medium, low}. Sub-technique IDs (Txxxx.nnn)
count as distinct techniques under ATT&CK for ICS v19.1.
"""
import csv, os
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
LONG = os.path.join(DATA, "technique_mapping_long.csv")

TAC_ORDER = ["Initial Access","Execution","Persistence","Privilege Escalation","Evasion",
             "Discovery","Lateral Movement","Collection","Command and Control",
             "Inhibit Response Function","Impair Process Control","Impact"]

with open(LONG, newline="") as f:
    rows = list(csv.DictReader(f))

ICS = [r for r in rows if r["confidence"] not in ("enterprise", "out-of-scope")]
ENT = [r for r in rows if r["confidence"] == "enterprise"]
OUT = [r for r in rows if r["confidence"] == "out-of-scope"]

# dataset order as presented in the paper
DATASET_ORDER = ['Edge-IIoTset', 'ICS-NAD', 'X-IIoTID', 'MSU-PWR', 'ICS-Flow', 'Rodofile', 'HIL-WDT', 'MSU-GP', 'EDS', 'SWaT']
ds_order = [d for d in DATASET_ORDER if any(r["dataset"] == d for r in rows)]

# ICS coverage
cov = defaultdict(set)
for r in ICS: cov[r["dataset"]].add(r["technique_id"])
name = {r["technique_id"]: r["technique_name"] for r in ICS}
tac  = {r["technique_id"]: r["tactic"] for r in ICS}
techs = sorted({r["technique_id"] for r in ICS}, key=lambda t: (TAC_ORDER.index(tac[t]), t))

with open(os.path.join(DATA, "coverage_matrix.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["technique_id","technique_name","tactic"] + ds_order)
    for t in techs:
        w.writerow([t, name[t], tac[t]] + ["1" if t in cov[d] else "" for d in ds_order])

# frequency + per-tactic
freq = Counter()
for d in ds_order:
    for t in cov[d]: freq[t] += 1
tac_cov = defaultdict(set)
for t in techs: tac_cov[tac[t]].add(t)

# Enterprise tally (reported separately)
ent_map = defaultdict(set)
for r in ENT: ent_map[r["dataset"]].add(r["enterprise_ref"])
ent_ids = sorted({r["enterprise_ref"].split()[0] for r in ENT})
with open(os.path.join(DATA, "enterprise_summary.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["dataset","enterprise_ref"])
    for d in ds_order:
        for e in sorted(ent_map[d]): w.writerow([d, e])

# report
print("datasets:", ds_order)
print("distinct ICS techniques:", len(techs), " ICS rows:", len(ICS))
print("per-dataset ICS technique counts:", {d: len(cov[d]) for d in ds_order})
print("per-tactic ICS coverage:")
covered_tac = 0
for t in TAC_ORDER:
    n = len(tac_cov[t]); covered_tac += (1 if n else 0)
    print(f"  {t:28s}: {n}  {sorted(tac_cov[t])}")
empty = [t for t in TAC_ORDER if len(tac_cov[t]) == 0]
print("tactics covered:", covered_tac, "/12   empty:", len(empty), empty)
print("top technique frequency:", freq.most_common(9))
print("singletons (freq==1):", sorted([t for t in techs if freq[t] == 1]))
print("\nENTERPRISE (reported separately): distinct =", len(ent_ids), ent_ids)
print("per-dataset enterprise:", {d: sorted(ent_map[d]) for d in ds_order if ent_map[d]})
print("out-of-scope rows:", len(OUT), [(r["dataset"], r["technique_id"]) for r in OUT])
print("review cells remaining:", sum(1 for r in rows if r["confidence"] == "review"))

# --- Sensitivity: fold the enterprise attacks back in as ICS coverage ---
# The counterfactual an attack-class tactic mapping implicitly adopts. Printed here for
# transparency; the paper reports only the headline (enterprise kept separate).
FOLD = ICS + ENT
fold_tac = defaultdict(set)
for r in FOLD: fold_tac[r["tactic"]].add(r["technique_id"])
fold_tech = sorted({r["technique_id"] for r in FOLD})
fold_cov = sum(1 for t in TAC_ORDER if fold_tac[t])
print("\nSENSITIVITY (enterprise counted as ICS coverage):")
print("  distinct techniques:", len(fold_tech), " tactics covered:", fold_cov, "/12")
print("  per-tactic:", {t: len(fold_tac[t]) for t in TAC_ORDER})
print("  tactics still empty:", [t for t in TAC_ORDER if not fold_tac[t]])
print("  techniques gained vs headline:", sorted(set(fold_tech) - set(techs)))
