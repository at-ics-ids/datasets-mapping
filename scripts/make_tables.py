#!/usr/bin/env python3
"""Emit the paper's Table II and Table III from the released mapping.

Table II  -> data/table2_per_dataset.csv
Table III -> data/table3_tactic_coverage.csv   (ICS block + Enterprise block)

Also computes the uncovered set per tactic: available - covered, using the
published ATT&CK for ICS v19.1 tactic sizes in data/attack_ics_v19_1_catalog.csv.
Nothing is invented; every number comes from the CSVs in data/.

The uncovered set is defined and reported PER TACTIC, as in the paper. Do not sum
the `available` column: ten techniques sit under more than one tactic in v19.1
(T1693 under three), so the column totals 90 tactic-technique pairs across only
79 distinct techniques. A corpus-wide uncovered count would need a distinct-
technique denominator, and a decision about parents versus sub-techniques.
"""
import csv, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

TAC_ORDER = ["Initial Access","Execution","Persistence","Privilege Escalation","Evasion",
             "Discovery","Lateral Movement","Collection","Command and Control",
             "Inhibit Response Function","Impair Process Control","Impact"]
KEY = {"Initial Access":"IA","Discovery":"DI","Collection":"CO",
       "Inhibit Response Function":"IRF","Impair Process Control":"IPC","Impact":"IM",
       "Execution":"EX","Persistence":"PE","Privilege Escalation":"PR","Evasion":"EV",
       "Lateral Movement":"LM","Command and Control":"C2"}

cov  = list(csv.DictReader(open(os.path.join(DATA, "coverage_matrix.csv"))))
ent  = list(csv.DictReader(open(os.path.join(DATA, "enterprise_summary.csv"))))
cat  = {r["tactic"]: int(r["techniques_available"])
        for r in csv.DictReader(open(os.path.join(DATA, "attack_ics_v19_1_catalog.csv")))}
etac = {r["technique_id"]: r["enterprise_tactic"]
        for r in csv.DictReader(open(os.path.join(DATA, "enterprise_tactics.csv")))}

DATASETS = [c for c in cov[0] if c not in ("technique_id","technique_name","tactic")]
ent_count = collections.Counter(r["dataset"] for r in ent)

# ---------------- Table II ----------------
p2 = os.path.join(DATA, "table2_per_dataset.csv")
with open(p2, "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["Dataset","ICS techniques","Tactics covered","Enterprise techniques"])
    for d in DATASETS:
        techs   = [r for r in cov if r[d].strip()]
        tactics = sorted({r["tactic"] for r in techs}, key=TAC_ORDER.index)
        w.writerow([d, len(techs), "; ".join(KEY[t] for t in tactics),
                    ent_count[d] if ent_count[d] else "-"])

# ---------------- Table III ----------------
tac_cov = collections.defaultdict(set)
for r in cov: tac_cov[r["tactic"]].add(r["technique_id"])
ent_ids = {r["enterprise_ref"].split()[0] for r in ent}
ent_by_tactic = collections.Counter(etac[t] for t in ent_ids)

p3 = os.path.join(DATA, "table3_tactic_coverage.csv")
with open(p3, "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["block","tactic","covered","available","uncovered"])
    for t in TAC_ORDER:
        c, a = len(tac_cov[t]), cat[t]
        w.writerow(["ICS", t, c, a, a - c])
    for t in ["Initial Access","Credential Access","Collection","Command and Control","Impact"]:
        w.writerow(["Enterprise", t, ent_by_tactic[t], "n/a", "n/a"])
    w.writerow(["Enterprise","Enterprise total", sum(ent_by_tactic.values()), "n/a", "n/a"])

ics_distinct = len({tid for t in TAC_ORDER for tid in tac_cov[t]})
empty = [t for t in TAC_ORDER if not tac_cov[t]]
print(f"wrote {os.path.relpath(p2, ROOT)}  (10 datasets)")
print(f"wrote {os.path.relpath(p3, ROOT)}  (12 ICS tactics + Enterprise block)")
print(f"  distinct ICS techniques covered: {ics_distinct}")
print(f"  uncovered, per tactic (see the `uncovered` column; not summable):")
for t in TAC_ORDER:
    print(f"    {t:<28}{cat[t] - len(tac_cov[t]):>3}")
print(f"  tactics exercised by no dataset: {len(empty)} -> {empty}")
print(f"  Enterprise techniques (separate): {sum(ent_by_tactic.values())}")
