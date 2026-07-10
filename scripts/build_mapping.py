#!/usr/bin/env python3
"""Reproducible analysis of the grounded technique-level ATT&CK-for-ICS mapping.

Source of truth: technique_mapping_long.csv (human-reviewed; every row carries a
confidence and, where applicable, a justification and an enterprise_ref). This
script derives the coverage matrix, technique frequency, per-tactic coverage and
the ICS/Enterprise split that feed Figures 1-3 and Table II. Nothing is invented.

Rows whose confidence is 'enterprise' map to ATT&CK Enterprise and are reported as
a SEPARATE tally. ICS coverage counts exactly the rows whose confidence is high or
medium; the script refuses to run on any other value. Rejected candidates
are recorded as `removed` in mapping_evidence.csv and never appear in this file.

Granularity. Coverage is reported at PARENT-TECHNIQUE grain: T1692.001 and T1692.002
are both credited to T1692 Unauthorized Message. This matches the grain of the
published catalog, whose techniques_available column counts parent techniques and
nests sub-techniques beneath them. The released mapping retains the sub-technique
identifiers; only the counting collapses them.

Tactic attribution. A technique is credited to EVERY tactic the ATT&CK for ICS
matrix lists it under, read from data/attack_ics_v19_1_technique_tactics.csv. This
is the same rule the techniques_available column of attack_ics_v19_1_catalog.csv
obeys, which is why that column totals 90 tactic-technique pairs across 79 distinct
techniques. Crediting a technique to one tactic while the denominator credits it to
several would make the two columns of Table III incommensurable. T1692 Unauthorized
Message is the only technique in this corpus that carries more than one tactic:
Evasion and Impair Process Control. The `tactic` column of technique_mapping_long.csv
is retained as a display label and is no longer the source of tactic coverage.
"""
import csv, os
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
LONG = os.path.join(DATA, "technique_mapping_long.csv")
TT   = os.path.join(DATA, "attack_ics_v19_1_technique_tactics.csv")

TAC_ORDER = ["Initial Access","Execution","Persistence","Privilege Escalation","Evasion",
             "Discovery","Lateral Movement","Collection","Command and Control",
             "Inhibit Response Function","Impair Process Control","Impact"]

def parent(tid):
    """T1692.002 -> T1692. Sub-techniques inherit their parent's tactics."""
    return tid.split(".")[0]

TACTICS = defaultdict(list)
PNAME = {}
with open(TT, newline="") as f:
    for r in csv.DictReader(f):
        TACTICS[r["technique_id"]].append(r["tactic"])
        PNAME[r["technique_id"]] = r["technique_name"]

def tactics_of(tid):
    t = TACTICS.get(parent(tid))
    if not t:
        raise KeyError(f"{tid}: no tactic recorded in {os.path.basename(TT)}. "
                       "Add it, with its source, before it can be counted.")
    return t

with open(LONG, newline="") as f:
    rows = list(csv.DictReader(f))

# Allowlist, not blacklist: ICS coverage is exactly what carries a confidence GRADE.
# `removed` rows live only in mapping_evidence.csv, but a blacklist would silently
# count one as coverage if it ever reached this file.
GRADES = ("high", "medium")
ICS = [r for r in rows if r["confidence"] in GRADES]
ENT = [r for r in rows if r["confidence"] == "enterprise"]
UNKNOWN = sorted({r["confidence"] for r in rows} - set(GRADES) - {"enterprise"})
if UNKNOWN:
    raise SystemExit(f"unrecognised confidence value(s) in {os.path.basename(LONG)}: {UNKNOWN}. "
                     "The published mapping carries only high, medium and enterprise; "
                     "rejected candidates are recorded as `removed` in mapping_evidence.csv.")

# dataset order as presented in the paper
DATASET_ORDER = ['Edge-IIoTset', 'ICS-NAD', 'X-IIoTID', 'MSU-PWR', 'ICS-Flow', 'Rodofile', 'HIL-WDT', 'MSU-GP', 'EDS', 'SWaT']
ds_order = [d for d in DATASET_ORDER if any(r["dataset"] == d for r in rows)]

# ICS coverage, at PARENT-TECHNIQUE grain (see module docstring)
cov = defaultdict(set)
for r in ICS: cov[r["dataset"]].add(parent(r["technique_id"]))
name = {parent(r["technique_id"]): PNAME[parent(r["technique_id"])] for r in ICS}
tac  = {parent(r["technique_id"]): r["tactic"] for r in ICS}   # display label only
techs = sorted({parent(r["technique_id"]) for r in ICS}, key=lambda t: (TAC_ORDER.index(tac[t]), t))

with open(os.path.join(DATA, "coverage_matrix.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["technique_id","technique_name","tactic"] + ds_order)
    for t in techs:
        w.writerow([t, name[t], tac[t]] + ["1" if t in cov[d] else "" for d in ds_order])

# frequency + per-tactic
freq = Counter()
for d in ds_order:
    for t in cov[d]: freq[t] += 1
tac_cov = defaultdict(set)
for t in techs:
    for tt in tactics_of(t): tac_cov[tt].add(t)

# Enterprise tally (reported separately)
ent_map = defaultdict(set)
for r in ENT: ent_map[r["dataset"]].add(r["enterprise_ref"])
ent_ids = sorted({r["enterprise_ref"].split()[0] for r in ENT})
with open(os.path.join(DATA, "enterprise_summary.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n"); w.writerow(["dataset","enterprise_ref"])
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
print("technique frequency, most exercised first:", freq.most_common())
print("singletons (freq==1):", sorted([t for t in techs if freq[t] == 1]))
print("\nENTERPRISE (reported separately): distinct =", len(ent_ids), ent_ids)
print("per-dataset enterprise:", {d: sorted(ent_map[d]) for d in ds_order if ent_map[d]})
_ev = os.path.join(DATA, "mapping_evidence.csv")
if os.path.exists(_ev):
    with open(_ev, newline="") as f:
        _rm = [r for r in csv.DictReader(f) if r["confidence"] == "removed"]
    print("removed (rejected) assignments, from mapping_evidence.csv:", len(_rm),
          [(r["dataset"], r["technique_id"]) for r in _rm])

# --- Sensitivity: fold the Enterprise attacks back in as if they were ICS coverage ---
# The counterfactual that an attack-class or tactic-level mapping implicitly adopts.
# Printed for transparency; the paper reports only the headline, with Enterprise kept
# separate. Two caveats the numbers below make concrete:
#   1. Enterprise tactics are a DIFFERENT taxonomy. Enterprise Collection (TA0009) and
#      ICS Collection (TA0100) share a name, not a definition. Folding them equates two
#      matrices, which is the error this block exists to illustrate, not to commit.
#   2. Some Enterprise techniques have no ICS tactic at all; they are listed separately
#      rather than silently dropped.
ETAC = {}
with open(os.path.join(DATA, "enterprise_tactics.csv"), newline="") as f:
    for r in csv.DictReader(f):
        ETAC[r["technique_id"]] = r["enterprise_tactic"]

fold_tac = {t: set(tac_cov[t]) for t in TAC_ORDER}
unplaceable = []
for e in ent_ids:
    t = ETAC.get(e)
    if t in fold_tac:
        fold_tac[t].add(e)
    else:
        unplaceable.append((e, t))

fold_tech = set(techs) | set(ent_ids)
fold_cov = sum(1 for t in TAC_ORDER if fold_tac[t])
print("\nSENSITIVITY (Enterprise counted as ICS coverage; not reported in the paper):")
print("  distinct techniques:", len(fold_tech), " tactics covered:", fold_cov, "/12",
      f"(headline: {len(techs)} techniques, {covered_tac}/12)")
gained = {t: sorted(fold_tac[t] - tac_cov[t]) for t in TAC_ORDER if fold_tac[t] - tac_cov[t]}
print("  techniques gained, per tactic:", gained)
print("  tactics gained:", [t for t in TAC_ORDER if fold_tac[t] and not tac_cov[t]])
print("  tactics still empty:", [t for t in TAC_ORDER if not fold_tac[t]])
if unplaceable:
    print("  Enterprise techniques with no ICS tactic:",
          [f"{e} ({t})" for e, t in unplaceable])
