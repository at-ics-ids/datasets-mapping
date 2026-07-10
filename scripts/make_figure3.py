#!/usr/bin/env python3
# Figure 3: coverage by tactic (techniques exercised vs available), from coverage_matrix.csv + ATT&CK v19.1 tactic counts
import csv, os
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
rows=list(csv.DictReader(open(os.path.join(_ROOT,"data","coverage_matrix.csv"))))
# A technique is credited to every tactic ATT&CK lists it under; sub-techniques inherit
# their parent's tactics. Same rule the `available` counts below obey.
TACTICS={}
for r in csv.DictReader(open(os.path.join(_ROOT,"data","attack_ics_v19_1_technique_tactics.csv"))):
    TACTICS.setdefault(r["technique_id"],[]).append(r["tactic"])
covered={}
for r in rows:
    for t in TACTICS[r["technique_id"].split(".")[0]]:
        covered[t]=covered.get(t,0)+1
# Available techniques per tactic: ONE source, the shipped catalog. Do not re-type these
# here. attack_ics_v19_1_catalog.csv cites the versioned matrix permalink and carries the
# note explaining why the column totals 90 pairs across 79 distinct techniques.
TAC_ORDER=["Initial Access","Execution","Persistence","Privilege Escalation","Evasion",
           "Discovery","Lateral Movement","Collection","Command and Control",
           "Inhibit Response Function","Impair Process Control","Impact"]
_cat={r["tactic"]:int(r["techniques_available"])
      for r in csv.DictReader(open(os.path.join(_ROOT,"data","attack_ics_v19_1_catalog.csv")))}
_missing=[t for t in TAC_ORDER if t not in _cat]
if _missing:
    raise SystemExit(f"attack_ics_v19_1_catalog.csv is missing tactics: {_missing}")
AVAIL=[(t,_cat[t]) for t in TAC_ORDER]
names=[t for t,_ in AVAIL]; avail=[a for _,a in AVAIL]; cov=[covered.get(t,0) for t,_ in AVAIL]
# Do not read `sum` as a technique count: a technique is credited to every tactic it
# appears under, so this totals tactic-technique PAIRS, not distinct techniques.
print("covered per tactic:", {t:covered.get(t,0) for t,_ in AVAIL})
print("  ", sum(cov), "tactic-technique pairs across",
      len({r["technique_id"] for r in rows}), "distinct techniques")
y=range(len(names))
fig,ax=plt.subplots(figsize=(7.2,3.9))
ax.barh(y,avail,color="#cdd8e8",label="Available in ATT&CK for ICS v19.1")
ax.barh(y,cov,color="#2E5FA6",label="Exercised by the ten datasets")
for i,(c,a) in enumerate(zip(cov,avail)):
    ax.text(a+0.15,i,f"{c}/{a}",va="center",ha="left",fontsize=7)
ax.set_yticks(list(y)); ax.set_yticklabels(names,fontsize=8); ax.invert_yaxis()
ax.set_xlabel("Number of techniques",fontsize=8); ax.set_xlim(0,15); ax.tick_params(axis='x',labelsize=7)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
ax.legend(fontsize=7,loc="lower center",bbox_to_anchor=(0.5,1.01),ncol=2,frameon=False)
plt.tight_layout()
out=os.path.join(_ROOT,"figures","Figure3_coverage_by_tactic")
# Deterministic output: matplotlib stamps a wall-clock /CreationDate into every PDF and
# the library version into every PNG. Both are suppressed so `git status` after a run
# reflects the mapping, not the clock. Note the PNG pixels still depend on the
# matplotlib version (tight bbox is measured from text extents); see requirements.txt.
fig.savefig(out+".png",dpi=300,bbox_inches="tight",metadata={"Software":None})
fig.savefig(out+".pdf",bbox_inches="tight",metadata={"CreationDate":None})
print("saved",out+".png")
