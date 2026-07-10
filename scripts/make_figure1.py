#!/usr/bin/env python3
# Figure 1: technique coverage matrix (datasets x techniques).
# ICS techniques (blue) from data/coverage_matrix.csv, plus a separate ATT&CK Enterprise
# band (purple) from data/enterprise_summary.csv. Enterprise is NOT counted as ICS coverage.
import csv, os
_HERE=os.path.dirname(os.path.abspath(__file__))
_ROOT=os.path.dirname(_HERE)
import matplotlib; matplotlib.use("Agg")
import numpy as np, matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap

rows=list(csv.reader(open(os.path.join(_ROOT,"data","coverage_matrix.csv"))))
hdr=rows[0]; datasets=hdr[3:]; data=rows[1:]
order=["Initial Access","Execution","Persistence","Privilege Escalation","Evasion","Discovery",
       "Lateral Movement","Collection","Command and Control","Inhibit Response Function","Impair Process Control","Impact"]
abbr={"Initial Access":"IA","Execution":"EX","Persistence":"PE","Privilege Escalation":"PR","Evasion":"EV",
      "Discovery":"DI","Lateral Movement":"LM","Collection":"CO","Command and Control":"C2",
      "Inhibit Response Function":"IRF","Impair Process Control":"IPC","Impact":"IM"}
ics=[(r[0], r[2], [1 if c.strip()=="1" else 0 for c in r[3:]]) for r in data]
ics.sort(key=lambda t:(order.index(t[1]), t[0]))

# Enterprise band (reported separately; not ICS coverage)
ent_rows=list(csv.DictReader(open(os.path.join(_ROOT,"data","enterprise_summary.csv"))))
ent_ids=sorted({r["enterprise_ref"].split()[0] for r in ent_rows})
ent_has={(r["dataset"], r["enterprise_ref"].split()[0]) for r in ent_rows}
ent=[(tid, "ENT", [2 if (d,tid) in ent_has else 0 for d in datasets]) for tid in ent_ids]

cols=ics+ent
M=np.array([[c[2][j] for c in cols] for j in range(len(datasets))])

fig,ax=plt.subplots(figsize=(12,3.7))
ax.imshow(M,cmap=ListedColormap(["#eef0f2","#2E5FA6","#7a4fb5"]),aspect="auto",vmin=0,vmax=2)
ax.set_xticks(np.arange(-0.5,len(cols),1),minor=True)
ax.set_yticks(np.arange(-0.5,len(datasets),1),minor=True)
ax.grid(which="minor",color="white",linewidth=1.1); ax.tick_params(which="minor",length=0)
ax.set_xticks(range(len(cols)))
ax.set_xticklabels([c[0] for c in cols],rotation=90,fontsize=6)
for i,lbl in enumerate(ax.get_xticklabels()):
    if cols[i][1]=="ENT": lbl.set_color("#7a4fb5")
ax.set_yticks(range(len(datasets))); ax.set_yticklabels(datasets,fontsize=8)

seq=[c[1] for c in cols]; s=0
for i in range(1,len(cols)+1):
    if i==len(cols) or seq[i]!=seq[s]:
        if i<len(cols):
            lw = 1.8 if seq[i]=="ENT" else 0.8
            ax.axvline(i-0.5,color="black",linewidth=lw)
        if seq[s]=="ENT":
            ax.text((s+i-1)/2,-0.95,"ATT&CK ENTERPRISE",ha="center",va="bottom",
                    fontsize=7,fontweight="bold",color="#7a4fb5")
        else:
            ax.text((s+i-1)/2,-0.95,abbr[seq[s]],ha="center",va="bottom",fontsize=7,fontweight="bold")
        s=i
ax.set_ylim(len(datasets)-0.5,-1.35)
for sp in ax.spines.values(): sp.set_visible(False)
plt.tight_layout()
out=os.path.join(_ROOT,"figures","Figure1_coverage_matrix")
# Deterministic output: matplotlib stamps a wall-clock /CreationDate into every PDF and
# the library version into every PNG. Both are suppressed so `git status` after a run
# reflects the mapping, not the clock. Note the PNG pixels still depend on the
# matplotlib version (tight bbox is measured from text extents); see requirements.txt.
fig.savefig(out+".png",dpi=300,bbox_inches="tight",metadata={"Software":None})
fig.savefig(out+".pdf",bbox_inches="tight",metadata={"CreationDate":None})
print("saved",out+".png","| ICS techniques:",len(ics),"| Enterprise:",len(ent),"| datasets:",len(datasets))
