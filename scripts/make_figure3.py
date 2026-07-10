#!/usr/bin/env python3
# Figure 3: coverage by tactic (techniques exercised vs available), from coverage_matrix.csv + ATT&CK v19.1 tactic counts
import csv, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
_HERE=os.path.dirname(os.path.abspath(__file__))
_ROOT=os.path.dirname(_HERE)
HERE=os.path.dirname(os.path.abspath(__file__))
rows=list(csv.reader(open(os.path.join(HERE,"..","mapping",os.path.join(_ROOT,"data","coverage_matrix.csv")))))[1:]
# covered = distinct covered techniques per tactic (each row in the matrix is a covered technique)
covered={}
for r in rows: covered[r[2]]=covered.get(r[2],0)+1
# available techniques per tactic in ATT&CK for ICS v19.1 (from the matrix header counts)
AVAIL=[("Initial Access",12),("Execution",10),("Persistence",5),("Privilege Escalation",2),
       ("Evasion",7),("Discovery",5),("Lateral Movement",6),("Collection",11),
       ("Command and Control",3),("Inhibit Response Function",13),("Impair Process Control",4),("Impact",12)]
names=[t for t,_ in AVAIL]; avail=[a for _,a in AVAIL]; cov=[covered.get(t,0) for t,_ in AVAIL]
print("covered per tactic:", {t:covered.get(t,0) for t,_ in AVAIL}, "sum", sum(cov))
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
fig.savefig(out+".png",dpi=300,bbox_inches="tight"); fig.savefig(out+".pdf",bbox_inches="tight")
print("saved",out+".png")
