#!/usr/bin/env python3
# Figure 2: technique frequency (how many of the 10 datasets exercise each technique)
import csv, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
_HERE=os.path.dirname(os.path.abspath(__file__))
_ROOT=os.path.dirname(_HERE)
HERE=os.path.dirname(os.path.abspath(__file__))
rows=list(csv.reader(open(os.path.join(HERE,"..","mapping",os.path.join(_ROOT,"data","coverage_matrix.csv")))))
hdr=rows[0]; data=rows[1:]
items=[]
for r in data:
    tid=r[0]; freq=sum(1 for c in r[3:] if c.strip()=="1"); items.append((tid,freq))
items.sort(key=lambda x:(-x[1], x[0]))
ids=[i[0] for i in items]; vals=[i[1] for i in items]
fig,ax=plt.subplots(figsize=(10,3.3))
bars=ax.bar(range(len(ids)),vals,width=0.8,color="#2E5FA6")
ax.set_xticks(range(len(ids))); ax.set_xticklabels(ids,rotation=90,fontsize=6)
ax.set_ylabel("Number of datasets",fontsize=8); ax.set_ylim(0,10.5)
ax.set_yticks(range(0,11,2)); ax.tick_params(axis='y',labelsize=7)
for b,v in zip(bars,vals):
    ax.text(b.get_x()+b.get_width()/2,v+0.12,str(v),ha="center",va="bottom",fontsize=6)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
ax.grid(axis='y',color="#dddddd",linewidth=0.6); ax.set_axisbelow(True)
plt.tight_layout()
out=os.path.join(_ROOT,"figures","Figure2_technique_frequency")
fig.savefig(out+".png",dpi=300,bbox_inches="tight"); fig.savefig(out+".pdf",bbox_inches="tight")
print("saved",out+".png","| techniques:",len(ids),"| max freq:",max(vals))
