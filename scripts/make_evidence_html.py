#!/usr/bin/env python3
"""Generate evidence-log.html (dashboard page) from mapping_evidence.csv.
Browsable per-dataset primary-source evidence: every technique with its paper location + verbatim quote."""
import csv, os, html
from collections import defaultdict
HERE=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.dirname(HERE)
DATA=os.path.join(ROOT,"data")
SRC=os.path.join(DATA,"mapping_evidence.csv")
OUT=os.path.join(ROOT,"evidence-log.html")

CITE={
 "Edge-IIoTset":"M. A. Ferrag et al., “Edge-IIoTset: A new comprehensive realistic cyber security dataset of IoT and IIoT applications,” IEEE Access, vol. 10, 2022.",
 "X-IIoTID":"M. Al-Hawawreh, E. Sitnikova, N. Aboutorab, “X-IIoTID: A connectivity- and device-agnostic intrusion dataset for industrial IoT,” IEEE Internet Things J., vol. 9, no. 5, 2022.",
 "ICS-NAD":"X. Zhou et al., “A dataset collected in real-world industrial control systems for network attack detection,” Scientific Data, vol. 13, Art. 399, 2026.",
 "ICS-Flow":"A. Dehlaghi-Ghadim et al., “Anomaly detection dataset for industrial control systems,” IEEE Access, vol. 11, 2023 (arXiv:2305.09678).",
 "Rodofile":"N. R. Rodofile et al., “Process control cyber-attacks and labelled datasets on S7Comm critical infrastructure,” ACISP, Springer, 2017.",
 "HIL-WDT":"L. Faramondi et al., “A hardware-in-the-loop water distribution testbed dataset for cyber-physical security testing,” IEEE Access, vol. 9, 2021.",
 "MSU-GP":"T. Morris, W. Gao, “Industrial control system traffic data sets for intrusion detection research,” Critical Infrastructure Protection VIII, Springer, 2014.",
 "MSU-PWR":"U. Adhikari, S. Pan, T. Morris et al., Power System Attack Datasets README (MSU/ORNL, 2014); R. C. B. Hink et al., ISRCS 2014.",
 "EDS":"Y. Xue et al., “Real-time intrusion detection based on decision fusion in industrial control systems,” IEEE Trans. Ind. Cyber-Phys. Syst., vol. 2, 2024.",
 "SWaT":"J. Goh, S. Adepu, K. N. Junejo, A. Mathur, “A Dataset to Support Research in the Design of Secure Water Treatment Systems,” CRITIS 2016; iTrust SWaT.A1&A2 (Dec 2015) + A6 (Dec 2019) attack docs.",
}
ORDER=["Edge-IIoTset","ICS-NAD","X-IIoTID","MSU-PWR","ICS-Flow","Rodofile","HIL-WDT","MSU-GP","EDS","SWaT"]
def e(x): return html.escape(str(x or ""))

rows=list(csv.DictReader(open(SRC)))
by=defaultdict(list)
for r in rows: by[r["dataset"]].append(r)

def kind(r):
    c=r["confidence"]
    if c=="enterprise": return "ent"
    if c in ("removed","out-of-scope"): return "rm"
    return "ics"

# summary counts
ics_t=set(); ent_t=set()
for r in rows:
    if kind(r)=="ics" and r["tactic"]: ics_t.add(r["technique_id"])
    if kind(r)=="ent":
        code=r["technique_id"].replace("ENT:","").split()[0]
        if code!="pivot": ent_t.add(code)

CSS="""
:root{--accent:#2E5FA6;--accent2:#12385f;--line:#dfe4ea;--card:#fff;--muted:#6b7683;--chip:#eef2f8}
body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#24303c;background:#f4f6f9}
.top{background:#12385f;color:#fff;padding:18px 0}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
.top h1{margin:.1em 0;font-size:22px}.top p{margin:.1em 0;color:#c8d6e6;font-size:13.5px}
.crumbs a{color:#bcd3ef;text-decoration:none;font-size:13px}
.sub{color:var(--muted);font-size:13.5px;margin:16px 0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:14px 0 20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 10px;text-align:center}
.stat .n{font-size:22px;font-weight:700;color:var(--accent)}.stat .l{font-size:11.5px;color:var(--muted);margin-top:2px}
details.ds{background:var(--card);border:1px solid var(--line);border-radius:11px;margin:0 0 12px;overflow:hidden}
details.ds>summary{cursor:pointer;padding:12px 16px;font-weight:700;font-size:15px;list-style:none;display:flex;align-items:center;gap:10px}
details.ds>summary::-webkit-details-marker{display:none}
details.ds>summary::before{content:"\\25B8";color:var(--accent);transition:transform .15s}
details.ds[open]>summary::before{transform:rotate(90deg)}
.cnt{margin-left:auto;font-weight:400;font-size:12px;color:var(--muted)}
.body{padding:0 16px 14px;border-top:1px solid var(--line)}
.cite{font-size:12.5px;color:#3a4757;background:#f7f9fc;border-left:3px solid var(--accent);border-radius:6px;padding:8px 12px;margin:12px 0}
h4{margin:14px 0 4px;font-size:13px;color:var(--accent2)}
h4.ent{color:#7a4fb5}h4.rm{color:#b23b3b}
table{border-collapse:collapse;width:100%;font-size:12px;margin:2px 0}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef2f8;color:var(--accent2);font-size:11.5px}
.tid{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--accent2);background:var(--chip);padding:1px 5px;border-radius:5px;white-space:nowrap}
.tid.ent{color:#7a4fb5;background:#f1ecf8}
.conf-high{color:#1f7a4d;font-weight:600}.conf-medium{color:#8a5a12;font-weight:600}
.ev{color:#33404d;font-style:italic}
.loc{font-size:11px;color:var(--muted);white-space:nowrap}
.foot{color:var(--muted);font-size:12px;margin:22px 0;text-align:center}
@media print{body{background:#fff}.top{background:#12385f!important;-webkit-print-color-adjust:exact}details.ds{break-inside:avoid}details.ds[open]>summary::before{content:""}}
"""

parts=[]
parts.append(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence Log — Cyber-AI 2026</title><link rel="icon" href="favicon.svg" type="image/svg+xml">
<style>{CSS}</style></head><body>
<header class="top"><div class="wrap"><nav class="crumbs"><a href="index.html">← Dashboard</a></nav>
<h1>Mapping Evidence Log</h1><p>Every ATT&amp;CK technique, grounded in the dataset's own paper or official release documentation</p></div></header>
<div class="wrap">
<p class="sub">For each of the ten datasets, every mapped technique is backed by a verbatim passage from the <b>original dataset paper</b> and its exact location. Enterprise cells are (mapped to ATT&amp;CK Enterprise, reported separately). Removed cells record assignments dropped as unsupported. Generated from <code>mapping/mapping_evidence.csv</code>.</p>
<div class="stats">
  <div class="stat"><div class="n">10/10</div><div class="l">datasets grounded</div></div>
  <div class="stat"><div class="n">{len(ics_t)}</div><div class="l">ICS techniques</div></div>
  <div class="stat"><div class="n">{len(ent_t)}</div><div class="l">Enterprise techniques</div></div>
  <div class="stat"><div class="n">{len(rows)}</div><div class="l">evidence cells</div></div>
</div>""")

def table(cells, enterprise=False):
    h="<table><tr><th>Attack class (paper wording)</th><th>Technique</th><th>Tactic</th><th>Conf.</th><th>Paper location</th><th>Verbatim evidence</th></tr>"
    for r in cells:
        tid=r["technique_id"].replace("ENT:","").strip()
        cls="tid ent" if enterprise else "tid"
        conf=r["confidence"]
        cc=f'conf-{conf}' if conf in ("high","medium") else ""
        h+=(f"<tr><td>{e(r['attack_class_paper_wording'])}</td>"
            f"<td><span class='{cls}'>{e(tid)}</span> {e(r['technique_name'])}</td>"
            f"<td>{e(r['tactic']) or '&mdash;'}</td>"
            f"<td class='{cc}'>{e(conf)}</td>"
            f"<td class='loc'>{e(r['source'])}</td>"
            f"<td class='ev'>“{e(r['verbatim_evidence'])}”</td></tr>")
    return h+"</table>"

for d in ORDER:
    if d not in by: continue
    g=by[d]
    ics=[r for r in g if kind(r)=="ics"]; ent=[r for r in g if kind(r)=="ent"]; rm=[r for r in g if kind(r)=="rm"]
    ntech=len({r["technique_id"] for r in ics})
    parts.append(f'<details class="ds"><summary>{e(d)} <span class="cnt">{ntech} ICS techniques'
                 + (f' · {len(ent)} Enterprise' if ent else '') + (f' · {len(rm)} removed' if rm else '') + '</span></summary>')
    parts.append(f'<div class="body"><div class="cite">{e(CITE.get(d,""))}</div>')
    if ics: parts.append("<h4>ICS techniques</h4>"+table(ics))
    if ent: parts.append('<h4 class="ent">ATT&amp;CK Enterprise (reported separately)</h4>'+table(ent,enterprise=True))
    if rm:  parts.append('<h4 class="rm">Removed / out of scope</h4>'+table(rm))
    parts.append("</div></details>")

parts.append('<p class="foot">Built 9 Jul 2026 · regenerated from mapping_evidence.csv · companion to the released mapping + EVIDENCE_LOG.md</p></div></body></html>')
open(OUT,"w").write("\n".join(parts))
print("wrote evidence-log.html |", len(rows), "cells,", len(by), "datasets")
