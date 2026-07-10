#!/usr/bin/env python3
"""Generate EVIDENCE_LOG.md from mapping_evidence.csv.
A per-technique justification reference: for every ICS/Enterprise/dropped mapping cell,
records the exact paper location and a verbatim quote from the dataset's ORIGINAL paper.
Purpose: answer any reviewer challenge on a single cell with one lookup."""
import csv, os
from collections import defaultdict, OrderedDict
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
SRC  = os.path.join(DATA, "mapping_evidence.csv")
OUT  = os.path.join(DATA, "EVIDENCE_LOG.md")

# full citations per dataset (for the header of each section)
CITE = {
 "Edge-IIoTset":"M. A. Ferrag, O. Friha, D. Hamouda, L. Maglaras, H. Janicke, \"Edge-IIoTset: A new comprehensive realistic cyber security dataset of IoT and IIoT applications,\" IEEE Access, vol. 10, 2022.",
 "X-IIoTID":"M. Al-Hawawreh, E. Sitnikova, N. Aboutorab, \"X-IIoTID: A connectivity- and device-agnostic intrusion dataset for industrial Internet of Things,\" IEEE Internet Things J., vol. 9, no. 5, 2022.",
 "ICS-NAD":"X. Zhou et al., \"A dataset collected in real-world industrial control systems for network attack detection,\" Scientific Data, vol. 13, Art. 399, 2026.",
 "ICS-Flow":"A. Dehlaghi-Ghadim, M. H. Moghadam, A. Balador, H. Hansson, \"Anomaly detection dataset for industrial control systems,\" IEEE Access, vol. 11, 2023 (arXiv:2305.09678).",
 "Rodofile":"N. R. Rodofile et al., \"Process control cyber-attacks and labelled datasets on S7Comm critical infrastructure,\" ACISP, Springer, 2017.",
 "HIL-WDT":"L. Faramondi, F. Flammini, S. Guarino, R. Setola, \"A hardware-in-the-loop water distribution testbed dataset for cyber-physical security testing,\" IEEE Access, vol. 9, 2021.",
 "MSU-GP":"T. Morris, W. Gao, \"Industrial control system traffic data sets for intrusion detection research,\" Critical Infrastructure Protection VIII, Springer, 2014.",
 "MSU-PWR":"U. Adhikari, S. Pan, T. Morris et al., Power System Attack Datasets README (MSU/ORNL, 2014); R. C. B. Hink et al., \"Machine learning for power system disturbance and cyber-attack discrimination,\" ISRCS, 2014.",
 "SWaT":"J. Goh, S. Adepu, K. N. Junejo, A. Mathur, \"A Dataset to Support Research in the Design of Secure Water Treatment Systems,\" CRITIS 2016; iTrust SWaT.A1&A2 (Dec 2015) + A6 (Dec 2019) attack docs.",
 "EDS":"Y. Xue et al., \"Real-time intrusion detection based on decision fusion in industrial control systems,\" IEEE Trans. Ind. Cyber-Phys. Syst., vol. 2, 2024.",
}
ORDER = ["Edge-IIoTset","ICS-NAD","X-IIoTID","MSU-PWR","ICS-Flow","Rodofile","HIL-WDT","MSU-GP","EDS","SWaT"]

rows = list(csv.DictReader(open(SRC)))
by = defaultdict(list)
for r in rows: by[r["dataset"]].append(r)

GRADES = ("high", "medium")
def kind(r):
    c = r["confidence"]
    if c == "enterprise": return "Enterprise (reported separately)"
    if c == "removed": return "Removed"
    if c == "unmapped": return "Documented, unmapped (no ATT&CK technique in either matrix)"
    if c not in GRADES:
        raise SystemExit(f"unrecognised confidence {c!r} in mapping_evidence.csv")
    return "ICS"

with open(OUT, "w") as f:
    f.write("# ATT&CK Mapping Evidence Log\n\n")
    f.write("Every technique assignment is grounded in a verbatim passage from the dataset's "
            "**own paper or its official release documentation**. For each cell: the attack class "
            "(in the source's own wording), the assigned "
            "technique and tactic, confidence, the exact location, and the quoted evidence. "
            "Enterprise cells are mapped to ATT&CK Enterprise and reported separately. "
            "Generated from `data/mapping_evidence.csv`.\n\n")
    done = [d for d in ORDER if d in by]
    f.write(f"**Datasets grounded so far: {len(done)}/10** — {', '.join(done)}.\n\n---\n\n")
    for d in ORDER:
        if d not in by: continue
        f.write(f"## {d}\n\n")
        f.write(f"> {CITE.get(d,'(citation pending)')}\n\n")
        # split by kind, preserve input order. The group list is DERIVED from kind(), not
        # re-typed: a renamed group must never silently drop rows from the released log.
        GROUPS = ("ICS", "Enterprise (reported separately)", "Removed",
                  "Documented, unmapped (no ATT&CK technique in either matrix)")
        assert set(GROUPS) >= {kind(r) for r in by[d]}, \
            f"{d}: unhandled group(s) {sorted({kind(r) for r in by[d]} - set(GROUPS))}"
        for grp in GROUPS:
            g = [r for r in by[d] if kind(r)==grp]
            if not g: continue
            f.write(f"### {grp}\n\n")
            f.write("| Attack class (paper wording) | Technique | Tactic | Conf. | Paper location | Verbatim evidence |\n")
            f.write("|---|---|---|---|---|---|\n")
            for r in g:
                tid = r["technique_id"].strip()
                tech = f"{tid} {r['technique_name']}".strip(" –-")
                # paper location = trailing "Sec..." portion of source if present
                src = r["source"]
                loc = src.split("+")[0].strip() if "Sec." not in src else "Sec."+src.split("Sec.")[-1].split("+")[0].strip()
                loc = src  # keep full source; it already carries author+section
                ev = r["verbatim_evidence"].replace("|","/").replace("\n"," ")
                f.write(f"| {r['attack_class_paper_wording']} | {tech} | {r['tactic'] or '—'} | {r['confidence']} | {loc} | \"{ev}\" |\n")
            f.write("\n")
        f.write("---\n\n")

print("wrote EVIDENCE_LOG.md |", len(rows), "cells across", len(by), "datasets")
