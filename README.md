# ATT&CK-for-ICS Technique Coverage Toolkit

Technique-level mapping of 10 public ICS/IIoT intrusion-detection datasets to
MITRE ATT&CK for ICS **v19.1**, with the scripts that reproduce every figure and table in the paper.

**Headline.** The ten datasets exercise **18 ICS techniques** across **7 of the 12 tactics**.
Enterprise (IT) attacks carried by the IIoT datasets map to **7 ATT&CK Enterprise techniques**, reported
separately and never counted as ICS coverage.

Coverage is reported at **parent-technique grain**, matching the granularity of the published v19.1 catalog:
`T1692.001` and `T1692.002` are both credited to `T1692 Unauthorized Message`, and the released mapping keeps
the sub-technique identifiers. A technique is credited to **every** tactic ATT&CK lists it under, which is the
rule the `techniques_available` column of `data/attack_ics_v19_1_catalog.csv` already obeys.

## Reproduce

```bash
pip install -r requirements.txt
bash reproduce.sh
```

The pins matter only for the figures. Every CSV, `EVIDENCE_LOG.md` and the ten data cards
are produced with the standard library and reproduce byte for byte on any Python 3; the
three PNG files reproduce only under `matplotlib==3.10.9`, the version they were rendered
with. Nothing in `scripts/` imports pandas.

Regenerates `data/coverage_matrix.csv`, `data/enterprise_summary.csv`, all three figures, the evidence log, the ten data cards, and the paper's Table II (`data/table2_per_dataset.csv`) and Table III (`data/table3_tactic_coverage.csv`, including the uncovered set per tactic).

## Grounding

Every mapped technique is taken from the dataset's **own paper or its official release documentation**, never
from a secondary summary. `data/mapping_evidence.csv` records, per cell, the verbatim passage that supports the
assignment, its source, and a confidence grade.

Confidence: **high** (60 cells) means the dataset's own description names the behavior the technique
describes; **medium** (9 cells) means the technique follows by inference from that description. Of the 69 ICS
assignments, one technique (`T0826 Loss of Availability`) rests on a single medium cell; rejecting every medium
assignment would leave 17 techniques and would empty no tactic.

Five candidate assignments were considered and rejected; they are kept in `data/mapping_evidence.csv` with
`confidence = removed` and the evidence behind each rejection. One documented behaviour carries no ATT&CK
identifier in either matrix and is recorded as `confidence = unmapped`.

## Layout

| path | contents |
|---|---|
| `scripts/` | mapping builder, figure scripts, table generator, evidence-log generators |
| `data/` | curated mapping, coverage matrix, enterprise summary, per-cell evidence, ATT&CK v19.1 catalog and technique-to-tactic map |
| `requirements.txt` | pinned versions; needed only for byte-identical figures |
| `figures/` | Figures 1-3 (PNG + PDF) |
| `datacards/` | machine-readable per-dataset cards (`<Dataset>.json` + `index.json`) |
| `NOTICE` | what this repository does not contain; MITRE ATT&CK and dataset-author rights |

## Licensing

The code is provided under the **MIT License** (`LICENSE`), and the mapping tables,
machine-readable data cards, figures, and documentation are provided under
**CC BY 4.0** (`LICENSE-DATA`). GitHub's sidebar reports only MIT; that is a
display limitation, not the terms.

## Scope and third-party rights

Read `NOTICE` before reusing anything here. In short:

**No datasets ship with this repository.** No traffic, no measurements, no labels.
What ships is a mapping of the attacks each dataset's authors *documented*. Every
dataset remains the property of its authors and is governed by its own terms of
distribution: obtain each one from its published source, or by request to its
authors, and comply with the terms they set. DOIs are in `data/dataset_meta.csv`.
This repository confers no right of access to any dataset.

**MITRE ATT&CK.** Technique and tactic identifiers and names are reproduced from
MITRE ATT&CK for ICS v19.1. © 2026 The MITRE Corporation. This work is reproduced
and distributed with the permission of The MITRE Corporation. ATT&CK® is a
registered trademark of The MITRE Corporation, which does not endorse this work.

**Quoted passages.** `data/mapping_evidence.csv` quotes short attributed passages
from the ten dataset papers so that each mapped technique can be traced to the
sentence that justifies it. Copyright in those sentences stays with their authors.
CC BY 4.0 covers our compilation, not the quotations. Cite the dataset papers.

## Citation

See `CITATION.cff`, and cite the paper. A DOI-bearing archive will be deposited on
acceptance; until then, cite the repository by its release tag.
