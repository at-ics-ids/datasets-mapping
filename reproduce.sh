#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Preflight. Runs before step 1 writes anything, so a missing dependency leaves the
# working tree clean instead of half-regenerated.
python3 - <<'PRE' || exit 1
import sys
missing = []
for m in ("matplotlib", "numpy"):
    try:
        __import__(m)
    except Exception as exc:
        missing.append(f"{m} ({exc})")
if missing:
    sys.exit("reproduce.sh: cannot import " + "; ".join(missing) + ".\n"
             "  Install the pinned versions:  pip install -r requirements.txt\n"
             "  Nothing has been written; the working tree is untouched.")
import matplotlib
PINNED = "3.10.9"
if matplotlib.__version__ != PINNED:
    print(f"reproduce.sh: matplotlib {matplotlib.__version__}; the figures were rendered with {PINNED}.")
    print("  Every CSV, the evidence log and the data cards will still match byte for byte.")
    print("  The three PNG files will not: a different matplotlib re-lays out the plot.")
PRE

echo "[1/6] mapping + coverage matrix"; python3 scripts/build_mapping.py
echo "[2/6] figures"; for f in 1 2 3; do python3 "scripts/make_figure$f.py"; done
echo "[3/6] evidence log (markdown)"; python3 scripts/make_evidence_log.py
echo "[4/6] evidence log (html)"; python3 scripts/make_evidence_html.py
echo "[5/6] data cards"; python3 scripts/make_datacards.py
echo "[6/6] tables"; python3 scripts/make_tables.py
echo "done."
