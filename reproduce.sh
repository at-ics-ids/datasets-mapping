#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "[1/5] mapping + coverage matrix"; python3 scripts/build_mapping.py
echo "[2/5] figures"; for f in 1 2 3; do python3 "scripts/make_figure$f.py"; done
echo "[3/5] evidence log"; python3 scripts/make_evidence_log.py; python3 scripts/make_evidence_html.py
echo "[4/5] data cards"; python3 scripts/make_datacards.py
echo "[5/5] tables"; python3 scripts/make_tables.py
echo "done."
