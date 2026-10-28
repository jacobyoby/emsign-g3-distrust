#!/usr/bin/env bash
# Regenerate committed SIEM stubs under rules/sigma and rules/elastic from indicators.csv.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m pip install -e . -q
python3 -c "from emsign_g3.siem_artifacts import refresh_committed_rules; refresh_committed_rules()"
if [[ "${1:-}" == "--check" ]]; then
  emsign-g3 export-indicators --check-committed-rules
fi
