#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
pip install -e ".[dev]" >/dev/null

pytest -q
soc-ai version
soc-ai doctor --min-free-gb 1
soc-ai pipeline-local --input sample_data/events.jsonl --run-dir reports/release-check-local
soc-ai qa-run --run-dir reports/release-check-local
soc-ai site-build --reports-dir reports --output-dir site
soc-ai datasets
soc-ai hec-send --input reports/release-check-local/data/events.redacted.jsonl.gz --index soc_ai_test --dry-run
soc-ai splunk-stage-tests --counts 100 --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --output-dir reports/release-check-splunk-stage --local-only
soc-ai ops-audit --reports-dir reports
soc-ai splunk-preflight --spl 'index=security sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --estimate-only 400000000 --skip-remote-count
soc-ai pipeline-splunk --spl 'index=security sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --estimate-only 400000000 --dry-run
soc-ai evaluate-labeled sample_data/labeled_scores.jsonl --threshold 0.5 --output reports/release-check-labeled.json

echo "release-check: ok"
