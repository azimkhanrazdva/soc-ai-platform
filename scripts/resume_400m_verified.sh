#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/soc-ai/app"
. .venv/bin/activate
RUN_ROOT="reports/400m-full-20260907-055835"
PIPE_DIR="$RUN_ROOT/pipeline-splunk-production"
LOG="$RUN_ROOT/resume-production-$(date -u +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
date -u +"resume_started=%Y-%m-%dT%H:%M:%SZ"
python3 - <<'PY'
import shutil
if shutil.disk_usage('.').free < 35 * 1024**3:
    raise SystemExit('Disk free below 35 GiB guard')
PY
# Reuse the campaign size for planning; the exact row gate below blocks publication.
soc-ai --config configs/production.toml pipeline-splunk \
  --estimate-only 400000000 \
  --spl "index=main source=soc-ai-400m-full-20260907055835" \
  --start "2026-09-01T00:00:00Z" --end "2026-09-08T00:00:00Z" \
  --run-dir "$PIPE_DIR" | tee "$RUN_ROOT/pipeline-production.json"
soc-ai --config configs/production.toml qa-run --run-dir "$PIPE_DIR" | tee "$RUN_ROOT/qa.json"
python3 - <<'PY'
import json
from pathlib import Path
root = Path('reports/400m-full-20260907-055835')
result = json.loads((root / 'pipeline-production.json').read_text())
qa = json.loads((root / 'qa.json').read_text())
if not result.get('integrity_ok') or result['ingest']['rows'] != 400000000:
    raise SystemExit('400M integrity/row count gate failed')
if qa.get('status') != 'pass':
    raise SystemExit('QA gate failed')
PY
soc-ai --config configs/production.toml ops-audit --reports-dir reports --splunk-host 127.0.0.1 > "$RUN_ROOT/ops-audit.json"
soc-ai --config configs/production.toml scale-report \
  --scale-plan "$RUN_ROOT/scale-plan.json" --audit "$RUN_ROOT/ops-audit.json" \
  --output "$RUN_ROOT/SOC-AI-400M-final-report.md"
date -u +"resume_finished=%Y-%m-%dT%H:%M:%SZ"
