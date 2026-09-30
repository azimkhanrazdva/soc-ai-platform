# SOC AI Platform Runbook

## First Check

```bash
cd /opt/soc-ai-platform
. .venv/bin/activate
soc-ai doctor
pytest -q
```

Full release check:

```bash
scripts/release_check.sh
```

Build local status site:

```bash
soc-ai site-build --reports-dir reports --output-dir site
python3 -m http.server 8090 --directory site
```

Quick complete local check:

```bash
soc-ai pipeline-local --input sample_data/events.jsonl
```

Review configured agents and rules:

```bash
soc-ai agents
soc-ai rules-list
```

`doctor` can be ready locally even when Splunk credentials are missing. Splunk export requires `SPLUNK_BASE_URL` and `SPLUNK_TOKEN`.

## Safe Splunk Workflow

1. Run preflight first.

```bash
soc-ai splunk-preflight --spl 'index=main sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z
```

Or use a saved export profile:

```bash
soc-ai splunk-profiles
soc-ai splunk-profile-plan --profile security_24h --estimate-only 400000000
```

2. If preflight count is too large, add partitions.

```bash
soc-ai splunk-preflight --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --partitions-json '[{"index":"main"},{"index":"security"}]'
```

3. Run dry-run and inspect windows.

```bash
soc-ai splunk-ingest --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --partitions-json '[{"index":"main"},{"index":"security"}]' --dry-run
```

4. Run export.

```bash
soc-ai splunk-ingest --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --partitions-json '[{"index":"main"},{"index":"security"}]'
```

Or run the full Splunk pipeline:

```bash
soc-ai pipeline-splunk --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --partitions-json '[{"index":"main"},{"index":"security"}]'
```

5. Build integrity manifest.

```bash
soc-ai manifest data/chunks/*.jsonl --output reports/chunk_manifest.json
soc-ai verify-manifest --manifest reports/chunk_manifest.json
```

6. Analyze and report.

```bash
soc-ai analyze data/chunks/*.jsonl --output reports/analysis.json
soc-ai rules-run data/chunks/*.jsonl --output reports/rule_findings.json
soc-ai report --metrics reports/analysis.json --output-dir reports
```

## Long Run In tmux

```bash
tmux new -s soc-run
cd /opt/soc-ai-platform
. .venv/bin/activate
soc-ai splunk-ingest --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z
```

Detach: `Ctrl+B`, then `D`.

Resume:

```bash
tmux attach -t soc-run
```

## Data Loss Rules

- Do not use `head`, `limit`, or sampling in production SPL exports unless the run is explicitly marked as a sample.
- The CLI rejects `head`, `tail`, `sample`, and bounded `sort` in Splunk exports by default.
- Prefer smaller windows or more partitions when chunks are too large.
- Keep checkpoint and manifest files with reports.
- Delete only project-owned temporary files, never Splunk source data or final chunk data.
