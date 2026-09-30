# SOC AI Platform

SOC AI Platform is a Python 3.11 toolkit for safe Splunk log extraction, chunked processing, privacy redaction, baseline anomaly analysis, benchmarking, and Markdown/HTML reporting.

It is built for two modes:

- `full`: small datasets that fit comfortably in memory.
- `chunked`: large datasets, including 400M-event class exports, processed by time windows and checkpoints.
- `auto`: chooses `full` for small estimates and `chunked` when the estimate is unknown or large.

## Setup

```bash
cd /opt/soc-ai-platform
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Or:

```bash
make install
```

Set Splunk variables in `.env` or export them in the shell:

```bash
export SPLUNK_BASE_URL="https://splunk.example.local:8089"
export SPLUNK_TOKEN="..."
export SPLUNK_VERIFY_TLS=true
```

The CLI loads `.env` by default. Existing shell variables take precedence over values in `.env`.

## Commands

Check readiness:

```bash
soc-ai doctor
soc-ai ops-audit --splunk-host soc-storage.example.test --reports-dir reports
```

Run release checks:

```bash
scripts/release_check.sh
```

Build the lightweight status site:

```bash
soc-ai site-build --reports-dir reports --output-dir site
python3 -m http.server 8090 --directory site
```

Run QA gates:

```bash
soc-ai qa-run --run-dir reports/release-check-local
```

List public test datasets:

```bash
soc-ai datasets
```

Send JSONL/JSONL.GZ to Splunk HEC in checkpointed batches:

```bash
soc-ai hec-send --input data/synthetic.redacted.jsonl.gz --index soc_ai_test --dry-run
```

HEC output separates `sent_rows` from `skipped_rows`; use `accounted_rows` to confirm resume runs have not lost rows.

Estimate staged 10M/20M/50M/100M disk needs:

```bash
soc-ai scale-plan
```

Run autonomous end-to-end Splunk stage tests. Each stage generates events, sends them to Splunk HEC, waits for indexing, exports them back with SPL chunking, runs integrity checks, builds the report, and applies QA gates:

```bash
soc-ai splunk-stage-tests --counts 10000,100000 --start 2026-09-01T00:00:00Z --end 2026-09-04T00:00:00Z
```

For long unattended runs, first check disk capacity with `soc-ai scale-plan`, then pass larger counts such as `10000000,20000000,50000000,100000000`. Raw generated files are removed after HEC ingest unless `--keep-raw` is set.

Run a complete local pipeline:

```bash
soc-ai pipeline-local --input sample_data/events.jsonl
```

Show SOC agent roles and allowed command boundaries:

```bash
soc-ai agents
```

List and run detection rules:

```bash
soc-ai rules-list
soc-ai rules-run data/sample.redacted.jsonl --output reports/rule_findings.json
```

List and plan saved Splunk export profiles:

```bash
soc-ai splunk-profiles
soc-ai splunk-profile-plan --profile security_24h --estimate-only 400000000
```

Plan a run:

```bash
soc-ai plan --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --estimated-events 400000000
```

Dry-run Splunk chunks:

```bash
soc-ai splunk-ingest --spl 'index=main sourcetype=* error OR failed' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --dry-run
```

Dry-run with partitions:

```bash
soc-ai splunk-ingest --spl 'sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --partitions-json '[{"index":"main"},{"index":"security"}]' --dry-run
```

Export from Splunk with checkpoints:

```bash
soc-ai splunk-ingest --spl 'index=main sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z
```

Run the full Splunk pipeline:

```bash
soc-ai pipeline-splunk --spl 'index=security sourcetype=*' --start 2026-09-01T00:00:00Z --end 2026-09-02T00:00:00Z --estimate-only 400000000 --dry-run
```

Saved Splunk export profiles live in `configs/splunk_exports.toml`. They are intended for repeatable exports where the SPL, time range, and partitions should be reviewed before a long run. Production Splunk exports reject lossy SPL commands such as `head`, `tail`, `sample`, and bounded `sort` by default.

Process local sample data:

```bash
soc-ai ingest-local --input sample_data/events.jsonl --output data/sample.redacted.jsonl
soc-ai analyze data/sample.redacted.jsonl --output reports/analysis.json
soc-ai report --metrics reports/analysis.json --output-dir reports
soc-ai benchmark data/sample.redacted.jsonl
```

Train and evaluate an unsupervised profile:

```bash
soc-ai train data/sample.redacted.jsonl --output reports/model_profile.json
soc-ai evaluate --profile reports/model_profile.json data/sample.redacted.jsonl --output reports/evaluation.json
```

Evaluate labeled scores:

```bash
soc-ai evaluate-labeled sample_data/labeled_scores.jsonl --threshold 0.5 --output reports/labeled_evaluation.json
```

Build and verify chunk integrity manifest:

```bash
soc-ai manifest data/*.jsonl --output reports/chunk_manifest.json
soc-ai verify-manifest --manifest reports/chunk_manifest.json
```

Generate synthetic data for local load tests:

```bash
soc-ai generate-synthetic --rows 100000 --output data/synthetic.jsonl
soc-ai ingest-local --input data/synthetic.jsonl --output data/synthetic.redacted.jsonl
soc-ai benchmark data/synthetic.redacted.jsonl
```

Resume behavior is checkpoint based: rerunning the same Splunk command skips chunks marked `done` and retries failed/missing chunks.

## 400M Event Readiness

This project does not load all events into RAM. Splunk export is split into time windows and optional partitions. Each chunk is written to disk, counted, redacted, checkpointed, and can be resumed. The exporter does not add `head` or `limit` to SPL because silent truncation would lose events. The practical limit depends on Splunk search limits, disk capacity, event size, selected fields, and chunk size.

Use Splunk-side filtering/projection first. SPL itself runs inside Splunk; local GPU acceleration can help only later ML/inference stages, not the Splunk search engine.

Use the local GPU for a review of redacted aggregate metrics after a run:

```bash
soc-ai gpu-review --metrics reports/metrics-*.json --model qwen2.5-coder:3b
soc-ai qa-ai-review --review reports/gpu_review.json
```

This uses Ollama at `OLLAMA_ENDPOINT` (default `http://127.0.0.1:11434/api/generate`) and never sends raw event files to the model. On a 4 GB GPU, the 3B Q4 model is preferred because it can run fully on GPU; larger models may fall back to CPU. The AI review is advisory only. If it makes unsupported attack, breach, or threat claims, `qa-ai-review` fails the output.

## Soup Report Model Training

Soup is optional and runs after ingestion/report QA. It trains a local report-writing model from redacted, QA-approved SOC reports; it is not used for raw Splunk export.

```bash
soc-ai report-training-dataset --run-dir reports/release-check-local --output data/report_training.jsonl
soc-ai soup-report-config --dataset data/report_training.jsonl --output configs/soup-report-model.yaml
soc-ai soup-training-plan --dataset data/report_training.jsonl --soup-config configs/soup-report-model.yaml
```

The generated Soup config defaults to `Qwen/Qwen2.5-7B-Instruct`, QLoRA 4-bit, gradient checkpointing, and layer streaming for lower VRAM. To execute only Soup validation and dry-run checks when Soup is installed:

```bash
soc-ai soup-training-plan --execute
```

Full training remains an explicit operator command from the generated plan. This prevents accidental GPU-heavy training during Splunk scale tests.

For a two-server deployment, run Splunk/export on the storage server with `configs/distributed-test.toml`, and set `OLLAMA_ENDPOINT` to the GPU server's private address. Keep raw chunks and reports on the storage server; send only aggregate metrics to `gpu-review`.

When the servers are on different subnets, use the provided user-level reverse tunnel unit in `deploy/systemd/soc-ai-ollama-tunnel.service`. It exposes Ollama only as `127.0.0.1:11435` on the storage server and does not open the GPU API to the LAN.

The GPU server dashboard is available through `deploy/systemd/soc-ai-monitor.service`. It binds to `127.0.0.1:8091`; view it remotely with `ssh -L 8091:127.0.0.1:8091 operator@soc-gpu.example.test` and open `http://127.0.0.1:8091`.

## Report Quality

Reports include event counts, privacy notes, keyword/rule signals, basic statistical comparison, and limitations. The first model layer is an unsupervised frequency profile that reports drift and unseen entity rates. True precision/recall/F1/ROC-AUC require labeled data. Without labels, the system reports anomaly score distributions and review candidates instead of pretending accuracy is known.

Large-run analysis bounds each in-memory distinct-value counter with `analysis.max_unique_values` (default `100000`). When pruning occurs, analysis and profile artifacts set `aggregation_limited=true`; top values and rare-host results are then approximate. This bounds local memory but does not replace staged execution, disk capacity planning, or production throughput testing for 400M events.

Rule evidence is bounded by `runtime.max_rule_findings` (default `100000`). Finding counts and severity totals remain exact; when evidence is capped, the rule artifact sets `findings_truncated=true`.

## Agents And Rules

Agent roles are configuration boundaries in `configs/agents.toml`. They describe responsibilities, model choice, command permissions, and whether human approval is expected before high-impact work. Detection rules live in `configs/detection_rules.json` and can be edited without changing Python code.
