from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

from .agents import agent_plan, review_workflow
from . import __version__
from .analyze import analyze_files
from .benchmark import benchmark_analysis
from .bridge import BridgeConfig, bridge_plan, bridge_status
from .chunking import build_time_windows, choose_mode
from .config import load_config, load_env_file
from .data_audit import build_data_audit
from .datasets import dataset_download, dataset_list
from .doctor import run_doctor
from .export_profiles import load_export_profiles, profile_plan
from .hec import hec_generate_synthetic, hec_send
from .gpu import gpu_review
from .integrity import build_manifest, verify_manifest
from .local_ingest import ingest_local
from .modeling import evaluate_labeled, evaluate_profile, train_profile
from .monitor import serve
from .ops_audit import run_ops_audit
from .qa import qa_ai_review, qa_report, qa_run
from .report import write_report
from .report_reference import ingest_report_reference
from .rules import load_rules, run_rules
from .scale import scale_plan
from .scale_report import write_scale_report
from .splunk import export_splunk_chunked, checkpoint_status, splunk_preflight
from .splunk_pipeline import run_splunk_pipeline
from .splunk_stage_tests import run_splunk_stage_tests
from .stage_tests import run_stage_tests
from .site import build_site
from .soup_integration import build_report_dataset, collect_report_paths, soup_training_plan, write_soup_report_config
from .synthetic import generate_synthetic
from .validation import parse_partitions_json


def main(argv: list[str] | None = None) -> int:
    try:
        return _main_impl(argv)
    except (ValueError, RuntimeError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


def _main_impl(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc-ai")
    parser.add_argument("--config", default="configs/default.toml")
    parser.add_argument("--env-file", default=".env")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("version", help="show version")

    p_bridge_plan = sub.add_parser("bridge-plan", help="show sender -> test Splunk -> GPU analysis flow")
    p_bridge_plan.add_argument("--sender-label", default="workstation")
    p_bridge_plan.add_argument("--test-server", default="soc-storage.example.test")
    p_bridge_plan.add_argument("--gpu-server", default="soc-gpu.example.test")
    p_bridge_plan.add_argument("--index", default="main")
    p_bridge_plan.add_argument("--sourcetype", default="soc_ai_json")
    p_bridge_plan.add_argument("--source-prefix", default="soc-ai-ingress")

    p_bridge_status = sub.add_parser("bridge-status", help="check sender/test-server/GPU bridge readiness")
    p_bridge_status.add_argument("--sender-label", default="workstation")
    p_bridge_status.add_argument("--test-server", default="soc-storage.example.test")
    p_bridge_status.add_argument("--gpu-server", default="soc-gpu.example.test")
    p_bridge_status.add_argument("--index", default="main")
    p_bridge_status.add_argument("--sourcetype", default="soc_ai_json")
    p_bridge_status.add_argument("--source-prefix", default="soc-ai-ingress")

    p_plan = sub.add_parser("plan", help="show automatic mode and chunk plan")
    p_plan.add_argument("--start", required=True)
    p_plan.add_argument("--end", required=True)
    p_plan.add_argument("--estimated-events", type=int)

    p_local = sub.add_parser("ingest-local", help="redact and normalize local JSONL/CSV logs")
    p_local.add_argument("--input", required=True)
    p_local.add_argument("--output", required=True)

    p_splunk = sub.add_parser("splunk-ingest", help="export Splunk events with chunk checkpoints")
    p_splunk.add_argument("--spl", required=True)
    p_splunk.add_argument("--start", required=True)
    p_splunk.add_argument("--end", required=True)
    p_splunk.add_argument("--dry-run", action="store_true")
    p_splunk.add_argument("--output-dir")
    p_splunk.add_argument("--checkpoint")
    p_splunk.add_argument("--estimated-events", type=int)
    p_splunk.add_argument("--allow-lossy-spl", action="store_true")
    p_splunk.add_argument(
        "--partitions-json",
        help='JSON list of partition filters, for example [{"index":"main"},{"index":"security"}]',
    )

    p_preflight = sub.add_parser("splunk-preflight", help="count/estimate Splunk events and plan adaptive chunks")
    p_preflight.add_argument("--spl", required=True)
    p_preflight.add_argument("--start", required=True)
    p_preflight.add_argument("--end", required=True)
    p_preflight.add_argument("--estimate-only", type=int)
    p_preflight.add_argument("--skip-remote-count", action="store_true")
    p_preflight.add_argument("--partitions-json")

    p_status = sub.add_parser("status", help="show checkpoint status")
    p_status.add_argument("--checkpoint", default="data/splunk_checkpoints.json")

    p_analyze = sub.add_parser("analyze", help="analyze JSONL files")
    p_analyze.add_argument("paths", nargs="+")
    p_analyze.add_argument("--output", default="reports/analysis.json")

    p_report = sub.add_parser("report", help="create Markdown/HTML report from analysis JSON")
    p_report.add_argument("--metrics", required=True)
    p_report.add_argument("--output-dir", default="reports")
    p_report.add_argument("--metadata", help="JSON with report_metadata and source_context")
    p_report.add_argument("--profile", help="Matching frequency profile to enrich source types")
    p_report.add_argument("--ai", action="store_true", help="Require validated local-model evidence planning")
    p_report.add_argument("--endpoint", default="http://127.0.0.1:11434/api/generate")
    p_report.add_argument("--model", default="qwen2.5-coder:3b")
    p_report.add_argument("--checkpoint", help="Complete checkpoint for exact temporal enrichment")
    p_report.add_argument("--manifest", help="Matching manifest for temporal enrichment")

    p_bench = sub.add_parser("benchmark", help="benchmark analysis throughput")
    p_bench.add_argument("paths", nargs="+")
    p_bench.add_argument("--output", default="reports/benchmark.json")

    p_gpu = sub.add_parser("gpu-review", help="review redacted aggregate metrics with local GPU Ollama")
    p_gpu.add_argument("--metrics", required=True)
    p_gpu.add_argument("--output", default="reports/gpu_review.json")
    p_gpu.add_argument("--model", default="qwen2.5-coder:3b")
    p_gpu.add_argument("--endpoint")

    p_monitor = sub.add_parser("monitor", help="serve the operations monitoring dashboard")
    p_monitor.add_argument("--host", default="127.0.0.1")
    p_monitor.add_argument("--port", type=int, default=8091)
    p_monitor.add_argument("--splunk-host", default="soc-storage.example.test")
    p_monitor.add_argument("--metrics")
    p_monitor.add_argument("--review")
    p_monitor.add_argument("--reports-dir", default="reports")
    p_monitor.add_argument("--upload-dir", default="data/uploads")

    p_synth = sub.add_parser("generate-synthetic", help="generate synthetic JSONL logs")
    p_synth.add_argument("--rows", type=int, required=True)
    p_synth.add_argument("--output", required=True)
    p_synth.add_argument("--seed", type=int, default=42)

    p_train = sub.add_parser("train", help="train an unsupervised frequency profile")
    p_train.add_argument("paths", nargs="+")
    p_train.add_argument("--output", default="reports/model_profile.json")

    p_eval = sub.add_parser("evaluate", help="evaluate drift/anomaly indicators against a profile")
    p_eval.add_argument("--profile", required=True)
    p_eval.add_argument("paths", nargs="+")
    p_eval.add_argument("--output", default="reports/evaluation.json")

    p_eval_labeled = sub.add_parser("evaluate-labeled", help="compute precision/recall/F1 for labeled JSONL scores")
    p_eval_labeled.add_argument("paths", nargs="+")
    p_eval_labeled.add_argument("--label-field", default="label")
    p_eval_labeled.add_argument("--score-field", default="score")
    p_eval_labeled.add_argument("--threshold", type=float, default=0.5)
    p_eval_labeled.add_argument("--positive-label", default="1")
    p_eval_labeled.add_argument("--output", default="reports/labeled_evaluation.json")

    p_manifest = sub.add_parser("manifest", help="build integrity manifest for JSONL chunks")
    p_manifest.add_argument("paths", nargs="+")
    p_manifest.add_argument("--output", default="reports/chunk_manifest.json")

    p_verify = sub.add_parser("verify-manifest", help="verify chunk hashes and row counts")
    p_verify.add_argument("--manifest", required=True)

    p_data_audit = sub.add_parser("data-audit", help="write strict data usage audit before report release")
    p_data_audit.add_argument("--metrics", required=True)
    p_data_audit.add_argument("--manifest", required=True)
    p_data_audit.add_argument("--output", default="reports/data-audit.json")

    p_doctor = sub.add_parser("doctor", help="check local readiness for SOC runs")
    p_doctor.add_argument("--min-free-gb", type=int, default=20)

    p_pipe_local = sub.add_parser("pipeline-local", help="run local ingest/analyze/train/report/benchmark pipeline")
    p_pipe_local.add_argument("--input", required=True)
    p_pipe_local.add_argument("--run-dir")

    p_pipe_splunk = sub.add_parser("pipeline-splunk", help="run Splunk preflight/ingest/analyze/rules/report pipeline")
    p_pipe_splunk.add_argument("--spl", required=True)
    p_pipe_splunk.add_argument("--start", required=True)
    p_pipe_splunk.add_argument("--end", required=True)
    p_pipe_splunk.add_argument("--partitions-json")
    p_pipe_splunk.add_argument("--estimate-only", type=int)
    p_pipe_splunk.add_argument("--run-dir")
    p_pipe_splunk.add_argument("--dry-run", action="store_true")

    p_qa_report = sub.add_parser("qa-report", help="quality gate one report")
    p_qa_report.add_argument("--markdown", required=True)
    p_qa_report.add_argument("--metrics")
    p_qa_report.add_argument("--no-strict", action="store_true")

    p_qa_run = sub.add_parser("qa-run", help="quality gate a pipeline run directory")
    p_qa_run.add_argument("--run-dir", required=True)
    p_qa_run.add_argument("--no-strict", action="store_true")

    p_qa_ai = sub.add_parser("qa-ai-review", help="quality gate an Ollama/GPU AI review JSON")
    p_qa_ai.add_argument("--review", required=True)
    p_qa_ai.add_argument("--no-strict", action="store_true")

    sub.add_parser("datasets", help="list public dataset catalog")

    p_download = sub.add_parser("dataset-download", help="download a public dataset")
    p_download.add_argument("--name", required=True)
    p_download.add_argument("--output-dir", default="data/downloads")
    p_download.add_argument("--max-bytes", type=int)

    p_hec = sub.add_parser("hec-send", help="send JSONL/JSONL.GZ events to Splunk HEC in checkpointed batches")
    p_hec.add_argument("--input", required=True)
    p_hec.add_argument("--index", required=True)
    p_hec.add_argument("--sourcetype", default="_json")
    p_hec.add_argument("--source", default="soc-ai")
    p_hec.add_argument("--batch-size", type=int, default=1000)
    p_hec.add_argument("--checkpoint")
    p_hec.add_argument("--dry-run", action="store_true")

    p_hec_gen = sub.add_parser("hec-generate-synthetic", help="stream varied synthetic events directly to Splunk HEC")
    p_hec_gen.add_argument("--rows", type=int, required=True)
    p_hec_gen.add_argument("--index", required=True)
    p_hec_gen.add_argument("--sourcetype", default="soc_ai_json")
    p_hec_gen.add_argument("--source", default="soc-ai-generated")
    p_hec_gen.add_argument("--batch-size", type=int, default=5000)
    p_hec_gen.add_argument("--checkpoint")
    p_hec_gen.add_argument("--seed", type=int, default=42)
    p_hec_gen.add_argument("--span-days", type=float)
    p_hec_gen.add_argument("--dry-run", action="store_true")

    p_stage = sub.add_parser("stage-tests", help="run progressive synthetic scale tests")
    p_stage.add_argument("--counts", default="1000,10000,100000")
    p_stage.add_argument("--output-dir", default="reports/stage-tests")
    p_stage.add_argument("--keep-raw", action="store_true")

    p_splunk_stage = sub.add_parser("splunk-stage-tests", help="run progressive end-to-end Splunk HEC/SPL/QA tests")
    p_splunk_stage.add_argument("--counts", default="10000,100000")
    p_splunk_stage.add_argument("--start", required=True)
    p_splunk_stage.add_argument("--end", required=True)
    p_splunk_stage.add_argument("--output-dir", default="reports/splunk-stage-tests")
    p_splunk_stage.add_argument("--index", default="main")
    p_splunk_stage.add_argument("--sourcetype", default="soc_ai_json")
    p_splunk_stage.add_argument("--source-prefix", default="soc-ai-stage")
    p_splunk_stage.add_argument("--batch-size", type=int, default=5000)
    p_splunk_stage.add_argument("--wait-seconds", type=int, default=20)
    p_splunk_stage.add_argument("--keep-raw", action="store_true")
    p_splunk_stage.add_argument("--local-only", action="store_true")

    p_site = sub.add_parser("site-build", help="build lightweight static status site")
    p_site.add_argument("--reports-dir", default="reports")
    p_site.add_argument("--output-dir", default="site")

    p_scale_plan = sub.add_parser("scale-plan", help="estimate disk needs for staged event-count tests")
    p_scale_plan.add_argument("--counts", default="10000000,20000000,50000000,100000000,100000000")
    p_scale_plan.add_argument("--avg-event-bytes", type=int, default=700)
    p_scale_plan.add_argument("--copies-per-run", type=int, default=2)
    p_scale_plan.add_argument("--safety-factor", type=float, default=1.4)
    p_scale_plan.add_argument("--compression-ratio", type=float, default=0.25)
    p_scale_plan.add_argument("--output-dir", default=".")

    p_scale_report = sub.add_parser("scale-report", help="write a Markdown report for large scale testing")
    p_scale_report.add_argument("--scale-plan", required=True)
    p_scale_report.add_argument("--output", default="reports/scale-report.md")
    p_scale_report.add_argument("--title", default="SOC AI 400M Scale Test Report")
    p_scale_report.add_argument("--audit")
    p_scale_report.add_argument("--stage-summary")

    p_agents = sub.add_parser("agents", help="show configured SOC agents and command boundaries")
    p_agents.add_argument("--agents-file", default="configs/agents.toml")
    p_review = sub.add_parser("agent-review", help="run report QA, GPU review and independent AI QA")
    p_review.add_argument("--run-dir", required=True)
    p_review.add_argument("--agents-file", default="configs/agents.toml")
    p_review.add_argument("--endpoint")

    p_ops = sub.add_parser("ops-audit", help="show safe operational audit of server, Splunk, GPU, model, and latest reports")
    p_ops.add_argument("--splunk-host", default="soc-storage.example.test")
    p_ops.add_argument("--reports-dir", default="reports")

    p_rules_list = sub.add_parser("rules-list", help="list configured detection rules")
    p_rules_list.add_argument("--rules", default="configs/detection_rules.json")

    p_rules_run = sub.add_parser("rules-run", help="run detection rules on JSONL files")
    p_rules_run.add_argument("paths", nargs="+")
    p_rules_run.add_argument("--rules", default="configs/detection_rules.json")
    p_rules_run.add_argument("--output", default="reports/rule_findings.json")

    p_profile_plan = sub.add_parser("splunk-profile-plan", help="plan a saved Splunk export profile")
    p_profile_plan.add_argument("--profile", required=True)
    p_profile_plan.add_argument("--profiles-file", default="configs/splunk_exports.toml")
    p_profile_plan.add_argument("--estimate-only", type=int)
    p_profile_plan.add_argument("--remote-count", action="store_true")

    p_profiles = sub.add_parser("splunk-profiles", help="list saved Splunk export profiles")
    p_profiles.add_argument("--profiles-file", default="configs/splunk_exports.toml")

    p_report_ds = sub.add_parser("report-training-dataset", help="build an Alpaca JSONL dataset from QA-approved SOC reports")
    p_report_ds.add_argument("--report", action="append", default=[])
    p_report_ds.add_argument("--run-dir", action="append", default=[])
    p_report_ds.add_argument("--reports-glob", action="append", default=[])
    p_report_ds.add_argument("--output", default="data/report_training.jsonl")
    p_report_ds.add_argument("--max-input-chars", type=int, default=120000)
    p_report_ds.add_argument("--max-output-chars", type=int, default=120000)

    p_report_ref = sub.add_parser("report-reference-ingest", help="ingest an official PDF report as style/reference training material")
    p_report_ref.add_argument("--pdf", required=True)
    p_report_ref.add_argument("--output-dir", default="data/report_references")
    p_report_ref.add_argument("--dataset", default=None)
    p_report_ref.add_argument("--min-text-quality", type=float, default=0.85)
    p_report_ref.add_argument("--max-output-chars", type=int, default=12000)
    p_report_ref.add_argument("--max-rows", type=int, default=24)

    p_soup_cfg = sub.add_parser("soup-report-config", help="write a Soup QLoRA config for SOC report generation")
    p_soup_cfg.add_argument("--dataset", default="data/report_training.jsonl")
    p_soup_cfg.add_argument("--output", default="configs/soup-report-model.yaml")
    p_soup_cfg.add_argument("--base-model", default="Qwen/Qwen2.5-7B-Instruct")
    p_soup_cfg.add_argument("--model-output-dir", default="models/soc-report-qwen25")
    p_soup_cfg.add_argument("--epochs", type=int, default=2)
    p_soup_cfg.add_argument("--learning-rate", default="1e-5")
    p_soup_cfg.add_argument("--max-length", type=int, default=4096)
    p_soup_cfg.add_argument("--lora-rank", type=int, default=64)
    p_soup_cfg.add_argument("--lora-alpha", type=int, default=16)
    p_soup_cfg.add_argument("--no-stream-layers", action="store_true")

    p_soup_plan = sub.add_parser("soup-training-plan", help="write and optionally run Soup validation/dry-run commands")
    p_soup_plan.add_argument("--dataset", default="data/report_training.jsonl")
    p_soup_plan.add_argument("--soup-config", default="configs/soup-report-model.yaml")
    p_soup_plan.add_argument("--output", default="reports/soup_training_plan.json")
    p_soup_plan.add_argument("--soup-binary", default="soup")
    p_soup_plan.add_argument("--deploy-name", default="soc-report-qwen25")
    p_soup_plan.add_argument("--model-output-dir", default="models/soc-report-qwen25")
    p_soup_plan.add_argument("--execute", action="store_true")

    args = parser.parse_args(argv)
    load_env_file(args.env_file)
    config = load_config(args.config)

    if args.cmd == "plan":
        windows = build_time_windows(args.start, args.end, config.runtime.chunk_seconds)
        result = {
            "mode": choose_mode(args.estimated_events, config.runtime.mode, config.runtime.small_run_max_events),
            "chunk_seconds": config.runtime.chunk_seconds,
            "planned_windows": len(windows),
            "first_window": {
                "earliest": windows[0].splunk_earliest(),
                "latest": windows[0].splunk_latest(),
            }
            if windows
            else None,
        }
        return _print(result)
    if args.cmd == "version":
        return _print({"version": __version__})
    if args.cmd in {"bridge-plan", "bridge-status"}:
        bridge_config = BridgeConfig(args.sender_label, args.test_server, args.gpu_server, args.index, args.sourcetype, args.source_prefix)
        payload = bridge_plan(bridge_config) if args.cmd == "bridge-plan" else bridge_status(bridge_config)
        _print(payload)
        return 0 if args.cmd == "bridge-plan" or payload.get("ready") else 1
    if args.cmd == "ingest-local":
        return _print(ingest_local(config, args.input, args.output))
    if args.cmd == "splunk-ingest":
        partitions = parse_partitions_json(args.partitions_json)
        return _print(
            export_splunk_chunked(
                config,
                args.spl,
                args.start,
                args.end,
                args.output_dir,
                args.checkpoint,
                partitions=partitions,
                dry_run=args.dry_run,
                estimated_events=args.estimated_events,
                allow_lossy_commands=args.allow_lossy_spl,
            )
        )
    if args.cmd == "splunk-preflight":
        partitions = parse_partitions_json(args.partitions_json)
        return _print(splunk_preflight(config, args.spl, args.start, args.end, args.estimate_only, partitions, args.skip_remote_count))
    if args.cmd == "status":
        return _print(checkpoint_status(args.checkpoint))
    if args.cmd == "analyze":
        paths = _expand(args.paths)
        metrics = analyze_files(
            paths,
            top_n=config.analysis.top_n,
            rare_threshold=config.analysis.rare_threshold,
            max_unique_values=config.analysis.max_unique_values,
        )
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return _print({"output": str(out), **metrics})
    if args.cmd == "report":
        metrics = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
        metrics.pop("report_plan", None)
        if args.metadata:
            metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
            if set(metadata) - {"report_metadata", "source_context"}:
                raise ValueError("Report metadata cannot override evidence metrics")
            metrics.update(metadata)
        if args.profile:
            profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
            if profile.get("total_events") != metrics.get("total_events"):
                raise ValueError("Profile and report event counts differ")
            metrics["top_sourcetypes"] = sorted(profile.get("fields", {}).get("sourcetype", {}).items(), key=lambda x: -x[1])
            metrics["top_sourcetypes"] = [list(row) for row in metrics["top_sourcetypes"]]
        if bool(args.checkpoint) != bool(args.manifest):
            raise ValueError("Timeline requires both checkpoint and manifest")
        if args.checkpoint:
            from .report_timeline import build_timeline
            metrics["timeline"] = build_timeline(args.checkpoint, args.manifest, metrics["total_events"])
        if args.ai:
            from .redaction import redact_event
            from .report_planner import plan_report
            metrics = redact_event(metrics, mask_ips=True)
            metrics["report_plan"] = plan_report(metrics, args.endpoint, args.model)
        return _print(write_report(metrics, args.output_dir))
    if args.cmd == "benchmark":
        return _print(benchmark_analysis(_expand(args.paths), args.output))
    if args.cmd == "gpu-review":
        return _print(gpu_review(args.metrics, args.output, args.model, args.endpoint))
    if args.cmd == "monitor":
        serve(args.host, args.port, splunk_host=args.splunk_host, metrics_path=args.metrics, review_path=args.review, reports_dir=args.reports_dir, upload_dir=args.upload_dir)
        return 0
    if args.cmd == "generate-synthetic":
        return _print(generate_synthetic(args.output, args.rows, args.seed))
    if args.cmd == "train":
        return _print(train_profile(_expand(args.paths), args.output))
    if args.cmd == "evaluate":
        return _print(evaluate_profile(args.profile, _expand(args.paths), args.output))
    if args.cmd == "evaluate-labeled":
        return _print(evaluate_labeled(_expand(args.paths), args.label_field, args.score_field, args.threshold, args.positive_label, args.output))
    if args.cmd == "manifest":
        return _print(build_manifest(_expand(args.paths), args.output))
    if args.cmd == "verify-manifest":
        return _print(verify_manifest(args.manifest))
    if args.cmd == "data-audit":
        metrics = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        result = build_data_audit(metrics, manifest, args.output)
        _print(result)
        return 0 if result.get("status") == "pass" else 1
    if args.cmd == "doctor":
        return _print(run_doctor(config, args.min_free_gb))
    if args.cmd == "pipeline-local":
        from .pipeline import run_local_pipeline

        return _print(run_local_pipeline(config, args.input, args.run_dir))
    if args.cmd == "pipeline-splunk":
        return _print(run_splunk_pipeline(config, args.spl, args.start, args.end, args.partitions_json, args.run_dir, args.estimate_only, args.dry_run))
    if args.cmd == "qa-report":
        return _print_gate(qa_report(args.markdown, args.metrics, strict=not args.no_strict))
    if args.cmd == "qa-run":
        return _print_gate(qa_run(args.run_dir, strict=not args.no_strict))
    if args.cmd == "qa-ai-review":
        return _print_gate(qa_ai_review(args.review, strict=not args.no_strict))
    if args.cmd == "agent-review":
        return _print_gate(review_workflow(args.run_dir, args.agents_file, args.endpoint))
    if args.cmd == "datasets":
        return _print(dataset_list())
    if args.cmd == "dataset-download":
        return _print(dataset_download(args.name, args.output_dir, args.max_bytes))
    if args.cmd == "hec-send":
        return _print(hec_send(config, args.input, args.index, args.sourcetype, args.source, args.batch_size, args.checkpoint, args.dry_run))
    if args.cmd == "hec-generate-synthetic":
        return _print(
            hec_generate_synthetic(
                config,
                rows=args.rows,
                index=args.index,
                sourcetype=args.sourcetype,
                source=args.source,
                batch_size=args.batch_size,
                checkpoint_path=args.checkpoint,
                seed=args.seed,
                span_seconds=int(args.span_days * 86400) if args.span_days else None,
                dry_run=args.dry_run,
            )
        )
    if args.cmd == "stage-tests":
        counts = [int(item.strip()) for item in args.counts.split(",") if item.strip()]
        return _print(run_stage_tests(config, counts, args.output_dir, keep_raw=args.keep_raw))
    if args.cmd == "splunk-stage-tests":
        counts = [int(item.strip()) for item in args.counts.split(",") if item.strip()]
        return _print(
            run_splunk_stage_tests(
                config,
                counts,
                start=args.start,
                end=args.end,
                output_dir=args.output_dir,
                index=args.index,
                sourcetype=args.sourcetype,
                source_prefix=args.source_prefix,
                batch_size=args.batch_size,
                wait_seconds=args.wait_seconds,
                keep_raw=args.keep_raw,
                local_only=args.local_only,
            )
        )
    if args.cmd == "site-build":
        return _print(build_site(args.reports_dir, args.output_dir))
    if args.cmd == "scale-plan":
        counts = [int(item.strip()) for item in args.counts.split(",") if item.strip()]
        return _print(scale_plan(counts, args.avg_event_bytes, args.copies_per_run, args.safety_factor, args.compression_ratio, args.output_dir))
    if args.cmd == "scale-report":
        plan = json.loads(Path(args.scale_plan).read_text(encoding="utf-8"))
        audit = json.loads(Path(args.audit).read_text(encoding="utf-8")) if args.audit else None
        stage_summary = json.loads(Path(args.stage_summary).read_text(encoding="utf-8")) if args.stage_summary else None
        return _print(write_scale_report(args.output, args.title, plan, audit, stage_summary))
    if args.cmd == "agents":
        return _print(agent_plan(args.agents_file))
    if args.cmd == "ops-audit":
        return _print(run_ops_audit(config, args.splunk_host, args.reports_dir))
    if args.cmd == "rules-list":
        return _print({"rules": load_rules(args.rules)})
    if args.cmd == "rules-run":
        return _print(run_rules(_expand(args.paths), args.rules, args.output, config.runtime.max_rule_findings))
    if args.cmd == "splunk-profile-plan":
        return _print(profile_plan(config, args.profile, args.profiles_file, args.estimate_only, skip_remote_count=not args.remote_count))
    if args.cmd == "splunk-profiles":
        return _print({"profiles": load_export_profiles(args.profiles_file)})
    if args.cmd == "report-training-dataset":
        paths = list(args.report)
        paths.extend(collect_report_paths(args.run_dir, args.reports_glob))
        return _print(
            build_report_dataset(
                paths,
                args.output,
                max_input_chars=args.max_input_chars,
                max_output_chars=args.max_output_chars,
            )
        )
    if args.cmd == "report-reference-ingest":
        return _print(ingest_report_reference(args.pdf, args.output_dir, args.dataset, args.min_text_quality, args.max_output_chars, args.max_rows))
    if args.cmd == "soup-report-config":
        return _print(
            write_soup_report_config(
                args.dataset,
                args.output,
                base_model=args.base_model,
                model_output_dir=args.model_output_dir,
                epochs=args.epochs,
                learning_rate=args.learning_rate,
                max_length=args.max_length,
                lora_rank=args.lora_rank,
                lora_alpha=args.lora_alpha,
                stream_layers=not args.no_stream_layers,
            )
        )
    if args.cmd == "soup-training-plan":
        return _print(
            soup_training_plan(
                args.dataset,
                args.soup_config,
                args.output,
                args.soup_binary,
                args.deploy_name,
                args.model_output_dir,
                args.execute,
            )
        )
    raise AssertionError(args.cmd)


def _expand(patterns: list[str]) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        matched = glob.glob(pattern)
        paths.extend(matched or [pattern])
    return paths


def _print_gate(payload: dict) -> int:
    _print(payload)
    return 0 if payload.get("status") == "pass" else 1


def _print(payload: dict) -> int:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
