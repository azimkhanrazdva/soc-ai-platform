from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import re
import shutil
import subprocess

from .qa import SECRET_REGEX


SENSITIVE_JSON_FIELD_REGEX = re.compile(
    r'(?i)("?(?:password|passwd|token|secret|authorization|session|cookie|api_key|apikey)"?\s*:\s*)"[^"]*"'
)


DEFAULT_REPORT_INSTRUCTION = (
    "Generate a strict SOC analyst report from redacted aggregate metrics. "
    "Do not invent incidents, breaches, attack names, hostnames, users, IPs, "
    "or conclusions that are not supported by the input metrics. Include an "
    "executive summary, top hosts, rule findings, integrity status, model "
    "comparison, limitations, and concrete next steps."
)


@dataclass(frozen=True, slots=True)
class ReportExample:
    markdown_path: Path
    metrics_path: Path | None


def build_report_dataset(
    report_paths: list[str | Path],
    output_path: str | Path,
    instruction: str = DEFAULT_REPORT_INSTRUCTION,
    max_input_chars: int = 120_000,
    max_output_chars: int = 120_000,
) -> dict:
    examples = [_resolve_example(Path(path)) for path in report_paths]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows_written = 0
    skipped: list[dict[str, str]] = []
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for example in examples:
            try:
                row = _example_to_alpaca_row(
                    example,
                    instruction,
                    max_input_chars,
                    max_output_chars,
                )
            except ValueError as exc:
                skipped.append({"report": str(example.markdown_path), "reason": str(exc)})
                continue
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            rows_written += 1
    return {
        "output": str(output),
        "format": "alpaca",
        "rows": rows_written,
        "skipped": skipped,
        "instruction": instruction,
        "max_input_chars": max_input_chars,
        "max_output_chars": max_output_chars,
    }


def collect_report_paths(run_dirs: list[str] | None, report_globs: list[str] | None) -> list[str]:
    paths: list[Path] = []
    for run_dir in run_dirs or []:
        root = Path(run_dir)
        paths.extend(sorted((root / "reports").glob("report-*.md")))
        paths.extend(sorted(root.glob("SOC-AI-*-final-report.md")))
    for pattern in report_globs or []:
        paths.extend(sorted(Path().glob(pattern)))
    deduped = []
    seen = set()
    for path in paths:
        key = str(path)
        if key not in seen and path.exists():
            seen.add(key)
            deduped.append(key)
    return deduped


def write_soup_report_config(
    dataset_path: str | Path,
    output_path: str | Path,
    base_model: str = "Qwen/Qwen2.5-7B-Instruct",
    model_output_dir: str = "models/soc-report-qwen25",
    epochs: int = 2,
    learning_rate: str = "1e-5",
    max_length: int = 4096,
    lora_rank: int = 64,
    lora_alpha: int = 16,
    stream_layers: bool = True,
    batch_size: str = "auto",
) -> dict:
    if epochs < 1:
        raise ValueError("epochs must be positive")
    if max_length < 512:
        raise ValueError("max_length must be at least 512")
    if lora_rank < 1:
        raise ValueError("lora_rank must be positive")
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    yaml = _render_soup_yaml(
        dataset_path=Path(dataset_path),
        base_model=base_model,
        model_output_dir=model_output_dir,
        epochs=epochs,
        learning_rate=learning_rate,
        max_length=max_length,
        lora_rank=lora_rank,
        lora_alpha=lora_alpha,
        stream_layers=stream_layers,
        batch_size="1" if stream_layers and batch_size == "auto" else batch_size,
    )
    output.write_text(yaml, encoding="utf-8", newline="\n")
    return {
        "output": str(output),
        "dataset": str(dataset_path),
        "base_model": base_model,
        "model_output_dir": model_output_dir,
        "stream_layers": stream_layers,
        "format": "soup-yaml",
    }


def soup_training_plan(
    dataset_path: str | Path,
    config_path: str | Path,
    output_path: str | Path,
    soup_binary: str = "soup",
    deploy_name: str = "soc-report-qwen25",
    model_output_dir: str = "models/soc-report-qwen25",
    execute: bool = False,
) -> dict:
    dataset = str(dataset_path)
    config = str(config_path)
    commands = [
        ["python", "-m", "pip", "install", "soup-cli[train,data-pro]"],
        [soup_binary, "data", "validate", dataset, "--format", "alpaca"],
        [soup_binary, "data", "pii", "--input", dataset, "-o", "reports/soup-report-pii.jsonl"],
        [soup_binary, "train", "--config", config, "--dry-run"],
        [soup_binary, "train", "--config", config],
        [soup_binary, "export", "--model", model_output_dir, "--format", "gguf"],
        [soup_binary, "export", "--model", model_output_dir, "--deploy", "ollama", "--deploy-name", deploy_name],
    ]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    plan = {
        "soup_available": shutil.which(soup_binary) is not None,
        "soup_binary": soup_binary,
        "dataset": dataset,
        "config": config,
        "deploy_name": deploy_name,
        "model_output_dir": model_output_dir,
        "commands": commands,
        "execute": execute,
        "executed": [],
        "note": "Only validation and dry-run are executed automatically; full training requires running the generated train command.",
    }
    if execute:
        for command in commands[1:4]:
            completed = subprocess.run(command, check=False, text=True, capture_output=True)
            plan["executed"].append(
                {
                    "command": command,
                    "returncode": completed.returncode,
                    "stdout_tail": completed.stdout[-2000:],
                    "stderr_tail": completed.stderr[-2000:],
                }
            )
            if completed.returncode != 0:
                break
    output.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"output": str(output), **plan}


def _resolve_example(markdown_path: Path) -> ReportExample:
    if not markdown_path.exists():
        raise ValueError(f"report not found: {markdown_path}")
    return ReportExample(markdown_path=markdown_path, metrics_path=_matching_metrics_path(markdown_path))


def _matching_metrics_path(markdown_path: Path) -> Path | None:
    match = re.fullmatch(r"report-(.+)\.md", markdown_path.name)
    if match:
        candidate = markdown_path.with_name(f"metrics-{match.group(1)}.json")
        if candidate.exists():
            return candidate
    return None


def _example_to_alpaca_row(
    example: ReportExample,
    instruction: str,
    max_input_chars: int,
    max_output_chars: int,
) -> dict[str, str]:
    report = _redact_text(example.markdown_path.read_text(encoding="utf-8"))
    if not report.strip():
        raise ValueError("empty report")
    if len(report) > max_output_chars:
        raise ValueError("report exceeds training window; provide a reviewed shorter example")
    metrics_payload = {}
    if example.metrics_path and example.metrics_path.exists():
        metrics_payload = json.loads(example.metrics_path.read_text(encoding="utf-8"))
    model_input = _redact_text(json.dumps(metrics_payload, ensure_ascii=False, indent=2, sort_keys=True))
    if not model_input.strip() or model_input == "{}":
        raise ValueError("exact matching metrics are required for grounded report training")
    if metrics_payload.get("integrity", {}).get("ok") is not True:
        raise ValueError("training metrics must pass integrity checks")
    if len(model_input) > max_input_chars:
        raise ValueError("metrics exceed training window; refusing to truncate evidence")
    return {"instruction": instruction, "input": model_input, "output": report}


def _redact_text(value: str) -> str:
    value = SECRET_REGEX.sub("<redacted-secret>", value)
    return SENSITIVE_JSON_FIELD_REGEX.sub(r'\1"<redacted-secret>"', value)


def _render_soup_yaml(
    dataset_path: Path,
    base_model: str,
    model_output_dir: str,
    epochs: int,
    learning_rate: str,
    max_length: int,
    lora_rank: int,
    lora_alpha: int,
    stream_layers: bool,
    batch_size: str,
) -> str:
    stream_line = "  stream_layers: true\n" if stream_layers else ""
    return (
        "# Generated by soc-ai soup-report-config.\n"
        "# Train only on redacted, QA-approved SOC report examples.\n"
        f"base: {_yaml_scalar(base_model)}\n"
        "task: sft\n\n"
        "data:\n"
        f"  train: {_yaml_scalar(_portable_path(dataset_path))}\n"
        "  format: alpaca\n"
        "  val_split: 0.1\n"
        f"  max_length: {max_length}\n\n"
        "training:\n"
        f"  epochs: {epochs}\n"
        f"  lr: {learning_rate}\n"
        f"  batch_size: {_yaml_batch_size(batch_size)}\n"
        f"{stream_line}"
        "  lora:\n"
        f"    r: {lora_rank}\n"
        f"    alpha: {lora_alpha}\n"
        "    target_modules: auto\n"
        "  quantization: 4bit\n"
        "  gradient_checkpointing: true\n\n"
        f"output: {_yaml_scalar(model_output_dir)}\n"
    )


def _yaml_scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _yaml_batch_size(value: str) -> str:
    return value if value.isdigit() else _yaml_scalar(value)


def _portable_path(path: Path) -> str:
    return str(path).replace("\\", "/")
