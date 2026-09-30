from __future__ import annotations

import json
from pathlib import Path

from soc_ai.soup_integration import (
    build_report_dataset,
    collect_report_paths,
    soup_training_plan,
    write_soup_report_config,
)


def test_build_report_dataset_pairs_metrics_and_redacts_secret(tmp_path: Path):
    reports = tmp_path / "run" / "reports"
    reports.mkdir(parents=True)
    (reports / "metrics-20260908-010101.json").write_text(
        json.dumps({"total_events": 5, "integrity": {"ok": True}, "token": "abc123SECRET"}),
        encoding="utf-8",
    )
    (reports / "report-20260908-010101.md").write_text(
        "# SOC\n\npassword=abc123SECRET\n\n## Integrity\nok",
        encoding="utf-8",
    )

    result = build_report_dataset([reports / "report-20260908-010101.md"], tmp_path / "train.jsonl")

    assert result["rows"] == 1
    row = json.loads((tmp_path / "train.jsonl").read_text(encoding="utf-8"))
    assert row["instruction"].startswith("Generate a strict SOC analyst report")
    assert "total_events" in row["input"]
    assert "abc123SECRET" not in row["input"]
    assert "abc123SECRET" not in row["output"]


def test_collect_report_paths_from_run_dir(tmp_path: Path):
    reports = tmp_path / "run" / "reports"
    reports.mkdir(parents=True)
    wanted = reports / "report-20260908-010101.md"
    wanted.write_text("# ok", encoding="utf-8")

    assert collect_report_paths([str(tmp_path / "run")], None) == [str(wanted)]


def test_write_soup_report_config_defaults_to_qwen_qlora_streaming(tmp_path: Path):
    result = write_soup_report_config("data/train.jsonl", tmp_path / "soup.yaml")

    text = (tmp_path / "soup.yaml").read_text(encoding="utf-8")
    assert result["base_model"] == "Qwen/Qwen2.5-7B-Instruct"
    assert "quantization: 4bit" in text
    assert "stream_layers: true" in text
    assert "gradient_checkpointing: true" in text


def test_soup_training_plan_does_not_execute_by_default(tmp_path: Path):
    result = soup_training_plan("data/train.jsonl", "configs/soup.yaml", tmp_path / "plan.json", model_output_dir="models/custom")

    assert result["execute"] is False
    assert result["executed"] == []
    assert result["commands"][1][:3] == ["soup", "data", "validate"]
    assert result["commands"][5][3] == "models/custom"


def test_training_rejects_unmatched_metrics_and_truncation(tmp_path):
    report = tmp_path / "report-1.md"
    report.write_text("Report based on evidence", encoding="utf-8")
    (tmp_path / "metrics-2.json").write_text('{"integrity":{"ok":true}}', encoding="utf-8")
    result = build_report_dataset([report], tmp_path / "dataset.jsonl")
    assert result["rows"] == 0
    assert "matching metrics" in result["skipped"][0]["reason"]
    (tmp_path / "metrics-1.json").write_text('{"integrity":{"ok":true}}', encoding="utf-8")
    result = build_report_dataset([report], tmp_path / "dataset.jsonl", max_input_chars=1)
    assert result["rows"] == 0
    assert "truncate evidence" in result["skipped"][0]["reason"]
