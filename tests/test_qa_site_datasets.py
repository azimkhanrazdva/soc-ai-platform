import json

from soc_ai.datasets import dataset_list
from soc_ai.qa import qa_ai_review, qa_report, qa_run
from soc_ai.site import build_site


def test_dataset_catalog_contains_large_and_splunk_sources():
    datasets = dataset_list()["datasets"]
    assert "botsv3" in datasets
    assert "lanl-2017" in datasets


def test_qa_report_passes_complete_report(tmp_path):
    md = tmp_path / "report.md"
    md.write_text(
        "# R\n\n## Executive summary\n## Top hosts\n## Rule findings\n## Integrity\n## Model comparison\n## Limitations\n",
        encoding="utf-8",
    )
    metrics = tmp_path / "metrics.json"
    metrics.write_text(json.dumps({"total_events": 1, "integrity": {"ok": True}, "rules": {"findings_count": 0}}), encoding="utf-8")
    assert qa_report(md, metrics)["status"] == "pass"


def test_qa_run_finds_latest_report(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report-1.md").write_text(
        "# R\n\n## Executive summary\n## Top hosts\n## Rule findings\n## Integrity\n## Model comparison\n## Limitations\n",
        encoding="utf-8",
    )
    (reports / "metrics-1.json").write_text(json.dumps({"total_events": 1, "integrity": {"ok": True}, "rules": {}}), encoding="utf-8")
    assert qa_run(tmp_path)["status"] == "pass"
    (reports / "metrics-1.json").rename(reports / "metrics-2.json")
    assert qa_run(tmp_path)["status"] == "fail"


def test_build_site(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "metrics-1.json").write_text(json.dumps({"total_events": 5, "integrity": {"ok": True}, "rules": {"findings_count": 2}}), encoding="utf-8")
    (reports / "benchmark.json").write_text(json.dumps({"events_per_second": 123}), encoding="utf-8")
    site = build_site(reports, tmp_path / "site")
    assert site["latest_total_events"] == 5
    assert (tmp_path / "site" / "index.html").exists()


def test_build_site_uses_latest_metrics_by_mtime(tmp_path):
    reports = tmp_path / "reports"
    nested = reports / "nested" / "reports"
    nested.mkdir(parents=True)
    old = reports / "metrics-z.json"
    new = nested / "metrics-a.json"
    old.write_text(json.dumps({"total_events": 1, "integrity": {"ok": True}, "rules": {"findings_count": 0}}), encoding="utf-8")
    new.write_text(json.dumps({"total_events": 100, "integrity": {"ok": True}, "rules": {"findings_count": 3}}), encoding="utf-8")
    site = build_site(reports, tmp_path / "site")
    assert site["latest_total_events"] == 100
    assert site["latest_rules"] == 3


def test_qa_ai_review_fails_unsupported_claims(tmp_path):
    review = tmp_path / "gpu_review.json"
    review.write_text(
        json.dumps(
            {
                "aggregate": {"total_events": 100},
                "response": {"top_risks": ["attack"], "data_quality_concerns": [], "next_actions": []},
                "quality_checks": {"passed": False, "unsupported_attack_terms": ["attack"]},
                "done": True,
            }
        ),
        encoding="utf-8",
    )
    result = qa_ai_review(review)
    assert result["status"] == "fail"
    assert "AI review contains unsupported attack or breach claims" in result["failures"]
