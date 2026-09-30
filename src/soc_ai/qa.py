from __future__ import annotations

from pathlib import Path
import json
import hashlib
import re


REQUIRED_REPORT_SECTIONS = [
    "Executive summary",
    "Top hosts",
    "Rule findings",
    "Integrity",
    "Model comparison",
    "Limitations",
]

SECRET_REGEX = re.compile(r"(?i)(splunk[_-]?token|authorization:\s*bearer|api[_-]?key=|password=)[A-Za-z0-9._:/+\-=]{6,}")


def qa_report(markdown_path: str | Path, metrics_path: str | Path | None = None, strict: bool = True) -> dict:
    md = Path(markdown_path).read_text(encoding="utf-8")
    failures = []
    warnings = []
    is_v2 = md.startswith("<!-- soc-report-v2 -->")
    if not is_v2:
        for section in REQUIRED_REPORT_SECTIONS:
            if section not in md:
                failures.append(f"missing report section: {section}")
    if SECRET_REGEX.search(md):
        failures.append("possible unredacted secret in markdown report")
    metrics = {}
    if strict and not metrics_path:
        failures.append("matching metrics are required for strict QA")
    if metrics_path:
        metrics = json.loads(Path(metrics_path).read_text(encoding="utf-8"))
        if is_v2:
            from .report_document import build_document, markdown_document
            from .report_planner import verify_bound_plan
            try:
                verify_bound_plan(metrics)
                document = build_document(metrics)
                failures.extend(document["failures"])
                from .pdf_qa import check_pdf
                pdf = Path(markdown_path).with_suffix(".pdf")
                if not pdf.is_file():
                    failures.append("matching PDF is missing")
                else:
                    try:
                        failures.extend(check_pdf(pdf, document)["failures"])
                    except Exception:
                        failures.append("PDF could not be verified")
                if md != "<!-- soc-report-v2 -->\n" + markdown_document(document):
                    failures.append("report content differs from verified evidence rendering")
            except (ValueError, TypeError, KeyError):
                failures.append("invalid report evidence or model plan")
        integrity = metrics.get("integrity", {})
        if (strict or integrity) and integrity.get("ok") is not True:
            failures.append("integrity check is not ok")
        if metrics.get("total_events", 0) <= 0:
            warnings.append("report has zero events")
        if "rules" not in metrics:
            warnings.append("rule findings summary is missing from metrics")
    status = "pass" if not failures and (not strict or not warnings) else "fail"
    return {"status": status, "failures": failures, "warnings": warnings, "strict": strict}


def qa_run(run_dir: str | Path, strict: bool = True) -> dict:
    root = Path(run_dir)
    reports = root / "reports"
    markdowns = sorted(reports.glob("report-*.md"))
    if not markdowns:
        return {"status": "fail", "failures": ["no markdown report found"], "warnings": [], "strict": strict}
    latest_md = markdowns[-1]
    matching = latest_md.with_name(latest_md.name.replace("report-", "metrics-", 1)).with_suffix(".json")
    latest_metrics = matching if matching.is_file() else None
    result = qa_report(latest_md, latest_metrics, strict=strict)
    result.update({"run_dir": str(root), "report": str(latest_md), "metrics": str(latest_metrics) if latest_metrics else None})
    return result


def qa_ai_review(review_path: str | Path, strict: bool = True) -> dict:
    from .gpu import _aggregate_metrics, _quality_checks

    review = json.loads(Path(review_path).read_text(encoding="utf-8"))
    failures = []
    warnings = []
    if not review.get("metrics") or not review.get("metrics_sha256"):
        failures.append("AI review requires source metrics and their digest")
    else:
        try:
            source_bytes = Path(review["metrics"]).read_bytes()
            if hashlib.sha256(source_bytes).hexdigest() != review["metrics_sha256"]:
                failures.append("AI review source metrics changed")
            expected = _aggregate_metrics(json.loads(source_bytes))
            if review.get("aggregate") != expected:
                failures.append("AI review aggregate differs from source metrics")
        except (OSError, ValueError, TypeError):
            failures.append("AI review source metrics are missing or invalid")
    if review.get("done_reason") == "length":
        failures.append("AI generation was truncated")
    checks = review.get("quality_checks", {})
    if checks.get("passed") is not True:
        failures.append("AI review quality checks did not pass")
    response = review.get("response")
    aggregate = review.get("aggregate")
    if not isinstance(response, dict) or not isinstance(aggregate, dict):
        failures.append("invalid AI review response or aggregate")
    elif not _quality_checks(response, aggregate)["passed"]:
        failures.append("independent AI response validation failed")
    if checks.get("unsupported_attack_terms"):
        failures.append("AI review contains unsupported attack or breach claims")
    if checks.get("low_frequency_hosts_mentioned"):
        failures.append("AI review mentions low-frequency hosts as notable evidence")
    if not review.get("aggregate"):
        failures.append("AI review is missing source aggregate metrics")
    if not review.get("response"):
        failures.append("AI review is missing model response")
    if review.get("done") is not True:
        warnings.append("AI backend did not report done=true")
    status = "pass" if not failures and (not strict or not warnings) else "fail"
    return {"status": status, "failures": failures, "warnings": warnings, "strict": strict, "review": str(review_path)}
