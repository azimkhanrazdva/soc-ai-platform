from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
import json
import re

from .storage import read_jsonl


def load_rules(path: str | Path = "configs/detection_rules.json") -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    rules = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        raise ValueError("rules file must contain a JSON list")
    return rules


def run_rules(
    paths: list[str | Path],
    rules_path: str | Path = "configs/detection_rules.json",
    output_path: str | Path = "reports/rule_findings.json",
    max_findings: int = 100_000,
) -> dict:
    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    rules = load_rules(rules_path)
    findings = []
    total_events = 0
    findings_count = 0
    findings_by_severity: dict[str, int] = {}
    for source_path in paths:
        for line_no, event in enumerate(read_jsonl(source_path), start=1):
            total_events += 1
            for rule in rules:
                if _matches(event, rule.get("match", {})):
                    findings_count += 1
                    severity = str(rule.get("severity", "medium"))
                    findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
                    if len(findings) < max_findings:
                        findings.append(_finding(rule, source_path, line_no, event))
    summary = {
        "rules_loaded": len(rules),
        "events_scanned": total_events,
        "findings_count": findings_count,
        "findings_by_severity": findings_by_severity,
        "findings_truncated": findings_count > len(findings),
        "findings": findings,
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return {"output": str(out), **summary}


def _matches(event: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    if not spec:
        return False
    if "all" in spec:
        return all(_predicate(event, item) for item in spec["all"])
    if "any" in spec:
        return any(_predicate(event, item) for item in spec["any"])
    return _predicate(event, spec)


def _predicate(event: Mapping[str, Any], item: Mapping[str, Any]) -> bool:
    field = str(item.get("field", ""))
    value = str(event.get(field, ""))
    if "equals" in item:
        return value == str(item["equals"])
    if "contains" in item:
        return str(item["contains"]).lower() in value.lower()
    if "regex" in item:
        return re.search(str(item["regex"]), value) is not None
    return False


def _finding(rule: Mapping[str, Any], source_path: str | Path, line_no: int, event: Mapping[str, Any]) -> dict:
    evidence = {k: event.get(k) for k in ("_time", "host", "source", "sourcetype", "user", "src_ip") if k in event}
    return {
        "rule_id": rule.get("id"),
        "title": rule.get("title"),
        "severity": rule.get("severity", "medium"),
        "description": rule.get("description", ""),
        "source_path": str(source_path),
        "line": line_no,
        "evidence": evidence,
    }


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "unknown"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts

