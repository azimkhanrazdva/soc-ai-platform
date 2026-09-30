from __future__ import annotations

from pathlib import Path
import html
import json
import re
import time
import uuid
import tempfile
import os

from .redaction import redact_event


def write_report(metrics: dict, output_dir: str | Path = "reports", title: str = "SOC AI Analysis Report") -> dict:
    from .report_document import build_document, markdown_document, html_document, pdf_document, docx_document, normalize_text
    from .report_planner import verify_bound_plan

    metrics = normalize_text(redact_event(metrics, mask_ips=True))
    verify_bound_plan(metrics)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:12]
    md_path = out / f"report-{ts}.md"
    html_path = out / f"report-{ts}.html"
    json_path = out / f"metrics-{ts}.json"
    pdf_path = out / f"report-{ts}.pdf"
    docx_path = out / f"report-{ts}.docx"
    document = build_document(metrics, title)
    md = "<!-- soc-report-v2 -->\n" + markdown_document(document)
    from .pdf_qa import check_pdf
    if document["failures"]:
        raise ValueError("Report evidence failed acceptance")
    with tempfile.TemporaryDirectory(prefix=".report-staging-", dir=out) as staging:
        stage = Path(staging)
        candidate = stage / pdf_path.name
        docx_candidate = stage / docx_path.name
        pdf_document(document, candidate)
        docx_document(document, docx_candidate)
        acceptance = check_pdf(candidate, document)
        if acceptance["status"] != "pass":
            raise ValueError("PDF acceptance failed: " + "; ".join(acceptance["failures"]))
        payloads = {
            md_path: md, html_path: html_document(document),
            json_path: json.dumps(metrics, indent=2, ensure_ascii=False, sort_keys=True),
            pdf_path.with_suffix(".document.json"): json.dumps(document, ensure_ascii=False, indent=2),
            pdf_path.with_suffix(".qa.json"): json.dumps(acceptance, indent=2),
        }
        for destination, content in payloads.items():
            temporary = stage / destination.name
            temporary.write_text(content, encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, destination)
        candidate.chmod(0o600)
        docx_candidate.chmod(0o600)
        os.replace(docx_candidate, docx_path)
        os.replace(candidate, pdf_path)
    return {"markdown": str(md_path), "html": str(html_path), "metrics": str(json_path), "pdf": str(pdf_path), "docx": str(docx_path)}


def render_markdown(metrics: dict, title: str) -> str:
    total = metrics.get("total_events", 0)
    integrity = metrics.get("integrity", {})
    ingest = metrics.get("ingest", {})
    rules = metrics.get("rules", {})
    evaluation = metrics.get("evaluation", {})
    generated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [
        f"# {_cell(title)}",
        "",
        "## Report passport",
        f"- Generated: {generated}",
        f"- Customer / environment: {metrics.get('customer', 'SOC AI monitored environment')}",
        f"- Reporting period: {_period(metrics)}",
        f"- Classification: confidential operational security report",
        f"- Evidence scope: Splunk-exported, redacted aggregate metrics and verified JSONL chunks",
        "",
        "## Executive summary",
        f"- Total events processed: {total}",
        f"- Splunk rows exported: {ingest.get('rows', total)}",
        f"- Export chunks: {ingest.get('planned_chunks', 'not_available')}",
        f"- Failed export chunks: {ingest.get('failed_chunks', 'not_available')}",
        f"- Current anomaly score: {(metrics.get('model_comparison') or [{}])[0].get('score', 'not_available')}",
        f"- Integrity status: {integrity.get('ok', 'not_available')}",
        f"- Strict QA status: {metrics.get('qa_status', 'not_recorded')}",
        "",
        "## Key observations",
        "1. The report uses aggregate evidence only. It does not publish raw log contents or secrets.",
        f"2. Verified row coverage is {_cell(integrity.get('verified_rows', 'not_available'))}; expected rows are {_cell(integrity.get('expected_rows', 'not_available'))}.",
        f"3. Rule findings count is {_cell(rules.get('findings_count', 0))}; truncated output: {_cell(rules.get('findings_truncated', False))}.",
        "",
        "## Main indicators",
        "| Indicator | Value |",
        "| --- | ---: |",
        f"| Total processed events | {_cell(total)} |",
        f"| Verified rows | {_cell(integrity.get('verified_rows', 'not_available'))} |",
        f"| Chunks | {_cell(ingest.get('planned_chunks', 'not_available'))} |",
        f"| Rule findings | {_cell(rules.get('findings_count', 0))} |",
        f"| Aggregation limited | {_cell(metrics.get('aggregation_limited', 'not_available'))} |",
        "",
        "## Top hosts",
        _table(metrics.get("top_hosts", [])),
        "",
        "Why this matters",
        "Host distribution helps detect telemetry gaps and unusually concentrated event sources. A high-volume host is not automatically compromised; it is a prioritization signal.",
        "",
        "## Top source IPs",
        _table(metrics.get("top_src_ips", [])),
        "",
        "Why this matters",
        "Source IP distribution supports authentication, network and perimeter triage. Masking/redaction can intentionally reduce identity detail in this section.",
        "",
        "## Keyword signals",
        _table(metrics.get("keyword_counts", [])),
        "",
        "Evidence note",
        "Keyword counters are deterministic aggregate signals. They must be reviewed with rule findings and source context before incident confirmation.",
        "",
        "## Rule findings",
        f"- Findings: {metrics.get('rules', {}).get('findings_count', 0)}",
        f"- Findings by severity: {_cell(metrics.get('rules', {}).get('findings_by_severity', {}))}",
        f"- Rules loaded: {_cell(metrics.get('rules', {}).get('rules_loaded', 'not_available'))}",
        f"- Events scanned by rules: {_cell(metrics.get('rules', {}).get('events_scanned', 'not_available'))}",
        "",
        "## Integrity",
        f"- Manifest verification: {metrics.get('integrity', {}).get('ok', 'not_available')}",
        f"- Verified rows: {metrics.get('integrity', {}).get('verified_rows', 'not_available')}",
        f"- Expected rows: {metrics.get('integrity', {}).get('expected_rows', 'not_available')}",
        f"- Integrity failures: {len(metrics.get('integrity', {}).get('failures', []) or [])}",
        "",
        "## Model comparison",
        "| Model | Type | Score | Labels required |",
        "| --- | --- | ---: | --- |",
    ]
    for row in metrics.get("model_comparison", []):
        lines.append("| " + " | ".join(_cell(row.get(key, "not_available")) for key in ("name", "type", "score", "labels_required")) + " |")
    lines.extend(
        [
            "",
            "## Model accuracy",
            f"- Evaluation model: {_cell(evaluation.get('model', 'not_available'))}",
            f"- Total evaluated events: {_cell(evaluation.get('total_events', 'not_available'))}",
            f"- Accuracy note: {_cell(evaluation.get('accuracy_note', 'Precision/recall/F1/ROC-AUC require labeled data.'))}",
            "",
            "## Recommendations",
            "1. Validate high-severity rule findings against raw evidence in Splunk before declaring incidents.",
            "2. Track export completeness with checkpoint, manifest and verified row counters for every production run.",
            "3. Keep postprocessing resumable and parallel for large datasets; avoid one-shot single-process report generation.",
            "4. Add labeled incident data if precision, recall, F1 and ROC-AUC are required for model acceptance.",
            "",
            "## Evidence and audit trail",
            f"- Manifest: {_cell(metrics.get('integrity', {}).get('manifest', 'not_available'))}",
            f"- Analysis source: {_cell(metrics.get('analysis_source', 'generated by SOC AI project'))}",
            f"- Report artifacts: Markdown, HTML, JSON metrics and PDF are generated by the project report module.",
            "",
            "## Limitations",
            f"- Aggregation cardinality limit reached: {metrics.get('aggregation_limited', 'not_available')}. Limited aggregates may omit identities.",
            "- Heuristic scores are not detection accuracy or evidence of a confirmed incident.",
            "- Accuracy metrics such as precision, recall, F1 and ROC-AUC require labeled data.",
            "- Splunk SPL execution itself runs in Splunk; local GPU acceleration applies only to local ML/inference stages.",
            "- 400M event readiness depends on chunk size, disk throughput, Splunk limits, and checkpointed resume behavior.",
        ]
    )
    return "\n".join(lines) + "\n"


def _period(metrics: dict) -> str:
    preflight = metrics.get("preflight") or {}
    context = metrics.get("source_context") or {}
    start = preflight.get("start") or context.get("start") or "not_available"
    end = preflight.get("end") or context.get("end") or "not_available"
    return f"{start} - {end}"


def render_html(markdown: str, title: str) -> str:
    body = "\n".join(f"<p>{html.escape(line)}</p>" if line else "" for line in markdown.splitlines())
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title></head><body>{body}</body></html>"


def render_pdf(markdown: str, output_path: str | Path, title: str = "SOC AI Analysis Report") -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _render_pdf_reportlab(markdown, path, title)
    except ModuleNotFoundError:
        _render_pdf_minimal(markdown, path, title)
    return str(path)


def _render_pdf_reportlab(markdown: str, path: Path, title: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#555555"), leading=10))
    styles.add(ParagraphStyle(name="Kpi", parent=styles["BodyText"], fontSize=10, leading=13))
    doc = SimpleDocTemplate(str(path), pagesize=A4, title=title, leftMargin=20 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=16 * mm)
    story = []
    story.append(Paragraph(html.escape(title), styles["Title"]))
    story.append(Spacer(1, 18))
    story.append(Paragraph("Operational SOC monitoring and evidence-based analysis report", styles["Heading2"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(time.strftime("Generated %Y-%m-%d %H:%M UTC", time.gmtime()), styles["SmallMuted"]))
    story.append(Spacer(1, 28))
    for raw_line in markdown.splitlines():
        line = _strip_markdown_table(raw_line)
        if re.fullmatch(r"\s*\|.*\|\s*", raw_line):
            cells = [html.escape(cell.strip()) for cell in raw_line.strip().strip("|").split("|")]
            if cells and not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                table = Table([[Paragraph(cell, styles["Kpi"]) for cell in cells]], colWidths=[80 * mm, 70 * mm] if len(cells) == 2 else None)
                table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BBBBBB")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F4F7"))]))
                story.append(table)
            continue
        if not line:
            story.append(Spacer(1, 6))
            continue
        if raw_line.startswith("# "):
            story.append(PageBreak())
            style = styles["Heading1"]
        elif raw_line.startswith("## "):
            style = styles["Heading2"]
        else:
            style = styles["BodyText"]
        story.append(Paragraph(html.escape(line.lstrip("#- ").strip()), style))
    doc.build(story, onFirstPage=_pdf_footer(title), onLaterPages=_pdf_footer(title))


def _pdf_footer(title: str):
    from reportlab.lib.units import mm

    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColorRGB(0.25, 0.25, 0.25)
        canvas.drawString(20 * mm, 10 * mm, title[:70])
        canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def _render_pdf_minimal(markdown: str, path: Path, title: str) -> None:
    lines = []
    for raw_line in markdown.splitlines():
        line = _strip_markdown_table(raw_line)
        if line:
            lines.extend(_wrap_pdf_line(line.lstrip("#- ").strip(), width=88))
        else:
            lines.append("")
    if not lines:
        lines = [title]

    pages = [lines[index : index + 54] for index in range(0, len(lines), 54)]
    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")
    page_refs = []
    for page_index, page_lines in enumerate(pages, start=1):
        content_ref = len(objects) + 2
        page_refs.append(f"{len(objects) + 1} 0 R")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {content_ref + 1} 0 R >> >> /Contents {content_ref} 0 R >>".encode("ascii"))
        objects.append(_pdf_stream(page_lines, page_index, len(pages)))
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(pages)} >>".encode("ascii")

    offsets = []
    with path.open("wb") as fh:
        fh.write(b"%PDF-1.4\n")
        for index, payload in enumerate(objects, start=1):
            offsets.append(fh.tell())
            fh.write(f"{index} 0 obj\n".encode("ascii"))
            fh.write(payload)
            fh.write(b"\nendobj\n")
        xref = fh.tell()
        fh.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
        for offset in offsets:
            fh.write(f"{offset:010d} 00000 n \n".encode("ascii"))
        fh.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))


def _pdf_stream(lines: list[str], page: int, total_pages: int) -> bytes:
    commands = ["BT", "/F1 10 Tf", "14 TL", "50 795 Td"]
    for raw in lines:
        commands.append(f"({_pdf_escape(raw)}) Tj")
        commands.append("T*")
    commands.extend(["ET", "BT", "/F1 8 Tf", f"50 28 Td", f"(Page {page} of {total_pages}) Tj", "ET"])
    data = "\n".join(commands).encode("latin-1", errors="replace")
    return b"<< /Length " + str(len(data)).encode("ascii") + b" >>\nstream\n" + data + b"\nendstream"


def _strip_markdown_table(line: str) -> str:
    if re.fullmatch(r"\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*", line):
        return ""
    return line.replace("|", "  ")


def _wrap_pdf_line(line: str, width: int) -> list[str]:
    words = line.split()
    wrapped: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            wrapped.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    wrapped.append(current)
    return wrapped


def _pdf_escape(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _table(items: list) -> str:
    lines = ["| Value | Count |", "| --- | ---: |"]
    for value, count in items:
        lines.append(f"| {_cell(value)} | {_cell(count)} |")
    return "\n".join(lines)


def _cell(value) -> str:
    return html.escape(str(value)).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")
