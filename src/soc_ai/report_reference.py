from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
import shutil
import time

from .soup_integration import DEFAULT_REPORT_INSTRUCTION, _redact_text
from .redaction import redact_text


LATIN_SECURITY_ALLOWLIST = {
    "ad",
    "api",
    "anydesk",
    "cef",
    "cve",
    "dc",
    "dns",
    "endpoint",
    "file",
    "high",
    "host",
    "identifier",
    "kata",
    "kedr",
    "ldap",
    "linux",
    "log4j",
    "low",
    "medium",
    "official",
    "organization",
    "powershell",
    "psexec",
    "report",
    "section",
    "soc",
    "splunk",
    "spring4shell",
    "table",
    "taa",
    "uac",
    "vpn",
    "windows",
    "winrm",
}


def ingest_report_reference(
    pdf_path: str | Path,
    output_dir: str | Path = "data/report_references",
    dataset_path: str | Path | None = None,
    min_text_quality: float = 0.85,
    max_output_chars: int = 12_000,
    max_rows: int = 24,
) -> dict:
    import pdfplumber

    source = Path(pdf_path)
    if not source.exists():
        raise ValueError(f"reference PDF not found: {source}")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    digest = _sha256(source)
    stem = f"{_safe_stem(source.stem)}-{digest[:12]}"
    stored_pdf = out / f"{stem}.pdf"
    if not stored_pdf.exists():
        shutil.copy2(source, stored_pdf)
        stored_pdf.chmod(0o600)

    page_texts = []
    page_sizes = []
    table_counts = []
    with pdfplumber.open(source) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            page_texts.append(text)
            page_sizes.append({"width": round(page.width, 2), "height": round(page.height, 2)})
            try:
                table_counts.append(len(page.extract_tables() or []))
            except Exception:
                table_counts.append(0)
    raw_text = "\n\n".join(page_texts)
    quality = _text_quality(raw_text)
    usable_text = quality >= min_text_quality
    clean_text = _redact_reference_text(raw_text) if usable_text else ""
    headings = _extract_heading_candidates(clean_text) if usable_text else []
    reference = {
        "schema": "soc-report-reference-v1",
        "source_pdf": str(stored_pdf),
        "original_pdf": str(source),
        "sha256": digest,
        "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pages": len(page_texts),
        "page_sizes": page_sizes[:5],
        "table_count_estimate": sum(table_counts),
        "text_quality": quality,
        "text_usable_for_training": usable_text,
        "headings": headings[:80],
        "status": "training_dataset_created" if usable_text else "visual_reference_only",
        "note": "PDF text is used only when extraction quality is high enough; otherwise the PDF is retained as a visual style reference.",
    }
    reference_path = out / f"{stem}.reference.json"
    reference_path.write_text(json.dumps(reference, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    reference_path.chmod(0o600)
    text_path = None
    rows = 0
    skipped_reason = ""
    if usable_text:
        text_path = out / f"{stem}.md"
        text_path.write_text("# Official report reference\n\n" + clean_text, encoding="utf-8")
        text_path.chmod(0o600)
        dataset = Path(dataset_path) if dataset_path else out / "report_style_references.jsonl"
        dataset.parent.mkdir(parents=True, exist_ok=True)
        with dataset.open("a", encoding="utf-8", newline="\n") as handle:
            for index, chunk in enumerate(_chunk_text(clean_text, max_output_chars, max_rows), 1):
                row = {
                    "instruction": DEFAULT_REPORT_INSTRUCTION + " Match the official report style, section hierarchy, table captions, and conservative wording from the supplied reference.",
                    "input": json.dumps({
                        "reference_type": "official_report_style",
                        "pages": len(page_texts),
                        "chunk": index,
                        "headings": headings[:30],
                        "constraints": ["do not invent facts", "preserve numeric evidence", "use official report tone"],
                    }, ensure_ascii=False, sort_keys=True),
                    "output": chunk,
                }
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                rows += 1
        dataset.chmod(0o600)
    else:
        skipped_reason = "PDF text extraction quality is too low; training on this text would poison the model"
    return {
        "reference": str(reference_path),
        "stored_pdf": str(stored_pdf),
        "text": str(text_path) if text_path else "",
        "dataset": str(dataset_path or out / "report_style_references.jsonl"),
        "rows_written": rows,
        "skipped_reason": skipped_reason,
        **reference,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9А-Яа-я._-]+", "_", value).strip("._-")
    return stem[:80] or "report-reference"


def _text_quality(text: str) -> float:
    letters = [char for char in text if char.isalpha()]
    if not letters:
        return 0.0
    replacement = text.count("\ufffd") + text.count("�")
    cyrillic = sum(1 for char in letters if "А" <= char <= "я" or char in "Ёё")
    latin = sum(1 for char in letters if "A" <= char <= "z")
    readable = cyrillic + latin
    penalty = min(1.0, replacement / max(1, len(text)))
    return round(max(0.0, readable / len(letters) - penalty), 4)


def _redact_reference_text(text: str) -> str:
    redacted = redact_text(_redact_text(text), mask_ips=True)
    redacted = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-zА-Яа-я]{2,}\b", "<email>", redacted)
    redacted = re.sub(
        r"\b[A-Za-zА-Яа-я0-9_-]+\.(?:[A-Za-zА-Яа-я0-9_-]+\.)*(?:local|lan|corp|kz|ru|com|net|org)\b",
        "<host>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"\b[A-Za-zА-Яа-я]\.[A-Za-zА-Яа-я][A-Za-zА-Яа-я_-]{2,}\b", "<user>", redacted)
    redacted = re.sub(r"\b[A-Za-zА-Яа-я][A-Za-zА-Яа-я_-]{1,}\.[A-Za-zА-Яа-я][A-Za-zА-Яа-я._-]{2,}\b", "<user>", redacted)
    redacted = re.sub(
        r"\b(?=[A-Za-zА-Яа-я0-9_-]{5,}\b)(?=[A-Za-zА-Яа-я0-9_-]*\d)(?=[A-Za-zА-Яа-я0-9_-]*[A-Za-zА-Яа-я])[A-Za-zА-Яа-я][A-Za-zА-Яа-я0-9_-]*\b",
        "<host>",
        redacted,
    )
    redacted = re.sub(r"\b[A-Za-z][A-Za-z0-9_-]*(?:server|srv|dc)[A-Za-z0-9_-]*\b", "<host>", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"\b(?:qazpat\w*|niis[-\w]*)\b", "<organization>", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"\b[A-Za-z][A-Za-z_-]{4,}\b", _redact_latin_identifier, redacted)
    lines = []
    for line in redacted.splitlines():
        normalized = line.strip().lower()
        if ("ул." in normalized and "г." in normalized) or "бц " in normalized or normalized.startswith("этаж "):
            lines.append("<organization-address>")
        else:
            lines.append(line)
    return "\n".join(lines)


def _redact_latin_identifier(match: re.Match[str]) -> str:
    value = match.group(0)
    if value.lower() in LATIN_SECURITY_ALLOWLIST:
        return value
    return "<identifier>"


def _extract_heading_candidates(text: str) -> list[str]:
    candidates = []
    for raw in text.splitlines():
        line = " ".join(raw.strip().split())
        if not line or len(line) > 140:
            continue
        if re.match(r"^(\d+(\.\d+)*\s+|[А-ЯA-Z][А-ЯA-Z\s]{6,}$|Таблица\s+№?\d+)", line):
            candidates.append(line)
    return candidates


def _chunk_text(text: str, max_chars: int, max_rows: int) -> list[str]:
    if max_chars < 1000:
        raise ValueError("max_output_chars must be at least 1000")
    paragraphs = [item.strip() for item in re.split(r"\n{2,}", text) if item.strip()]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        addition = paragraph if not current else current + "\n\n" + paragraph
        if len(addition) > max_chars and current:
            chunks.append(current)
            current = paragraph
            if len(chunks) >= max_rows:
                break
        else:
            current = addition
    if current and len(chunks) < max_rows:
        chunks.append(current[:max_chars])
    return chunks
