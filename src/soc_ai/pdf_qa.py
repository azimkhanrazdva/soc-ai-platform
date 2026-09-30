"""Fail-closed acceptance of the rendered PDF against its source document."""
from pathlib import Path
import hashlib
import re


def check_pdf(path, document):
    import pdfplumber

    failures = list(document.get("failures", []))
    normalize = lambda text: re.sub(r"\s+", "", str(text))
    with pdfplumber.open(path) as pdf:
        texts = []
        # The official template reserves a cover, contents, and each section.
        if len(pdf.pages) < len(document["sections"]) + 2:
            failures.append("PDF is missing required section pages")
        for index, page in enumerate(pdf.pages, 1):
            text = page.extract_text(use_text_flow=True) or ""
            texts.append(text)
            body = [c for c in page.chars if 48 < c["top"] < page.height - 48]
            if len(body) < 30:
                failures.append(f"PDF page {index}: empty or near-empty body")
            for char in page.chars:
                if char["x0"] < 45 or char["x1"] > page.width - 45 or char["top"] < 15 or char["bottom"] > page.height - 15:
                    failures.append(f"PDF page {index}: text outside safe margins")
                    break
            if "\ufffd" in text or "\x00" in text:
                failures.append(f"PDF page {index}: broken text encoding")
            if re.search("[ёЁ]", text):
                failures.append(f"PDF page {index}: forbidden letter ё")
            words = sorted(page.extract_words(), key=lambda word: word["top"])
            overlap = False
            for position, first in enumerate(words):
                for second in words[position + 1:]:
                    if second["top"] >= first["bottom"]:
                        break
                    width = min(first["x1"], second["x1"]) - max(first["x0"], second["x0"])
                    height = min(first["bottom"], second["bottom"]) - max(first["top"], second["top"])
                    area = min((w["x1"]-w["x0"])*(w["bottom"]-w["top"]) for w in (first, second))
                    if width > 0 and height > 0 and width * height > area * 0.2:
                        overlap = True
                        break
                if overlap:
                    break
            if overlap:
                failures.append(f"PDF page {index}: overlapping text")
            pixels = page.to_image(resolution=50).original.convert("L")
            histogram = pixels.histogram()
            if sum(histogram[:200]) < pixels.width * pixels.height * 0.001:
                failures.append(f"PDF page {index}: rendering is blank")
        joined = normalize("\n".join(texts))
        for section in document["sections"]:
            expected = [section["title"], *section["paragraphs"]]
            if section["rows"]:
                expected += section["headers"]
            expected += [cell for row in section["rows"] for cell in row]
            if any(normalize(value) not in joined for value in expected if str(value).strip()):
                failures.append(f"PDF section {section['id']}: content missing or altered")
        pages = len(pdf.pages)
    return {"status": "fail" if failures else "pass", "failures": failures,
            "pages": pages, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            "policy": "official-pdf-v1"}
