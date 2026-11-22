"""PDF text extraction (pypdfium2) plus one in-memory cleanup pass: footer
removal, mojibake/CID glyph restoration, soft-hyphen rejoining,
page-continuation marker removal, NFKC."""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# character ID (CID) to glyph mapping for common ligatures and quotes
_CID_MAP = {16: '"', 17: '"', 27: "ff", 28: "fi", 29: "fl", 30: "ffi", 31: "ffl"}
_CTRL_LIGATURES = str.maketrans({chr(cid): glyph for cid, glyph in _CID_MAP.items()})
_CTRL_STRIP_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_FOOTER_RE = re.compile(r"Page \d+ of \d+")
_CONTINUATION_RE = re.compile(
    r"^.*(?:\.\s?\.\s?\.\s?)?continue[sd] (?:on next|from previous) page.*$", re.IGNORECASE
)


@dataclass(frozen=True)
class ExtractedDoc:
    text: str
    page_count: int
    backend: str = "pypdfium2"


def _extract_pages(path: Path) -> list[str]:
    import pypdfium2 as pdfium

    pages: list[str] = []
    doc = pdfium.PdfDocument(path)
    try:
        for page in doc:
            textpage = page.get_textpage()
            try:
                pages.append(textpage.get_text_range() or "")
            finally:
                textpage.close()
            page.close()
    finally:
        doc.close()
    return pages


def _clean_page(text: str) -> str:
    lines = []
    for line in text.split("\n"):
        if _FOOTER_RE.search(line):
            continue
        if _CONTINUATION_RE.match(line.strip()):
            continue
        lines.append(line.replace("\t", "    "))
    cleaned = "\n".join(lines)
    cleaned = (
        cleaned.replace("ÔåÆ", "->")
        .replace("ÔÇÖ", "'")
        .replace("ÔÇ£", '"')
        .replace("ÔÇØ", '"')
        .replace("￾", "-")  # hyphen at a line wrap comes back as U+FFFE
    )
    cleaned = re.sub(r"[ ]{2,}", " ", cleaned)
    return cleaned.rstrip() + "\n"


def _restore_cid_glyphs(text: str) -> str:
    # "word-part\n   (cid:44)→rest" is one soft-wrapped word.
    text = re.sub(r"\n[ \t]*\(cid:44\)→", "", text)
    for cid, glyph in _CID_MAP.items():
        text = text.replace(f"(cid:{cid})", glyph)
    text = re.sub(r"\(cid:\d+\)", "", text)  # unknown CIDs: drop
    text = re.sub(r"(\w)-\n[ \t]*(\w)", r"\1\2", text)
    return text


def extract_pdf(path: Path) -> ExtractedDoc:
    """Extract and clean the full report text."""
    if path.suffix.lower() == ".txt":
        # Text already extracted (and e.g. pseudonymized) from a PDF: use as is.
        return ExtractedDoc(text=path.read_text(encoding="utf-8"), page_count=0, backend="text")
    raw_pages = _extract_pages(path)
    log.info("Extracted %d pages from %s", len(raw_pages), path.name)
    text = "".join(_clean_page(p) for p in raw_pages)
    text = _CTRL_STRIP_RE.sub("", text.translate(_CTRL_LIGATURES).replace("\r", ""))
    text = unicodedata.normalize("NFKC", text)
    text = _restore_cid_glyphs(text)
    if not text.strip():
        raise ValueError(
            f"No text extracted from {path}; the file may be corrupted or image-only."
        )
    return ExtractedDoc(text=text, page_count=len(raw_pages))
