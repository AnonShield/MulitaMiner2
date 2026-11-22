"""Reader tests against a real baseline PDF (no network, no LLM)."""
import re
from pathlib import Path

from mulitaminer.pdf_reader import extract_pdf

BASELINE_PDF = Path("resources/openvas/OpenVAS_JuiceShop.pdf")
OPENVAS_MARKER = re.compile(r"^\s*(?:Critical|High|Medium|Low|Log)\s+\(CVSS:", re.MULTILINE)


def test_extracts_marker_lines():
    doc = extract_pdf(BASELINE_PDF)
    assert doc.page_count > 0
    assert len(doc.text) > 1000
    assert OPENVAS_MARKER.search(doc.text), "no OpenVAS marker line survived extraction"


def test_cleanup_removes_footers_and_continuations():
    doc = extract_pdf(BASELINE_PDF)
    assert "continues on next page" not in doc.text.lower()
    assert not re.search(r"Page \d+ of \d+", doc.text)


def test_text_input_is_used_verbatim(tmp_path):
    txt = tmp_path / "report.txt"
    txt.write_text("10287 Traceroute Information Info\nPlugin Output:\n", encoding="utf-8")
    doc = extract_pdf(txt)
    assert doc.text == txt.read_text(encoding="utf-8")
    assert (doc.page_count, doc.backend) == (0, "text")


def test_no_control_characters_survive_extraction():
    """pypdfium2 emits broken ligatures as raw control chars ("a\\x1bected" =
    "affected"); a stray control char makes the LLM's JSON invalid, so the
    reader must map them (CID table) or strip them."""
    doc = extract_pdf(Path("resources/openvas/OpenVAS_Metasploitable2.pdf"))
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", doc.text)
    assert "affected" in doc.text  # the \x1b ligature was restored, not dropped
