"""Writers: schema-derived columns, round-trippable JSON."""
import json

from mulitaminer.models import VulnRecord
from mulitaminer.scanner_engine import _record_with_fields, get_scanner
from mulitaminer.writers import (
    columns_for,
    unified_columns,
    write_csv,
    write_json,
    write_xlsx,
)

OpenVASRecord = get_scanner("openvas").record_type  # core + config-declared fields

RECORDS = [
    OpenVASRecord(name="A", severity="HIGH", cvss=7.5, port=443, protocol="tcp",
                  description=["first", "second"], source="OPENVAS"),
    OpenVASRecord(name="B", severity="LOG", cvss=0.0, source="OPENVAS"),
]


def test_columns_derived_from_schema_include_severity():
    cols = columns_for(OpenVASRecord)
    assert "Name" in cols and "severity" in cols and "source" in cols


def test_json_round_trip(tmp_path):
    out = tmp_path / "results.json"
    write_json(RECORDS, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 2
    assert data[0]["Name"] == "A"
    assert data[0]["severity"] == "HIGH"
    assert data[1]["cvss"] == 0.0
    assert data[0]["source"] == "OPENVAS"


def test_xlsx_and_csv_write(tmp_path):
    import pandas as pd

    write_xlsx(RECORDS, tmp_path / "r.xlsx")
    write_csv(RECORDS, tmp_path / "r.csv")
    df = pd.read_excel(tmp_path / "r.xlsx")
    # Tabular output uses the union columns so every scanner writes the same shape.
    assert list(df.columns) == unified_columns()
    assert df.iloc[0]["Name"] == "A"
    # list fields are newline-joined in tabular formats
    assert df.iloc[0]["description"] == "first\nsecond"


def test_config_declared_field_joins_union_empty_for_others():
    """A config-declared field (e.g. Qualys `category`) becomes a shared output
    column; scanners that don't declare it emit it, empty."""
    qualys = _record_with_fields(VulnRecord, "qualys", {"category": "str"})
    cols = unified_columns([OpenVASRecord, qualys])
    assert "category" in cols
    # It is not part of OpenVAS's own schema, but the union carries it.
    assert "category" not in columns_for(OpenVASRecord)


def test_formula_like_cells_stay_text(tmp_path):
    import pandas as pd

    hostile = [OpenVASRecord(name='=HYPERLINK("http://x.test","open")', severity="HIGH", cvss=1.0,
                             description=["-2+3", "@SUM(1)"], source="OPENVAS")]
    write_csv(hostile, tmp_path / "h.csv")
    write_xlsx(hostile, tmp_path / "h.xlsx")
    csv_text = (tmp_path / "h.csv").read_text(encoding="utf-8")
    assert "'=HYPERLINK" in csv_text and "'-2+3" in csv_text
    df = pd.read_excel(tmp_path / "h.xlsx")
    assert df.iloc[0]["Name"] == "'=HYPERLINK(\"http://x.test\",\"open\")"   # text, not a formula
    assert df.iloc[0]["description"] == "-2+3\n@SUM(1)"   # openpyxl only runs "="

