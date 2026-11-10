"""Output writers: JSON (primary), XLSX, CSV.

Columns are derived from the record model; never hardcoded.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from mulitaminer.models import VulnRecord

log = logging.getLogger(__name__)


def _source_last(keys: list[str]) -> list[str]:
    """`source` is stamped metadata; keep it as the last output column."""
    return [k for k in keys if k != "source"] + (["source"] if "source" in keys else [])


def _dump(records: list[VulnRecord]) -> list[dict]:
    return [
        {k: d[k] for k in _source_last(list(d))}
        for d in (r.model_dump(by_alias=True) for r in records)
    ]


def columns_for(record_type: type[VulnRecord]) -> list[str]:
    """Schema-ordered output columns of one record type (JSON key names)."""
    return _source_last([f.alias or name for name, f in record_type.model_fields.items()])


def unified_columns(record_types: list[type[VulnRecord]] | None = None) -> list[str]:
    """Union of output columns across scanners, so every scanner's tabular output
    is structurally identical (empty where a scanner doesn't fill a column). Core
    (VulnRecord) columns first in schema order, then scanner-specific extras in a
    stable order. Pass explicit record_types for testing; default is every
    registered scanner."""
    if record_types is None:
        from mulitaminer.scanner_engine import all_scanners

        record_types = [p.record_type for p in all_scanners().values()]
    cols = columns_for(VulnRecord)
    seen = set(cols)
    for record_type in sorted(record_types, key=lambda t: t.__name__):
        for col in columns_for(record_type):
            if col not in seen:
                seen.add(col)
                cols.append(col)
    return _source_last(cols)


def write_json(records: list[VulnRecord], path: Path) -> None:
    path.write_text(
        json.dumps(_dump(records), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log.info("Wrote %d records to %s", len(records), path)


def _cell(value) -> object:
    if isinstance(value, list):
        return "\n".join(
            v if isinstance(v, str) else json.dumps(v, ensure_ascii=False) for v in value
        )
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False) if value else ""
    return value


def _dataframe(records: list[VulnRecord]):
    import pandas as pd

    # Union columns so every scanner's tabular output is structurally identical;
    # a column a record does not have serializes empty.
    cols = unified_columns()
    rows = [{c: _cell(d.get(c)) for c in cols} for d in _dump(records)]
    return pd.DataFrame(rows, columns=cols)


# A spreadsheet runs a cell that starts with one of these as a formula: Excel
# on a CSV, all of them (DDE, HYPERLINK); openpyxl in an XLSX, "=". Text the
# scanner copied from a scanned host must stay text, and the apostrophe is
# Excel's own mark for a literal.
CSV_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")
XLSX_FORMULA_STARTS = ("=",)


def guard_formulas(df, starts: tuple[str, ...] = CSV_FORMULA_STARTS):
    return df.map(lambda v: "'" + v if isinstance(v, str) and v.startswith(starts) else v)


def write_xlsx(records: list[VulnRecord], path: Path) -> None:
    guard_formulas(_dataframe(records), XLSX_FORMULA_STARTS).to_excel(path, index=False)
    log.info("Wrote %d records to %s", len(records), path)


def write_csv(records: list[VulnRecord], path: Path) -> None:
    guard_formulas(_dataframe(records)).to_csv(path, index=False, encoding="utf-8")
    log.info("Wrote %d records to %s", len(records), path)
