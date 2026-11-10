"""CAIS export: dotted-key institutional schema, emitted as CSV + JSON.

Deterministic mapping from validated records; no LLM involved. Fields the
records cannot provide (EPSS, dates, CPE) are emitted as null/empty so the
column set is always complete.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from mulitaminer.exporters import register
from mulitaminer.exporters.generic import cves_from
from mulitaminer.models import VulnRecord
from mulitaminer.writers import guard_formulas

CWE_RE = re.compile(r"CWE[-\s](\d+)", re.IGNORECASE)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CVSS3_SCORE_RE = re.compile(r"CVSSV3\s+BASE\s+SCORE\s+([\d.]+)", re.IGNORECASE)
_CVSS3_VECTOR_RE = re.compile(r"CVSSV3\s+VECTOR\s+(\S+)", re.IGNORECASE)
_CVSS2_SCORE_RE = re.compile(r"CVSS\s+BASE\s+SCORE\s+([\d.]+)", re.IGNORECASE)
_CVSS2_VECTOR_RE = re.compile(r"CVSS\s+VECTOR\s+(\S+)", re.IGNORECASE)

_SYSTEM_TYPE = {"OPENVAS": "Network Service", "TENABLEWAS": "Web Application"}


def _join(lines: list[str]) -> str | None:
    return "\n".join(lines) if lines else None


def _cvss_fields(record: VulnRecord) -> dict:
    out = {"definition.cvss3.base_score": None, "definition.cvss3.base_vector": None,
           "definition.cvss2.base_score": None, "definition.cvss2.base_vector": None}
    cvss = getattr(record, "cvss", None)  # scanner-specific field (config-declared)
    if isinstance(cvss, (int, float)):
        out["definition.cvss3.base_score"] = float(cvss)
    elif isinstance(cvss, list):
        joined = " ".join(cvss)
        if m := _CVSS3_SCORE_RE.search(joined):
            out["definition.cvss3.base_score"] = float(m.group(1))
        if m := _CVSS3_VECTOR_RE.search(joined):
            out["definition.cvss3.base_vector"] = m.group(1)
        if m := _CVSS2_SCORE_RE.search(joined):
            out["definition.cvss2.base_score"] = float(m.group(1))
        if m := _CVSS2_VECTOR_RE.search(joined):
            out["definition.cvss2.base_vector"] = m.group(1)
    return out


def _cwes_from(record: VulnRecord) -> str | None:
    found: list[str] = []
    for ref in record.references:
        for num in CWE_RE.findall(ref):
            cwe = f"CWE-{num}"
            if cwe not in found:
                found.append(cwe)
    return ", ".join(found) or None


def to_cais_row(record: VulnRecord, row_id: int) -> dict:
    host = record.host
    is_ip = bool(host and IPV4_RE.match(host))
    cves = cves_from(record)
    details = getattr(record, "plugin_details", None) or None
    return {
        "id": f"vuln_{row_id}",
        "asset.name": host,
        "asset.display_fqdn": None if is_ip else host,
        "asset.display_ipv4_address": host if is_ip else None,
        "asset.host_name": host,
        "asset.operating_system": None,
        "asset.system_type": _SYSTEM_TYPE.get(record.source),
        "definition.name": record.name,
        "definition.severity": record.severity,
        "definition.description": _join(record.description),
        "definition.solution": _join(record.solution),
        "definition.id": str(getattr(record, "plugin", None)) if getattr(record, "plugin", None) else None,
        "definition.family": details.family if details else None,
        "definition.type": None,
        "definition.cve": ", ".join(cves) or None,
        "definition.cwe": _cwes_from(record),
        "definition.cpe": None,
        "definition.references": list(record.references),
        "definition.see_also": [],
        **_cvss_fields(record),
        "definition.synopsis": None,
        "definition.plugin_published": details.publication_date if details else None,
        "definition.vulnerability_published": None,
        "definition.patch_published": None,
        "definition.epss.score": None,
        "definition.exploitability_ease": None,
        "output": _join(getattr(record, "detection_result", [])),
        "port": record.port,
        "protocol": record.protocol,
        "scan.id": None,
        "scan.target": host,
        "severity": record.severity,
        "state": "open",
        "first_observed": None,
        "last_seen": None,
        "age_in_days": None,
    }


@register("cais", "CAIS institutional schema (CSV + JSON)")
def to_cais(records: list[VulnRecord], record_type: type[VulnRecord], out_dir: Path) -> Path:
    import pandas as pd

    rows = [to_cais_row(r, i + 1) for i, r in enumerate(records)]
    (out_dir / "results.cais.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    csv_rows = [
        {k: ("; ".join(v) if isinstance(v, list) else v) for k, v in row.items()}
        for row in rows
    ]
    path = out_dir / "results.cais.csv"
    guard_formulas(pd.DataFrame(csv_rows)).to_csv(path, index=False, encoding="utf-8")
    return path
