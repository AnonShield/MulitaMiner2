"""SARIF 2.1.0 export; the de facto findings format tools actually ingest
(GitHub code scanning, DefectDojo, SonarQube, Azure DevOps).

Network findings carry no file location, so results use logicalLocations
(`host:port`, or the instance URL for host-less web findings) plus a synthetic
physicalLocation (the host at line 1, as Trivy does for container images),
without which GitHub code scanning drops the result. Scanner-specific fields
ride in the SARIF property bag.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from mulitaminer import __version__
from mulitaminer.exporters import register
from mulitaminer.exporters.generic import endpoints
from mulitaminer.models import VulnRecord

# MulitaMiner severity -> SARIF result level.
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "LOG": "note", "INFO": "note"}

# Label -> score used as `security-severity` when the record has no CVSS. GitHub
# bands: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}


def _rule_id(record: VulnRecord) -> str:
    plugin = getattr(record, "plugin", None)  # scanner-specific field
    if plugin:
        return f"{record.source}-{plugin}"
    slug = re.sub(r"[^A-Za-z0-9]+", "-", record.name).strip("-")[:80]
    return f"{record.source}-{slug}"


def _result(record: VulnRecord, rule_index: int) -> dict:
    message = "\n".join(record.description) or record.name
    result = {
        "ruleId": _rule_id(record),
        "ruleIndex": rule_index,
        "level": _LEVEL.get(record.severity.upper(), "note"),
        "message": {"text": message},
        "properties": {
            "severity": record.severity,
            "cvss": getattr(record, "cvss", None),
            "source": record.source,
            "port": record.port,
            "protocol": record.protocol,
        },
    }
    if not (eps := endpoints(record)):
        return result
    qualified = eps[0]
    host = record.host or urlsplit(qualified).hostname or qualified
    result["locations"] = [{
        "physicalLocation": {"artifactLocation": {"uri": host}, "region": {"startLine": 1}},
        "logicalLocations": [{"fullyQualifiedName": qualified, "kind": "resource"}],
    }]
    return result


def _security_severity(record: VulnRecord) -> float | None:
    """GitHub and DefectDojo map this to Critical..Low; DefectDojo also stores it
    as the CVSS score, so a real numeric CVSS wins over the label midpoint."""
    cvss = getattr(record, "cvss", None)  # scanner-specific field
    if isinstance(cvss, (int, float)) and cvss > 0:
        return float(cvss)
    return _SECURITY_SEVERITY.get(record.severity.upper())


@register("sarif", "SARIF 2.1.0 JSON (GitHub code scanning, DefectDojo, SonarQube)")
def to_sarif(records: list[VulnRecord], record_type: type[VulnRecord], out_dir: Path) -> Path:
    rules: dict[str, dict] = {}
    rule_index: dict[str, int] = {}
    for record in records:
        rid = _rule_id(record)
        if rid not in rules:
            rule_index[rid] = len(rules)
            rule = {"id": rid, "name": record.name,
                    "shortDescription": {"text": record.name}}
            solution = "\n".join(record.solution)
            if solution:
                rule["help"] = {"text": solution}
            if (score := _security_severity(record)) is not None:
                rule["properties"] = {"security-severity": str(score), "tags": ["security"]}
            rules[rid] = rule

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MulitaMiner",
                        "version": __version__,
                        "informationUri": "https://github.com/AnonShield/MulitaMiner2",
                        "rules": list(rules.values()),
                    }
                },
                # GitHub replaces earlier analyses of the same category: one per
                # scanner, so uploading a Nessus run keeps the OpenVAS alerts.
                "automationDetails": {
                    "id": f"mulitaminer/{records[0].source.lower() if records else 'unknown'}/"
                },
                "results": [_result(r, rule_index[_rule_id(r)]) for r in records],
            }
        ],
    }
    path = out_dir / "results.sarif"
    path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
