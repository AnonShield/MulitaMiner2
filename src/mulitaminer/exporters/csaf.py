"""CSAF 2.0 security advisory export (OASIS; the CISA-endorsed advisory format).

One document per run: scanned hosts become the product_tree and vulnerabilities[]
is keyed by CVE, as CSAF expects (a finding citing N CVEs feeds N entries;
findings sharing a CVE merge). Findings without a CVE get one entry per title.
Scores are emitted only when a CVSS v3 vector is available (the cvss_v3 object
requires vectorString).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mulitaminer import __version__
from mulitaminer.exporters import register
from mulitaminer.exporters.generic import cves_from, instance_urls
from mulitaminer.models import VulnRecord

# Tenable: "CVSSV3 BASE SCORE 6.5" / Nessus: "CVSS v3.0 Base Score 6.5 (CVSS:3.0/...)".
_CVSS3_SCORE_RE = re.compile(r"CVSS\s*V3(?:\.\d)?\s+BASE\s+SCORE\s+([\d.]+)", re.IGNORECASE)
_CVSS3_VECTOR_RE = re.compile(r"CVSS:3\.[01](?:/[A-Z]+:[A-Z])+")


def _rating(score: float) -> str:
    """CVSS v3 qualitative scale; CSAF test 6.1.9 requires baseSeverity to match it."""
    if score == 0:
        return "NONE"
    return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def _product_id(host: str, index: dict[str, str]) -> str:
    if host not in index:
        index[host] = f"HOST-{len(index) + 1}"
    return index[host]


def _cvss(record: VulnRecord) -> dict | None:
    cvss = getattr(record, "cvss", None)  # scanner-specific field
    if not isinstance(cvss, list):
        return None
    joined = " ".join(cvss)
    vector = _CVSS3_VECTOR_RE.search(joined)
    score = _CVSS3_SCORE_RE.search(joined)
    if not (vector and score):
        return None
    base = float(score.group(1))
    return {
        "version": vector.group(0)[5:8],
        "vectorString": vector.group(0),
        "baseScore": base,
        "baseSeverity": _rating(base),
    }


def _product_name(record: VulnRecord) -> str:
    if record.host:
        return record.host
    if urls := instance_urls(record):  # host-less web findings (ZAP)
        return urlsplit(urls[0]).netloc or urls[0]
    # Location not extracted; every vulnerability still needs a product (test 6.1.27.6).
    return "unidentified target"


def _products_by(pairs: list[tuple[str, str]]) -> dict[str, list[str]]:
    """value -> distinct product ids carrying it, in first-seen order; empty values dropped."""
    grouped: dict[str, list[str]] = {}
    for value, pid in pairs:
        if value and pid not in grouped.setdefault(value, []):
            grouped[value].append(pid)
    return grouped


def _vulnerability(cve: str | None, members: list[tuple[VulnRecord, str]]) -> dict:
    """One CSAF vulnerability: every finding (on every host) that cites `cve`, or
    one finding title across hosts when the finding cites no CVE."""
    first: dict[str, VulnRecord] = {}  # finding name -> its first record
    for record, _ in members:
        first.setdefault(record.name, record)
    entry: dict = {
        "title": "; ".join(first),
        "notes": [{"category": "description", "title": name,
                   "text": "\n".join(r.description) or name} for name, r in first.items()],
    }
    if cve:
        entry["cve"] = cve
    entry["product_status"] = {"known_affected": list(dict.fromkeys(p for _, p in members))}
    # Scanner rating is not a CVSS score; CSAF's place for an issuer rating is an impact threat.
    entry["threats"] = [{"category": "impact", "details": sev, "product_ids": pids}
                        for sev, pids in _products_by([(r.severity.upper(), p) for r, p in members]).items()]
    if remediations := _products_by([("\n".join(r.solution), p) for r, p in members]):
        entry["remediations"] = [{"category": "mitigation", "details": text, "product_ids": pids}
                                 for text, pids in remediations.items()]
    scores: dict[str, dict] = {}  # product -> its first score (test 6.1.7: one per product)
    for record, pid in members:
        if pid not in scores and (cvss := _cvss(record)):
            scores[pid] = cvss
    if scores:
        by_score = _products_by([(json.dumps(c, sort_keys=True), p) for p, c in scores.items()])
        entry["scores"] = [{"products": pids, "cvss_v3": json.loads(c)} for c, pids in by_score.items()]
    return entry


@register("csaf", "CSAF 2.0 security advisory JSON (CISA/CSIRT ecosystem)")
def to_csaf(records: list[VulnRecord], record_type: type[VulnRecord], out_dir: Path) -> Path:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    product_index: dict[str, str] = {}
    groups: dict[tuple[str, str], list[tuple[VulnRecord, str]]] = {}
    for record in records:
        pid = _product_id(_product_name(record), product_index)
        keys = [("cve", c) for c in cves_from(record)] or [("title", record.name)]
        for key in keys:
            groups.setdefault(key, []).append((record, pid))
    vulnerabilities = [_vulnerability(value if kind == "cve" else None, members)
                       for (kind, value), members in groups.items()]

    document = {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "lang": "en",
            "publisher": {
                "category": "other",
                "name": "MulitaMiner",
                "namespace": "https://github.com/AnonShield/MulitaMiner2",
            },
            "title": "MulitaMiner scan findings",
            "tracking": {
                "id": f"MULITAMINER-{now.replace(':', '').replace('-', '')}",
                "status": "final",
                "version": "1",
                "generator": {"engine": {"name": "MulitaMiner", "version": __version__}},
                "initial_release_date": now,
                "current_release_date": now,
                "revision_history": [
                    {"date": now, "number": "1", "summary": "Initial version"}
                ],
            },
        },
        "product_tree": {
            "full_product_names": [
                {"product_id": pid, "name": host} for host, pid in product_index.items()
            ]
        },
        "vulnerabilities": vulnerabilities,
    }
    path = out_dir / "results.csaf.json"
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
