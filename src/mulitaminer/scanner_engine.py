"""Builds a ScannerProfile (segmenter + consolidator) from a JSON config.

A scanner is one JSON + one prompt file; no Python needed to add one.
Config field reference and rationale: docs/SCANNER_CONFIGS.md.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

from pydantic import Field, create_model, field_validator

from mulitaminer.consolidate import dedupe, normalize_name
from mulitaminer.models import Block, Instance, PluginDetails, VulnRecord

RECORD_TYPES: dict[str, type[VulnRecord]] = {
    "generic": VulnRecord,
}

# Config `fields` type vocabulary -> (annotation, default). All are LLM-produced
# (no llm_produced=False marker), so they flow into the extraction contract, the
# output columns, and per-field evaluation automatically.
_FIELD_TYPES: dict[str, tuple] = {
    "str": (str, ""),
    "list": (list[str], Field(default_factory=list)),
    "int": (int | None, None),
    "float": (float | None, None),
    "number": (float | int | None, None),
}
# Structured sub-schemas stay as code models (type safety, validators); a config
# references them by name ("PluginDetails") or as a list ("[Instance]").
_FIELD_MODELS: dict[str, type] = {"Instance": Instance, "PluginDetails": PluginDetails}
_LIST_MODEL_RE = re.compile(r"\[(\w+)\]")


def _blank_to_dict(cls, value):  # noqa: N805 - pydantic validator
    return {} if value in ("", "-", None) else value


def _blank_to_list(cls, value):  # noqa: N805 - pydantic validator
    return [] if value in ("", "-", None) else value


def _resolve_field(scanner: str, fname: str, ftype: str) -> tuple:
    """(annotation, default, empty_coercer|None) for one config field type."""
    if ftype in _FIELD_TYPES:
        annotation, default = _FIELD_TYPES[ftype]
        return annotation, default, None
    if ftype in _FIELD_MODELS:
        model = _FIELD_MODELS[ftype]
        return model, Field(default_factory=model), _blank_to_dict
    m = _LIST_MODEL_RE.fullmatch(ftype)
    if m and m.group(1) in _FIELD_MODELS:
        model = _FIELD_MODELS[m.group(1)]
        return list[model], Field(default_factory=list), _blank_to_list
    raise ValueError(
        f"scanner '{scanner}': field '{fname}' has unknown type '{ftype}'; use "
        f"{sorted(_FIELD_TYPES)}, a model {sorted(_FIELD_MODELS)}, or [Model]"
    )


def _record_with_fields(base: type[VulnRecord], name: str, spec: dict) -> type[VulnRecord]:
    """A record subclass extending `base` with config-declared `fields`."""
    definitions: dict = {}
    validators: dict = {}
    for fname, ftype in spec.items():
        annotation, default, coercer = _resolve_field(name, fname, ftype)
        definitions[fname] = (annotation, default)
        if coercer is not None:
            validators[f"_coerce_{fname}"] = field_validator(fname, mode="before")(coercer)
    return create_model(
        f"{name.capitalize()}Record",
        __base__=base,
        __validators__=validators or None,
        **definitions,
    )

_BUILTIN_DIR = Path(__file__).parent / "configs" / "scanners"

# A wrapped block-title tail, e.g. "(1)" or "Instances" / "Instances (25)"
# alone on the line above a marker; the real name sits one line further up.
_SUFFIX_FRAGMENT = re.compile(r"^(\(\d+\)|Instances(\s*\(\d+\))?)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ScannerProfile:
    """Everything that defines one scanner, built from its JSON config."""

    name: str                     # CLI name, e.g. "openvas"
    source: str                   # stamped into VulnRecord.source
    record_type: type[VulnRecord]
    marker: re.Pattern            # one match line == one candidate finding
    prompt_path: Path
    max_vulns_per_chunk: int      # empirical calibration, per scanner
    segment: Callable[[str], list[Block]]
    # records -> (consolidated records, merge-log lines). Always runs:
    # structural pairing + severity normalization + identical-identity dedup.
    consolidate: Callable[[list[VulnRecord]], tuple[list[VulnRecord], list[str]]]
    # Per-field metric overrides for evaluation (config "evaluation.field_metrics");
    # frozen dataclass needs a hashable default, hence tuple of pairs.
    field_metric_overrides: tuple[tuple[str, str], ...] = ()
    # Alignment composite-key parts beyond the name (config "evaluation.key_parts",
    # e.g. ("port", "protocol")); how this scanner's findings are disambiguated.
    key_parts: tuple[str, ...] = ()

    def prompt(self) -> str:
        return self.prompt_path.read_text(encoding="utf-8")


def _join_wrapped_rows(lines: list[str], start: re.Pattern, until: re.Pattern,
                       max_lines: int) -> list[str]:
    """Rejoin table rows the PDF text split across lines: a line matching
    `start` that does not yet satisfy `until` absorbs the following lines until
    one does, within `max_lines` lines in total. Anything else is left as is."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        end = None
        if start.match(line) and not until.search(line):
            for j in range(i + 1, min(i + max_lines, len(lines))):
                if until.search(lines[j]):
                    end = j
                    break
        if end is None:
            out.append(line)
            i += 1
        else:
            out.append(" ".join(ln.strip() for ln in lines[i:end + 1]))
            i = end + 1
    return out


def _build_segmenter(cfg: dict):
    marker = re.compile(cfg["marker_pattern"])
    join = cfg.get("marker_join")
    join_start = re.compile(join["start"]) if join else None
    join_until = re.compile(join["until"]) if join else None
    join_max = int(join.get("max_lines", 3)) if join else 0
    context = cfg.get("context") or {}
    headers = [re.compile(p, re.IGNORECASE) for p in context.get("header_patterns", [])]
    host_anchor = re.compile(context["host_anchor"], re.IGNORECASE) if "host_anchor" in context else None
    host_line = re.compile(context["host_line"]) if "host_line" in context else None
    walkback = 1 if cfg.get("name_above_marker") else 0
    name_stop = re.compile(cfg["name_stop_pattern"], re.IGNORECASE) if "name_stop_pattern" in cfg else None
    # Whole lines that are pure report noise (e.g. a "2 Results per Host 7" table
    # cell that wraps between the finding name and its first section), dropped
    # before segmentation so they never pollute a block or its extracted name.
    discard = [re.compile(p, re.IGNORECASE) for p in cfg.get("discard_patterns", [])]

    def segment(text: str) -> list[Block]:
        lines = text.splitlines()
        if discard:
            lines = [ln for ln in lines if not any(p.fullmatch(ln.strip()) for p in discard)]
        if join_start:
            lines = _join_wrapped_rows(lines, join_start, join_until, join_max)
        host = port = proto = None
        last_nonblank: str | None = None
        markers: list[tuple[int, dict]] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if host_anchor and host_line and last_nonblank and host_anchor.match(stripped):
                m = host_line.match(last_nonblank)
                if m:
                    host = m.group(1)
            if stripped:
                last_nonblank = stripped
            for header in headers:
                m = header.match(stripped)
                if m:
                    groups = m.groupdict()
                    if groups.get("port"):
                        port = int(groups["port"]) if groups["port"].isdigit() else groups["port"]
                    if groups.get("proto"):
                        proto = groups["proto"].lower()
                    break
            m = marker.search(line)
            if m:
                severity = m.group(1).upper() if m.groups() and m.group(1) else None
                markers.append(
                    (i, {"host": host, "port": port, "protocol": proto,
                         "severity_hint": severity})
                )

        starts: list[int] = []
        for k, (idx, _) in enumerate(markers):
            start = idx
            barrier = markers[k - 1][0] if k else -1
            if walkback and idx - 1 > barrier:
                candidate = lines[idx - 1].strip()
                if candidate and not (name_stop and name_stop.match(candidate)):
                    start = idx - 1
                    # Long "<name> Instances (N)" titles wrap: the line above
                    # the marker is then only the suffix fragment ("(1)" or
                    # "Instances"). Climb one more line for the real name.
                    if _SUFFIX_FRAGMENT.match(candidate) and start - 1 > barrier:
                        above = lines[start - 1].strip()
                        if above and not (name_stop and name_stop.match(above)):
                            start -= 1
            starts.append(start)

        blocks: list[Block] = []
        for k, start in enumerate(starts):
            end = starts[k + 1] if k + 1 < len(starts) else len(lines)
            blocks.append(
                Block(id=k, text="\n".join(lines[start:end]).strip(), **markers[k][1])
            )
        return blocks

    return segment


def _build_consolidator(cfg: dict):
    pair = cfg.get("pair")
    strip_suffix = re.compile(pair["strip_name_suffix"], re.IGNORECASE) if pair and "strip_name_suffix" in pair else None

    def _pair_key(record: VulnRecord):
        name = record.name or ""
        if strip_suffix:
            name = strip_suffix.sub("", name)
        return (normalize_name(name), *(getattr(record, f) for f in pair["by"]))

    def _identity_key(record: VulnRecord):
        # A duplicate is a FULLY identical record (name compared normalized):
        # same key with different content means two real findings; merging
        # them would silently lose one. Only exact repeats collapse.
        data = record.model_dump(mode="json", by_alias=True)
        data["Name"] = normalize_name(record.name)
        return json.dumps(data, sort_keys=True)

    def consolidate(records: list[VulnRecord]):
        log_lines: list[str] = []
        if pair:
            records, lines = dedupe(records, _pair_key,
                                    merge_instances=bool(pair.get("merge_instances")))
            log_lines += lines
        records, lines = dedupe(records, _identity_key)
        return records, log_lines + lines

    return consolidate


def _resolve_prompt(config_path: Path, prompt_name: str) -> Path:
    """Prompts may sit next to the JSON (flat user dirs) or in a sibling
    `prompts/` folder (the package convention: configs/scanners + configs/prompts)."""
    candidates = (
        config_path.parent / prompt_name,
        config_path.parent.parent / "prompts" / prompt_name,
        config_path.parent / "prompts" / prompt_name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValueError(
        f"Prompt '{prompt_name}' for scanner config {config_path} not found in: "
        + ", ".join(str(c.parent) for c in candidates)
    )


def load_profile(config_path: Path) -> ScannerProfile:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    try:
        record_type = RECORD_TYPES.get(cfg.get("record", cfg["name"]), VulnRecord)
        if cfg.get("fields"):
            record_type = _record_with_fields(record_type, cfg["name"], cfg["fields"])
        return ScannerProfile(
            name=cfg["name"],
            source=cfg["source"],
            record_type=record_type,
            marker=re.compile(cfg["marker_pattern"]),
            prompt_path=_resolve_prompt(config_path, cfg.get("prompt", f"{cfg['name']}.txt")),
            max_vulns_per_chunk=int(cfg["max_vulns_per_chunk"]),
            segment=_build_segmenter(cfg),
            consolidate=_build_consolidator(cfg),
            field_metric_overrides=tuple(
                (cfg.get("evaluation") or {}).get("field_metrics", {}).items()
            ),
            key_parts=tuple((cfg.get("evaluation") or {}).get("key_parts", [])),
        )
    except KeyError as exc:
        raise ValueError(f"Scanner config {config_path} is missing field {exc}") from exc


@lru_cache
def _registry(extra_dir: str | None) -> dict[str, ScannerProfile]:
    profiles: dict[str, ScannerProfile] = {}
    dirs = [_BUILTIN_DIR]
    if extra_dir:
        user_dir = Path(extra_dir)
        # Accept both a flat user dir and one mirroring the scanners/ split.
        dirs += [user_dir, user_dir / "scanners"]
    for directory in dirs:
        for config in sorted(directory.glob("*.json")):
            profile = load_profile(config)
            profiles[profile.name] = profile
    return profiles


def all_scanners() -> dict[str, ScannerProfile]:
    return _registry(os.getenv("MULITAMINER_SCANNERS_DIR"))


def get_scanner(name: str) -> ScannerProfile:
    scanners = all_scanners()
    try:
        return scanners[name.lower()]
    except KeyError:
        raise ValueError(f"Unknown scanner '{name}'. Available: {sorted(scanners)}")


def scanner_for(report: Path, forced: str | None = None) -> str:
    """The scanner a report belongs to: `forced` (an explicit --scanner) if
    given, else the report's parent-folder name when it is a registered scanner
    (the `resources/<scanner>/report.pdf` convention). Explicit, never guessed
    from content - raises with an actionable message when it cannot be resolved.
    """
    if forced:
        return forced.lower()
    folder = report.parent.name.lower()
    if folder in all_scanners():
        return folder
    raise ValueError(
        f"Cannot determine the scanner for '{report.name}': its folder "
        f"'{report.parent.name}' is not a known scanner {sorted(all_scanners())}. "
        f"Put the report under a scanner-named folder or pass --scanner."
    )
