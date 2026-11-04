"""End-to-end run: read -> segment -> extract -> consolidate -> write.

All intermediate state is in memory (spec §10). Disk is touched only for the
final run artifacts under outputs/runs/<timestamp>_<input>_<model>/ and, with
debug=True, inspection dumps in the same directory.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from mulitaminer import settings
from mulitaminer.extraction import extract_blocks
from mulitaminer.llm import FatalLLMError, LLMClient, get_model
from mulitaminer.models import RunResult, TokenUsage, full_drops, full_retries
from mulitaminer.pdf_reader import extract_pdf
from mulitaminer.scanner_engine import get_scanner, scanner_for
from mulitaminer.exporters import get_exporter
from mulitaminer.ui import NULL_PROGRESS, Progress
from mulitaminer.writers import write_json

log = logging.getLogger(__name__)


class _ThreadFilter(logging.Filter):
    """Keep only records emitted from one run's thread, so concurrent runs
    writing their own per-run log never cross-contaminate."""

    def __init__(self, ident: int):
        super().__init__()
        self.ident = ident

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread == self.ident


@dataclass
class RunConfig:
    input_path: Path
    scanner: str | None                # None = auto-detect (directory mode)
    model: str
    model_name: str | None = None      # override for generic local profiles
    formats: tuple[str, ...] = ()      # extra exports (see exporters registry)
    output_dir: Path | None = None     # default: settings.OUTPUTS_DIR
    debug: bool = False
    limit: int | None = None           # keep only the first N blocks (prompt tuning)

    def snapshot(self) -> dict:
        return {
            "input": str(self.input_path),
            "scanner": self.scanner,
            "model": self.model,
            "model_name": self.model_name,
            "formats": list(self.formats),
            "debug": self.debug,
            "limit": self.limit,
        }


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)


def _make_run_dir(config: RunConfig) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = config.output_dir or settings.OUTPUTS_DIR
    run_dir = root / f"{stamp}_{_slug(config.input_path.stem)}_{_slug(config.model)}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def run_directory(config: RunConfig, client: LLMClient | None = None) -> list[dict]:
    """Extract every PDF in the directory ``config.input_path``.

    Per file: resolve the scanner (config.scanner forces one for the whole
    batch; otherwise each report's parent-folder name, the
    `resources/<scanner>/report.pdf` convention), then run the normal pipeline
    into its own run dir. A failing file is recorded and the batch continues,
    EXCEPT for FatalLLMError (bad key/quota): every subsequent file would fail
    the same way, so the batch aborts.

    Returns one summary dict per PDF: file, status (ok|failed), scanner,
    detail, and run_dir/cost_usd when extracted.
    """
    pdfs = sorted(config.input_path.rglob("*.pdf"))
    if not pdfs:
        raise ValueError(f"No PDF files in {config.input_path}")

    summaries: list[dict] = []
    for pdf in pdfs:
        entry = {"file": pdf.name, "status": "failed", "scanner": config.scanner,
                 "detail": ""}
        summaries.append(entry)
        scanner_name = config.scanner
        try:
            scanner_name = scanner_for(pdf, config.scanner)
            result, run_dir = run(replace(config, input_path=pdf,
                                          scanner=scanner_name), client=client)
            entry.update(
                status="ok", scanner=scanner_name, run_dir=str(run_dir),
                cost_usd=result.usage.cost_usd,
                detail=f"{len(result.records)} records in {result.duration_s}s",
            )
        except FatalLLMError:
            entry["detail"] = "fatal provider error; batch aborted"
            raise
        except Exception as exc:  # one bad file must not sink the batch
            entry["scanner"] = scanner_name
            entry["detail"] = f"{type(exc).__name__}: {exc}"
            log.error("%s: failed (%s)", pdf.name, entry["detail"])
    return summaries


def run(config: RunConfig, client: LLMClient | None = None,
        run_dir: Path | None = None, doc=None,
        progress: Progress | None = None) -> tuple[RunResult, Path]:
    """Execute one extraction run. Returns (result, run directory).

    ``run_dir`` pins the output location (experiment harness). ``doc`` supplies
    an already-extracted document, so a caller can extract a PDF once and reuse
    it across runs (pdfium is not thread-safe, so this also avoids concurrent
    extraction of the same file). ``progress`` receives lifecycle events for a
    live view; the default sink does nothing."""
    started = time.perf_counter()
    progress = progress or NULL_PROGRESS
    profile = get_scanner(config.scanner)
    if client is None:
        client = LLMClient(get_model(config.model), model_name=config.model_name)

    if run_dir is None:
        run_dir = _make_run_dir(config)
    else:
        run_dir.mkdir(parents=True, exist_ok=True)
    # A per-run log is always written (debug.log at DEBUG with --debug, else
    # run.log at INFO), so the detailed per-chunk trace survives even when the
    # console is quiet. A thread filter keeps concurrent experiment runs apart.
    name, level = ("debug.log", logging.DEBUG) if config.debug else ("run.log", logging.INFO)
    file_handler = logging.FileHandler(run_dir / name, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    file_handler.addFilter(_ThreadFilter(threading.get_ident()))
    logging.getLogger().addHandler(file_handler)

    try:
        progress.stage("reading")
        if doc is None:
            doc = extract_pdf(config.input_path)
        progress.stage("segmenting")
        blocks = profile.segment(doc.text)
        if not blocks:
            raise ValueError(
                f"No finding blocks found in {config.input_path.name} with the "
                f"'{profile.name}' scanner profile; wrong --scanner?"
            )
        log.info("Segmented %d finding blocks", len(blocks))
        if config.limit and config.limit < len(blocks):
            log.info("Keeping the first %d of %d blocks (--limit)", config.limit, len(blocks))
            blocks = blocks[:config.limit]
        progress.segmented(len(blocks))

        usage = TokenUsage()
        debug_sink: list | None = [] if config.debug else None
        drops: Counter = Counter()
        retries: Counter = Counter()
        records, warnings, negation_flags = extract_blocks(
            blocks, profile, client, usage, debug_sink,
            progress=progress, drops=drops, retries=retries)
        raw_count = len(records)
        raw_records = list(records)
        records, merge_log = profile.consolidate(records)
        log.info(
            "Extracted %d/%d blocks; %d records after consolidation",
            raw_count, len(blocks), len(records),
        )

        result = RunResult(
            records=records,
            warnings=warnings,
            drops=full_drops(drops),
            retries=full_retries(retries),
            usage=usage,
            duration_s=round(time.perf_counter() - started, 2),
            block_count=len(blocks),
            chunk_count=0,  # informational; per-round chunking varies
            config=config.snapshot(),
        )

        write_json(records, run_dir / "results.json")
        if merge_log:
            # Consolidation changed something: keep the pre-consolidation
            # records so every merge decision stays auditable offline.
            write_json(raw_records, run_dir / "results.raw.json")
        for fmt in config.formats:
            get_exporter(fmt)(records, profile.record_type, run_dir)

        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "config": result.config,
                    "runtime": client.runtime_info(),
                    "block_count": result.block_count,
                    "raw_record_count": raw_count,
                    "final_record_count": len(records),
                    "usage": usage.model_dump(),
                    "duration_s": result.duration_s,
                    "warnings": warnings,
                    "drops": full_drops(drops),
                    "retries": full_retries(retries),
                    "merge_log": merge_log,
                    "negation_flags": negation_flags,
                    "pdf": {"pages": doc.page_count, "backend": doc.backend},
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        if config.debug:
            (run_dir / "layout.txt").write_text(doc.text, encoding="utf-8")
            (run_dir / "blocks.txt").write_text(
                "\n\n".join(f"--- BLOCK {b.id} (host={b.host} port={b.port}/"
                            f"{b.protocol} sev={b.severity_hint}) ---\n{b.text}"
                            for b in blocks),
                encoding="utf-8",
            )
            with (run_dir / "llm_traffic.jsonl").open("w", encoding="utf-8") as fh:
                for entry in debug_sink or []:
                    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return result, run_dir
    finally:
        if file_handler:
            logging.getLogger().removeHandler(file_handler)
            file_handler.close()
