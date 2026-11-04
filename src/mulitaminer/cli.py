"""Command-line interface. Thin consumer of the mulitaminer library."""
from __future__ import annotations

import logging
from pathlib import Path

import typer
from dotenv import load_dotenv

from mulitaminer import settings, ui
from mulitaminer.llm import FatalLLMError, all_models
from mulitaminer.scanner_engine import all_scanners

app = typer.Typer(
    name="mulitaminer",
    help="Extract structured vulnerability records from security-scanner PDF reports using LLMs",
    no_args_is_help=True,
)


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


@app.command()
def extract(
    report: Path = typer.Argument(
        ..., exists=True, readable=True,
        help="Scanner PDF report, or a directory of PDFs",
    ),
    scanner: str | None = typer.Option(
        None, "--scanner", "-s",
        help="Force a scanner; omit to use the report's parent-folder name",
    ),
    model: str = typer.Option("deepseek", "--model", "-m", help="See `mulitaminer models`"),
    model_name: str | None = typer.Option(
        None, "--model-name", help="Provider model id override (for ollama/lmstudio)"
    ),
    export: list[str] = typer.Option(
        [], "--export", "-e",
        help="Extra output formats (repeatable). See `mulitaminer formats`.",
    ),
    xlsx: bool = typer.Option(False, "--xlsx", help="Shorthand for --export xlsx"),
    csv: bool = typer.Option(False, "--csv", help="Shorthand for --export csv"),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Run artifacts root"),
    debug: bool = typer.Option(False, "--debug", help="Dump layout/blocks/LLM traffic to the run dir"),
    limit: int | None = typer.Option(
        None, "--limit", min=1,
        help="Extract only the first N findings (tune a prompt on a big report)",
    ),
) -> None:
    """Extract vulnerabilities from REPORT (file or directory) into run directories."""
    _setup_logging(debug)
    load_dotenv()
    from mulitaminer.pipeline import RunConfig, run, run_directory

    config = RunConfig(
        input_path=report,
        scanner=scanner,
        model=model,
        model_name=model_name,
        formats=tuple(dict.fromkeys(
            list(export) + (["xlsx"] if xlsx else []) + (["csv"] if csv else [])
        )),
        output_dir=output_dir,
        debug=debug,
        limit=limit,
    )

    if report.is_dir():
        try:
            summaries = run_directory(config)
        except (FatalLLMError, ValueError) as exc:
            ui.error(exc)
            raise typer.Exit(code=1)
        ok = [s for s in summaries if s["status"] == "ok"]
        for s in summaries:
            style = {"ok": "green", "skipped": "yellow"}.get(s["status"], "red")
            ui.echo(
                f"{s['status']:<8} {s['file']:<45} {s['scanner'] or '-':<9} {s['detail']}",
                style=style,
            )
        total_cost = sum(s.get("cost_usd", 0.0) for s in ok)
        ui.echo(
            f"\n{len(ok)} extracted, "
            f"{sum(s['status'] == 'skipped' for s in summaries)} skipped, "
            f"{sum(s['status'] == 'failed' for s in summaries)} failed; "
            f"total ${total_cost:.4f}"
        )
        raise typer.Exit(code=0 if ok else 1)

    from mulitaminer.scanner_engine import scanner_for

    try:
        config.scanner = scanner_for(report, scanner)
    except ValueError as exc:
        ui.error(exc)
        raise typer.Exit(code=1)

    # --debug keeps the full console log; otherwise a live one-liner with the
    # console log quieted (the detail still lands in the per-run log file).
    progress = ui.Progress() if debug else ui.extract_view(config.model, report.name)
    try:
        if isinstance(progress, ui.ExtractView):
            with ui.quiet_logging(), progress:
                result, run_dir = run(config, progress=progress)
        else:
            result, run_dir = run(config, progress=progress)
    except (FatalLLMError, ValueError) as exc:
        ui.error(exc)
        raise typer.Exit(code=1)

    ui.echo(
        f"\n{len(result.records)} records ({result.block_count} blocks) in "
        f"{result.duration_s}s; ${result.usage.cost_usd:.4f} "
        f"({result.usage.prompt_tokens}+{result.usage.completion_tokens} tokens, "
        f"{result.usage.calls} calls)"
    )
    total_drops = sum(result.drops.values())
    detail = ", ".join(f"{k}={v}" for k, v in result.drops.items())
    if total_drops:
        ui.warn(f"block_id drops: {total_drops} ({detail})")
    else:
        ui.echo(f"block_id drops: 0 (clean) - {detail}")
    if result.warnings:
        ui.warn(f"{len(result.warnings)} warning(s):")
        for w in result.warnings:
            ui.warn(f"  - {w}")
    ui.echo(f"Artifacts: {run_dir}")


@app.command()
def models() -> None:
    """List available model profiles (built-in + MULITAMINER2_LLMS_DIR)."""
    for key, p in all_models().items():
        kind = "local " if p.is_local else "cloud "
        keys = p.api_key_env or "no key needed"
        ui.echo(f"{key:<16} {kind} {p.model:<28} {keys}")


@app.command()
def schema() -> None:
    """Print the effective unified output schema: every column, its type, and
    where it comes from (the shared core, or the scanner config that declares it).

    The schema is assembled at runtime (core fields in code + config-declared
    fields), so this is the single place to inspect the whole picture."""
    import typing

    from mulitaminer.models import VulnRecord
    from mulitaminer.writers import unified_columns

    def by_col(record_type) -> dict:
        return {(f.alias or name): f for name, f in record_type.model_fields.items()}

    def typename(annotation) -> str:
        if typing.get_args(annotation):
            return str(annotation).replace("typing.", "")
        return getattr(annotation, "__name__", str(annotation))

    core = by_col(VulnRecord)
    annotation = {col: f.annotation for col, f in core.items()}
    origin: dict[str, list[str]] = {}
    for name, profile in all_scanners().items():
        for col, f in by_col(profile.record_type).items():
            if col not in core:
                annotation.setdefault(col, f.annotation)
                origin.setdefault(col, [])
                if name not in origin[col]:
                    origin[col].append(name)

    ui.echo("Unified output schema (identical columns for every scanner):", style="bold")
    for col in unified_columns():
        source = "core" if col in core else "+".join(origin.get(col, []))
        ui.echo(f"  {col:<26} {typename(annotation.get(col)):<20} {source}")


@app.command()
def segment(
    report: Path = typer.Argument(..., exists=True, readable=True, help="Scanner PDF report"),
    scanner: str = typer.Option(..., "--scanner", "-s", help="See `mulitaminer scanners`"),
    show: int = typer.Option(3, "--show", help="How many blocks to preview"),
    lines: int = typer.Option(6, "--lines", help="Preview lines per block"),
) -> None:
    """Segment REPORT into blocks WITHOUT calling any LLM (free, offline).

    The config-writing feedback loop (docs/SCANNER_CONFIGS.md): the block
    count must equal the report's finding count.
    """
    _setup_logging(debug=False)
    from mulitaminer.pdf_reader import extract_pdf
    from mulitaminer.scanner_engine import get_scanner

    profile = get_scanner(scanner)
    doc = extract_pdf(report)
    blocks = profile.segment(doc.text)
    ui.echo(f"\n{len(blocks)} blocks found in {report.name}", style="bold")
    for block in blocks[:show]:
        context = ", ".join(
            f"{k}={v}" for k, v in
            (("host", block.host), ("port", block.port),
             ("protocol", block.protocol), ("severity", block.severity_hint))
            if v is not None
        )
        ui.echo(f"\n--- BLOCK {block.id} ({context or 'no context'}) ---", style="cyan")
        for line in block.text.splitlines()[:lines]:
            ui.echo(f"  {line}")
    if len(blocks) > show:
        ui.echo(f"\n... {len(blocks) - show} more blocks (use --show to see more)")


@app.command()
def export(
    results: Path = typer.Argument(
        ..., exists=True, help="A results.json or a run directory containing one"
    ),
    formats: list[str] = typer.Option(
        ..., "--export", "-e", help="Formats to generate (repeatable). See `mulitaminer formats`."
    ),
) -> None:
    """Generate exports from an existing results.json. No LLM calls."""
    import json

    from mulitaminer.exporters import get_exporter
    from mulitaminer.models import record_type_for_source

    path = results / "results.json" if results.is_dir() else results
    data = json.loads(path.read_text(encoding="utf-8"))
    record_type = record_type_for_source(data[0].get("source") if data else None)
    records = [record_type.model_validate(r) for r in data]
    for fmt in formats:
        out = get_exporter(fmt)(records, record_type, path.parent)
        ui.echo(f"{fmt}: {out}")


@app.command()
def evaluate(
    target: Path | None = typer.Argument(
        None, help="A run directory (results.json + run.json) or a results.json file"
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b",
        help="Baseline XLSX (required for a bare results.json; otherwise auto-discovered)",
    ),
    metrics: str = typer.Option(
        "all", "--metrics",
        help="Text metrics to run: 'all' or comma-separated (token_f1,rouge_l,bertscore)",
    ),
    threshold: float = typer.Option(
        settings.DEFAULT_ALIGN_THRESHOLD, "--threshold",
        help="Alignment similarity cutoff",
    ),
    list_metrics: bool = typer.Option(
        False, "--list-metrics", help="List the metric registry and exit"
    ),
) -> None:
    """Score an existing extraction against a baseline. Never runs extraction."""
    from mulitaminer.evaluation import evaluate_run
    from mulitaminer.evaluation.report import summary_table, write_reports
    from mulitaminer.evaluation.scorers import SCORERS

    if list_metrics:
        for s in SCORERS.values():
            status = "available" if s.available else f"UNAVAILABLE - {s.hint}"
            ui.echo(f"{s.name:<10} {s.kind:<11} {status}")
        return
    if target is None:
        ui.error("provide a run directory or results.json (or --list-metrics).")
        raise typer.Exit(code=1)

    if (Path(target) / "experiment.json").is_file():  # whole-experiment re-eval
        from mulitaminer.experiment import evaluate_experiment

        ev = evaluate_experiment(Path(target), metrics=metrics, force=True,
                                 threshold=threshold)
        skipped = f", {ev['failed']} skipped (no baseline)" if ev["failed"] else ""
        ui.echo(f"\nRe-evaluated {ev['evaluated']} run(s) across {ev['runs']} "
                f"total{skipped}.", style="bold")
        if ev.get("report"):
            ui.echo(f"report: {ev['report']}")
        return

    try:
        result = evaluate_run(target, baseline=baseline, metrics=metrics,
                              threshold=threshold)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        ui.error(exc)
        raise typer.Exit(code=1)

    results_path = Path(result.meta["results"])
    paths = write_reports(result, results_path.parent)
    cov = result.coverage
    fn, fp = len(cov["false_negatives"]), len(cov["false_positives"])
    ui.echo(
        f"\nCoverage: {cov['matched']}/{cov['baseline_count']} matched "
        f"(recall {cov['recall']:.3f}, precision {cov['precision']:.3f}); "
        f"{fn} false negative{'s' * (fn != 1)}, {fp} false positive{'s' * (fp != 1)}",
        style="bold",
    )
    if cov.get("false_positive_kinds"):
        kinds = ", ".join(f"{n} {k}" for k, n in sorted(cov["false_positive_kinds"].items()))
        ui.echo(f"  false-positive breakdown: {kinds}")
    ui.echo(f"\n{summary_table(result)}\n")
    for kind, path in paths.items():
        ui.echo(f"{kind}: {path}")


@app.command()
def experiment(
    reports: Path = typer.Argument(
        ..., exists=True, help="A PDF, or a directory searched recursively for PDFs"
    ),
    models: str = typer.Option(..., "--models", help="Comma-separated model keys"),
    runs: int = typer.Option(..., "--runs", help="Runs per (model, report)"),
    scanner: str | None = typer.Option(
        None, "--scanner", "-s", help="Force a scanner; omit to use each report's parent-folder name"
    ),
    metrics: str = typer.Option("all", "--metrics", help="Metrics for per-run evaluation"),
    output_dir: Path = typer.Option(Path("output_experiments"), "--output-dir"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Keep the full per-chunk log on the console"
    ),
) -> None:
    """Run X extractions per (model, report), local and API models in parallel."""
    import json

    _setup_logging(debug=False)
    load_dotenv()
    from mulitaminer.experiment import ExperimentConfig, run_experiment

    pdfs = sorted(reports.rglob("*.pdf")) if reports.is_dir() else [reports]
    if not pdfs:
        ui.error(f"No PDFs under {reports}")
        raise typer.Exit(code=1)

    config = ExperimentConfig(
        reports=pdfs,
        models=[m.strip() for m in models.split(",") if m.strip()],
        runs=runs,
        scanner=scanner,
        metrics=metrics,
        output_dir=output_dir,
        verbose=verbose,
    )
    result = run_experiment(config)
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    t = manifest["totals"]
    ui.echo(
        f"\n{t['done']}/{t['planned']} runs done, {t['failed']} failed, "
        f"{t['skipped_reports']} reports skipped; "
        f"{t['active_seconds']}s active, ${t['cost_usd']:.4f}",
        style="bold",
    )
    ui.echo(f"Manifest: {result['manifest']}")
    if result.get("report"):
        ui.echo(f"Report:   {result['report']}")


@app.command()
def report(
    experiment_dir: Path = typer.Argument(
        ..., exists=True, help="An experiment directory (containing experiment.json)"
    ),
) -> None:
    """Build the self-contained HTML report from an experiment tree."""
    from mulitaminer.experiment_report import build_report

    out = build_report(experiment_dir)
    ui.echo(f"Report: {out}")


@app.command("sync-feeds")
def sync_feeds_cmd() -> None:
    """Download the KEV and EPSS feeds for prioritization (~5 MB, daily data)."""
    from mulitaminer.prioritization import sync_feeds
    from mulitaminer.settings import FEEDS_DIR

    meta = sync_feeds()
    ui.echo(f"Synced to {FEEDS_DIR.resolve()}: {meta['kev_count']} KEV entries, "
            f"{meta['epss_count']} EPSS scores (score date {meta['epss_score_date']})")


@app.command()
def prioritize(
    results: Path = typer.Argument(
        ..., exists=True, help="A results.json or a run directory containing one"
    ),
) -> None:
    """Rank a run's findings into a remediation queue (KEV/EPSS/SSVC, offline)."""
    from mulitaminer.prioritization import prioritize_run

    try:
        paths = prioritize_run(results)
    except ValueError as exc:
        ui.error(exc)
        raise typer.Exit(code=1)
    for kind, path in paths.items():
        ui.echo(f"{kind}: {path}")


@app.command()
def formats() -> None:
    """List available export formats for --export."""
    from mulitaminer.exporters import DESCRIPTIONS, EXPORTERS

    for name in sorted(EXPORTERS):
        ui.echo(f"{name:<9} {DESCRIPTIONS.get(name, '')}")


@app.command()
def scanners() -> None:
    """List available scanner profiles (built-in + MULITAMINER_SCANNERS_DIR)."""
    for key, p in all_scanners().items():
        ui.echo(f"{key:<10} source={p.source:<11} max_vulns_per_chunk={p.max_vulns_per_chunk}")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="0.0.0.0 to accept other machines"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload", help="Restart on Python edits (development)"),
    proxy_headers: bool = typer.Option(
        False, "--proxy-headers",
        help="Behind a reverse proxy: take the client address from X-Forwarded-For"),
) -> None:
    """Serve the browser front end (docs/WEB.md). Needs `uv sync --group web`."""
    try:
        import uvicorn
    except ImportError:
        ui.error("the web front end is not installed: uv sync --group web")
        raise typer.Exit(code=1)
    ui.echo(f"MulitaMiner web on http://{host}:{port}  (Ctrl+C to stop)")
    # No access log: the job link in the URL is also that job's decryption key.
    uvicorn.run("mulitaminer.web.app:app", host=host, port=port, reload=reload,
                access_log=False, proxy_headers=proxy_headers,
                forwarded_allow_ips="*" if proxy_headers else None)


if __name__ == "__main__":
    app()
