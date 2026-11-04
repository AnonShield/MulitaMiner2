# Usage

## Commands

| Command | What it does |
| --- | --- |
| `mulitaminer extract REPORT.pdf -s SCANNER -m MODEL` | Full extraction into a new run directory |
| `mulitaminer extract DIR -m MODEL` | Extract every PDF in a directory (scanner auto-detected per file) |
| `mulitaminer segment REPORT.pdf -s SCANNER` | Segmentation only, offline and free |
| `mulitaminer export RUN_DIR -e FORMAT` | Generate exports from an existing run, no LLM calls |
| `mulitaminer evaluate RUN_DIR` | Score a run against a baseline XLSX (offline) |
| `mulitaminer experiment DIR --models A,B --runs N` | X runs per (model, report), local + cloud in parallel |
| `mulitaminer sync-feeds` | Download the KEV and EPSS feeds for prioritization |
| `mulitaminer prioritize RUN_DIR` | Rank a run into a remediation queue (offline) |
| `mulitaminer models` | List model profiles and their env vars |
| `mulitaminer scanners` | List available scanners |
| `mulitaminer formats` | List export formats and what consumes each |

Run any command with `--help` for all flags.

## extract

```bash
uv run mulitaminer extract report.pdf --scanner openvas --model deepseek
```

| Flag | Effect |
| --- | --- |
| `-s, --scanner` | Scanner profile (`mulitaminer scanners`); omit on a directory or single file to auto-detect |
| `-m, --model` | Model profile (`mulitaminer models`), default `deepseek` |
| `--model-name` | Provider model id override for local/OpenAI-compatible profiles |
| `-e, --export` | Extra output format, repeatable (`mulitaminer formats`) |
| `--xlsx` / `--csv` | Shorthands for `-e xlsx` / `-e csv` |
| `--output-dir` | Run artifacts root, default `outputs/runs/` |
| `--debug` | Also dump layout, blocks and raw LLM traffic |
| `--limit N` | Extract only the first N findings: tune a scanner prompt on a big report without paying for the whole run |

### Directory mode (batch)

`extract` and `experiment` both take a directory and walk it recursively. The
scanner is resolved per file, and never guessed from the PDF's content:

1. `-s/--scanner`, when given, forces one scanner for **every** file in the batch.
2. Otherwise the PDF's **parent folder name**, which must be a registered
   scanner (`mulitaminer scanners`).

Subfolders are therefore only needed when the batch mixes scanners:

```bash
# Mixed batch: one subfolder per scanner, each detected on its own
#   reports/openvas/scan-a.pdf   -> openvas
#   reports/nessus/scan-b.pdf    -> nessus
uv run mulitaminer extract reports -m deepseek

# Flat folder, one scanner: no subfolder needed, force it
uv run mulitaminer extract ~/pdfs -s openvas -m deepseek
```

A PDF whose folder is not a registered scanner fails with the list of valid
names rather than guessing. In `extract`, one failing file does not sink the
batch: it is recorded and the walk continues, except on a fatal provider error
(bad key, exhausted quota), which aborts because every later file would fail
the same way.

The same folder convention feeds evaluation: a baseline XLSX sitting next to
the PDF (`<scanner>/<stem>.pdf` + `<scanner>/<stem>.xlsx`) is picked up
automatically, which is how `experiment` scores each run.

## evaluate

```bash
uv run mulitaminer evaluate outputs/runs/<run_dir>
```

Aligns a run's records to a baseline XLSX (auto-discovered next to the source
PDF, or `--baseline`) and writes `evaluation.json` + `evaluation.md` into the
run directory: coverage (recall/precision, false negatives/false positives) and
per-field scores. Metrics are derived from the record schema: exact match for
numeric/categorical fields, set F1 for reference lists, token F1 and ROUGE-L for
text. Select with `--metrics`, list them with `--list-metrics`. BERTScore and
the NLI contradiction check need the optional eval deps (`uv sync --group
eval`); BERTScore is the heavy one, the NLI model is light enough for CPU.
Both join `--metrics all` once installed.

See [EVALUATION.md](EVALUATION.md) for what the numbers mean, the false-positive
taxonomy (invention vs duplicate), and the HTML report.

## experiment

```bash
uv run mulitaminer experiment <dir> --models deepseek,qwen2.5-1.5b --runs 5
```

Runs X extractions per (model, report) over a directory of PDFs (scanner
resolved per file, see [Directory mode](#directory-mode-batch)), evaluating
each against the baseline XLSX next to its PDF. Local and cloud
models run **in parallel** (grouped by the credential or server that enforces
rate limits). Completed runs are checkpointed, so an interrupted batch resumes
where it stopped, and a model run on another machine can be dropped into the
same tree and merged by re-invoking with both model keys (every run cached, no
API calls). Output lands under `output_experiments/<model>/<scanner>/<report>/run_<n>/`,
plus an auto-generated `report.html` (see [EVALUATION.md](EVALUATION.md)).

## Run artifacts

Each run creates `outputs/runs/<timestamp>_<input>_<model>/`:

| File | Content |
| --- | --- |
| `results.json` | Extracted records (primary artifact). Every field explained in [OUTPUT.md](OUTPUT.md) |
| `run.json` | Config snapshot, tokens, cost, duration, warnings, block_id drops, merge log, negation flags |
| `results.raw.json` | Pre-consolidation records, only when merges happened |
| `results.<format>.*` | One file per `--export` |
| `run.log` | The per-run detailed log (always written; `debug.log` at DEBUG with `--debug`) |
| `layout.txt`, `blocks.txt`, `llm_traffic.jsonl`, `debug.log` | Only with `--debug` |

## Examples

```bash
# Local model via Ollama, no API key
uv run mulitaminer extract report.pdf -s tenable -m qwen2.5-1.5b

# Multiple exports at extraction time
uv run mulitaminer extract report.pdf -s openvas -m deepseek -e sarif -e generic

# Add exports to a finished run later
uv run mulitaminer export outputs/runs/20260721T033139Z_report_deepseek -e csaf

# Extract a whole folder, scanner auto-detected per PDF
uv run mulitaminer extract resources/openvas -m deepseek

# Evaluate a run; pick metrics, or list them
uv run mulitaminer evaluate outputs/runs/<run_dir> --metrics token_f1,rouge_l
uv run mulitaminer evaluate --list-metrics

# Batch experiment: 5 runs each of two models over a folder, in parallel
uv run mulitaminer experiment resources --models deepseek,qwen2.5-1.5b --runs 5
```
