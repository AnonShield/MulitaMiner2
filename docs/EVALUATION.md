# Evaluation

How `evaluate` and `experiment` score an extraction against a baseline, what the
numbers mean, and what the HTML report shows.

![Evaluation flow](imgs/evaluation.svg)

## What gets produced

- `evaluate` writes `evaluation.json` (machine) and `evaluation.md` (human) into
  the run directory.
- `experiment` evaluates every run the same way and builds a self-contained
  `report.html` over the whole tree.
- The full output layout (records, run.json, evaluation files) and every field's
  meaning are documented in [OUTPUT.md](OUTPUT.md).

## Coverage

The baseline XLSX is the gold standard, one row per finding. Coverage aligns the
extracted records to those rows and reports:

| Field | Meaning |
| --- | --- |
| `matched` | extracted records paired to a baseline row |
| `recall` | matched / baseline_count (how much of the baseline was recovered) |
| `precision` | matched / extraction_count (how much of the extraction is in the baseline) |
| `false_negatives` | baseline rows with no extracted match |
| `false_positives` | extracted records with no baseline match |

Coverage measures **alignment fidelity**, not invention. Extraction is
block-anchored (one record per finding block, count fixed before any LLM call),
so the model cannot invent a vulnerability from nothing. A false positive is
therefore almost always a record whose identity did not line up with its baseline
twin, not a hallucination.

## Alignment

Each (extraction, baseline) pair is scored by a composite key and a fuzzy name
match, then the globally optimal 1-to-1 assignment is solved (Hungarian,
`scipy.linear_sum_assignment`) and cut at a threshold (0.70).

- Composite key = normalized name plus scanner-specific parts (OpenVAS:
  port+protocol; Tenable: severity+plugin).
- Matching keys score the key match; conflicting keys penalize the name score,
  so two findings on different ports do not accidentally pair.
- A pair below 0.70 is dropped: its extraction side becomes a false positive and
  its baseline side a false negative.

## False positives, classified

Every false positive carries a `category` (`false_positive_kinds` totals them,
`false_positive_detail` lists each with its closest baseline row):

- **invention**: no baseline row is its counterpart. This is relative to the
  baseline, not a claim it was fabricated. With block-anchoring these are usually
  a real report finding the baseline lacks, or the same finding with a diverged
  name; a high `best_similarity` points to the latter.
- **duplicate**: the same finding (identical composite key) was extracted more
  than once while the baseline has it once.

`best_baseline`/`best_similarity` give the closest baseline row for context, so a
name-diverged false positive (high similarity) is easy to tell from a genuinely
unrelated one (low similarity).

A false negative is the mirror image: a baseline finding the extraction did not
recover (or recovered under a name too different to align).

## Per-field metrics

Only matched pairs are scored, field by field. Each field's metric is derived
from its type in the record schema, so a field is measured with the tool that
fits its shape.

### Which metric each field gets

| Fields | Metric | Why |
| --- | --- | --- |
| `severity`, `port`, `protocol`, `plugin`, `cvss` (OpenVAS) | `exact` | one correct value; partial credit is meaningless. Case- and format-insensitive (`TCP` = `tcp`, `8019` = `8019.0`). `protocol` is a free str, so each scanner config forces `exact` via `field_metrics` rather than the inferred text metric. |
| `references` | `set_f1_ids` | an unordered set of ids: `set_f1_ids` canonicalizes each item to its identifier (`CVE-...`, `CWE-N`, `BID-N`) and scores the sets, so `cve: CVE-1` vs `CVE-1` is not a miss. The strict `set_f1` (format-sensitive) is recorded alongside so the report shows whether a gap is content or just formatting. |
| `cvss` (Tenable, a list of vectors) | `set_f1` | an unordered list of vector strings, scored as a set. |
| `plugin_details`, `instances` (Tenable) | `structural` | a nested object / list of objects: recurse and score each sub-field. |
| `name`, `description`, `solution`, `impact`, `insight`, `detection_result`, `detection_method`, `product_detection_result`, `log_method`, `instances` (OpenVAS) | `text` | free prose: no single right string, so measure with the text metrics below. |

`exact`, `set_f1`, `set_f1_ids`, and `structural` are structural metrics: they
always run. `references` gets `set_f1_ids` as a by-name default (a set of ids)
that a scanner config can still override.

### What each text metric measures, and why more than one

Prose fields are judged from several angles because each metric has a blind spot:

- **`token_f1`**: bag-of-words overlap (precision/recall/F1 over tokens). Cheap
  and order-insensitive; a floor that says "roughly the same words".
- **`rouge_l`**: longest common subsequence, so it rewards preserved word
  **order** and phrasing, which `token_f1` ignores.
- **`bertscore`**: semantic similarity from contextual embeddings, so it credits
  a paraphrase (same meaning, different words) that token overlap would miss.
  Rescaled with the BERTScore baseline (`rescale_with_baseline`), so unrelated
  text scores near 0 instead of ~0.85 (floored at 0, an omission's score). The order of individual pairs is
  unchanged, but field means can reorder models: presence-rule pairs stay at 0
  or 1, so a paraphrase now weighs against a verbatim copy on the same footing
  as an omission does (raw, unrelated text scored 0.86 while an omission scored
  0). Older
  evaluations without `meta.bertscore_rescaled` are raw; convert them with
  `tools/rescale_bertscore.py`. Optional and heavy (`uv sync --group eval`).
- **`nli`**: a contradiction check. It is the safety net for `bertscore`'s blind
  spot: an extraction that negates the baseline ("does not use a weak
  algorithm") shares almost every token, so `bertscore` scores it very high, yet
  the meaning is the opposite. `nli` flags it. The model is
  `cross-encoder/nli-deberta-v3-xsmall`, picked over lighter and heavier
  candidates by benchmarking on synthetic negation flips of real scanner
  sentences (AUC 0.986, ~45 pairs/s on CPU). The score is
  `1 - max P(contradiction)` over the baseline's sentences; whitespace-identical
  pairs short-circuit to 1.0 without the model, and it also catches non-negation
  factual flips (a swapped version number or CVE id) that every other text
  metric misses. Optional (`uv sync --group eval`), but light enough to run on
  CPU.

So `bertscore` measures fidelity of wording; `nli` guards against a fluent,
similar-looking record that flipped the meaning. They are complementary, not
interchangeable (see the negation blind spot documented for embedding metrics,
e.g. [arXiv:2307.13989](https://arxiv.org/abs/2307.13989)).

The HTML report lists whichever text metrics a run actually scored, so
`bertscore` and `nli` appear once you evaluate with them.

Empty-vs-empty scores a vacuous 1.0 (flagged so reports can count it apart);
present-vs-absent scores 0.0. A written-out "no value" (`N/A`, `NA`,
`Not applicable.`) counts as empty on both sides, so a model that transcribes
Qualys's `N/A` faithfully is not scored against a blank baseline cell. This
applies to text fields only, never to `name` (alignment keys on it) or to
literal fields such as Nessus severity `None`.

## The HTML report (experiment)

`report.html` is self-contained (inline SVG, no network). It shows:

- model ranking by mean recall (fixed 0-1 scale) with run-to-run spread,
- per-field measured means across models,
- score distribution per report,
- false negatives vs false positives per model (mean/run),
- cost and latency per model, and a cost-vs-recall Pareto view.
