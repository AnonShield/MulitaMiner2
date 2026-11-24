"""Error taxonomy: what kind of mistake each extracted text item is.

The field metrics say how close an extraction is to the gold; this says whether
what differs was copied from elsewhere in the report, paraphrased, invented, or
left out.

Unit = one item of a list field (a paragraph, a line, a reference), over the
pairs already aligned in evaluation.json. Each extracted item is:
  correct              in the gold field (>= 80% of its word 4-grams)
  instruction_ignored  right content, but a category label the prompt says to
                       strip was kept ("cert-bund: CB-K16/1776")
  copied_off           not in the gold field, but copied from the report text
  paraphrase           in neither, but close to the gold (rescaled BERTScore >= 0.5)
  invented             in neither, and not close to the gold
Each gold item the extraction does not cover is `omitted`; `extra` counts
items of a field the gold leaves empty (also counted under their category).
0.80 is the input-faithfulness cut used for the baselines; 0.5 separates the
calibration paraphrases (~0.55-0.65) from unrelated text (~0.35). Copy
detection is exact; the paraphrase/invented split rests on that cut, so the
output keeps examples to check.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from mulitaminer.evaluation.runner import load_baseline

CATEGORIES = ["correct", "instruction_ignored", "copied_off", "paraphrase", "invented", "omitted", "extra"]
CONTAIN = 0.80
CLOSE = 0.50
NGRAM = 4
SKIP_FIELDS = {"name"}
PLACEHOLDER = re.compile(r"^\s*(n/?a|not applicable|none|-)\s*$", re.IGNORECASE)
# "cert-bund: CB-K16/1776" vs gold "CB-K16/1776": the label is format, not content
REF_LABEL = re.compile(r"^\s*(?!https?:)[a-z][a-z0-9 _-]{0,15}:\s*(?=\S)", re.IGNORECASE)


def _tokens(text: str) -> list[str]:
    # join hyphens inside words on both sides: the PDF keeps line-wrap hyphens
    # ("unau-thorized") that the scanner export does not
    return re.findall(r"[a-z0-9]+", re.sub(r"(?<=[a-z])-\s*(?=[a-z])", "", text.lower()))


def _grams(toks: list[str]) -> set[tuple]:
    return {tuple(toks[i:i + NGRAM]) for i in range(len(toks) - NGRAM + 1)}


class _Ref:
    """A reference text indexed for containment checks."""

    def __init__(self, text: str):
        self.toks = _tokens(text)
        self.joined = " " + " ".join(self.toks) + " "
        self.grams = _grams(self.toks)
        self.compact = "".join(self.toks)

    def contains(self, item: str) -> float:
        t = _tokens(item)
        if not t:
            return 1.0
        # a URL or id the PDF wrapped mid-token: compare without separators
        if " " not in item.strip() and "".join(t) in self.compact:
            return 1.0
        if len(t) < NGRAM:  # too short for 4-grams: exact word sequence
            return 1.0 if " " + " ".join(t) + " " in self.joined else 0.0
        g = _grams(t)
        return len(g & self.grams) / len(g)


def _items(value) -> list[str]:
    if value is None:
        return []
    raw = value if isinstance(value, list) else str(value).splitlines()
    out = []
    for v in raw:
        s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        if s.strip() and not PLACEHOLDER.match(s):
            out.append(s.strip())
    return out


def _unlabel(item: str, field: str) -> str:
    return REF_LABEL.sub("", item).strip() if field == "references" else item


def classify_run(run_dir: Path, baseline: Path, report_text: str, similarity=None) -> dict:
    """Counts per field and category, plus examples. `similarity` scores
    (item, reference) pairs; defaults to the rescaled BERTScore."""
    if similarity is None:
        from mulitaminer.evaluation.scorers import _bertscore_batch as similarity
    ev = json.loads((run_dir / "evaluation.json").read_text(encoding="utf-8"))
    ext = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    gold, _ = load_baseline(Path(baseline))
    report = _Ref(report_text)

    fields = sorted({f for p in ev["pairs"] for f, m in p["scores"].items()
                     if "token_f1" in m or "set_f1" in m} - SKIP_FIELDS)
    counts: dict[str, Counter] = defaultdict(Counter)
    examples: dict[str, list] = defaultdict(list)
    pending = []  # (field, category if close, category if not, item, reference text)

    for p in ev["pairs"]:
        e_row, g_row = ext[p["extraction_index"]], gold[p["baseline_index"]]
        for f in fields:
            e_items = _items(e_row.get(f))
            g_items = [_unlabel(it, f) for it in _items(g_row.get(f))]
            if not e_items and not g_items:
                continue
            # coverage of gold items ignores labels: a kept label is an ignored instruction, not an omission
            g_ref, e_ref = _Ref("\n".join(g_items)), _Ref("\n".join(_unlabel(it, f) for it in e_items))
            for it in e_items:
                if not g_items:
                    counts[f]["extra"] += 1
                if g_items and g_ref.contains(it) >= CONTAIN:
                    counts[f]["correct"] += 1
                elif g_items and _unlabel(it, f) != it and g_ref.contains(_unlabel(it, f)) >= CONTAIN:
                    counts[f]["instruction_ignored"] += 1
                    examples[f"{f}/instruction_ignored"].append(it[:200])
                elif report.contains(it) >= CONTAIN:
                    counts[f]["copied_off"] += 1
                    examples[f"{f}/copied_off"].append(it[:200])
                elif g_items:
                    pending.append((f, "paraphrase", "invented", it, "\n".join(g_items)))
                else:
                    counts[f]["invented"] += 1
                    examples[f"{f}/invented"].append(it[:200])
            for it in g_items:
                if e_items and e_ref.contains(it) >= CONTAIN:
                    continue
                if e_items:  # maybe covered by a paraphrase: decided below
                    pending.append((f, None, "omitted", it, "\n".join(e_items)))
                else:
                    counts[f]["omitted"] += 1

    if pending:
        scores = similarity([(it, ref) for _, _, _, it, ref in pending])
        for (f, close_cat, far_cat, it, _), s in zip(pending, scores):
            cat = close_cat if s >= CLOSE else far_cat
            if cat:
                counts[f][cat] += 1
                examples[f"{f}/{cat}"].append(f"[{s:.2f}] {it[:200]}")
    return {"thresholds": {"contain": CONTAIN, "close": CLOSE, "ngram": NGRAM},
            "counts": {f: dict(c) for f, c in counts.items()},
            "examples": {k: v[:5] for k, v in examples.items()}}


def write_errors(run_dir: Path, result: dict) -> Path:
    path = Path(run_dir) / "errors.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


__all__ = ["CATEGORIES", "classify_run", "write_errors"]
