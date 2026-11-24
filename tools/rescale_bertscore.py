"""Convert raw BERTScores in existing evaluation.json files to the rescaled scale.

Rescaling is linear per pair, (raw - b) / (1 - b), so stored scores convert
exactly without re-running the model. Presence-rule pairs (empty x empty = 1.0
vacuous, one side empty = 0.0) never went through BERT and are kept.

usage: python tools/rescale_bertscore.py PATH... [--in-place]
  PATH: evaluation.json files or directories searched recursively.
  Default writes evaluation.rescaled.json next to each file; --in-place
  replaces evaluation.json (the raw one is kept as evaluation.bertscore_raw.json).
Standard library only, so it runs on hosts without the eval extras.
"""
import json
import shutil
import statistics
import sys
from pathlib import Path

# F baseline of roberta-large, layer 17 (bert_score rescale_baseline/en/roberta-large.tsv)
BASELINE_F = 0.83122575


def rescale(score: float) -> float:
    """Same as the scorer: rescaled, floored at 0 (an omission's score)."""
    return max(0.0, (score - BASELINE_F) / (1 - BASELINE_F))


def convert(ev: dict) -> int:
    """Rescale BERT-computed pair scores and rebuild the field stats; returns pairs changed."""
    changed = 0
    per_field: dict[str, list[tuple[float, bool]]] = {}
    for pair in ev.get("pairs", []):
        for field, metrics in pair.get("scores", {}).items():
            m = metrics.get("bertscore")
            if m is None:
                continue
            if not m["vacuous"] and m["score"] > 0:  # 0.0 = one side empty, not scored by BERT
                m["score"] = rescale(m["score"])
                changed += 1
            per_field.setdefault(field, []).append((m["score"], m["vacuous"]))
    for field, pairs in per_field.items():
        st = ev["fields"][field]["bertscore"]
        values = [v for v, _ in pairs]
        measured = [v for v, vac in pairs if not vac]
        st.update({
            "mean": round(statistics.fmean(values), 4),
            "measured_mean": round(statistics.fmean(measured), 4) if measured else None,
            "min": round(min(values), 4),
            "std": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
        })
    ev.setdefault("meta", {})["bertscore_rescaled"] = True
    return changed


def main(argv: list[str]) -> None:
    in_place = "--in-place" in argv
    paths = [Path(a) for a in argv if a != "--in-place"]
    files = [f for p in paths for f in ([p] if p.is_file() else p.rglob("evaluation.json"))]
    for f in files:
        ev = json.loads(f.read_text(encoding="utf-8"))
        if ev.get("meta", {}).get("bertscore_rescaled"):
            print(f"skip (already rescaled): {f}")
            continue
        n = convert(ev)
        if in_place:
            shutil.copy2(f, f.with_name("evaluation.bertscore_raw.json"))
            dest = f
        else:
            dest = f.with_name("evaluation.rescaled.json")
        dest.write_text(json.dumps(ev, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"{n} pairs rescaled: {dest}")


if __name__ == "__main__":
    main(sys.argv[1:])
