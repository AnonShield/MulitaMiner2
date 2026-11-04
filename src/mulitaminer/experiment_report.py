"""Self-contained HTML report for an experiment tree: reads experiment.json plus
each run's evaluation.json and renders one offline inline-SVG dashboard (no JS
deps, no external assets), styled after the project's cream/orange deck.

A *target* is one report (its baseline XLSX is the gold); a *model* is an LLM
profile; spread is across the N runs.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from mulitaminer.evaluation.scorers import SCORERS

# Metric families derived from the scorer registry so a new scorer shows up here
# with no edit. "structural" is the extra label nested/dict fields carry.
_TEXT = tuple(n for n, s in SCORERS.items() if s.kind == "text")
_DET = tuple(n for n, s in SCORERS.items() if s.kind == "structural") + ("structural",)
_TEXT_SET = frozenset(_TEXT)


def _ms(values: list[float]) -> dict:
    if not values:
        return {"m": None, "s": 0.0}
    return {"m": round(statistics.fmean(values), 4),
            "s": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0}


def _box(values: list[float]) -> dict | None:
    if not values:
        return None
    vs = sorted(values)
    if len(vs) < 2:
        v = vs[0]
        return {"min": v, "q1": v, "med": v, "q3": v, "max": v, "n": 1}
    q1, med, q3 = statistics.quantiles(vs, n=4)
    return {"min": round(vs[0], 4), "q1": round(q1, 4), "med": round(med, 4),
            "q3": round(q3, 4), "max": round(vs[-1], 4), "n": len(vs)}


def _new_detail() -> dict:
    return {"runs": 0, "base": 0, "extr": 0, "match": 0,
            "fn": defaultdict(lambda: [0, 0]), "fp": {},
            "fp_n": defaultdict(lambda: [0, 0]), "pairs": defaultdict(list)}


def _tally(counts: dict, names: list[str]) -> None:
    """Runs the name showed up in, then total hits: a name can repeat within a run."""
    for name in set(names):
        counts[name][0] += 1
    for name in names:
        counts[name][1] += 1


def _fold_pairs(runs: list[tuple[str, dict]]) -> list:
    """One matched finding: [name, {metric: {field: mean score}}, runs matched].

    The row set is the UNION over runs, so a finding a non-deterministic model
    recovered only sometimes is still a row, and its scores average only the
    runs it appeared in. The count travels with it or a 2-run average would
    read as a 5-run one. Cells vacuous in every run are left out and show blank.
    """
    acc: dict = defaultdict(lambda: defaultdict(list))
    for _, scores in runs:
        for field, metrics in scores.items():
            for metric, st in metrics.items():
                if not st.get("vacuous") and st.get("score") is not None:
                    acc[metric][field].append(st["score"])
    return [runs[0][0],
            {m: {f: round(statistics.fmean(v), 3) for f, v in fs.items()}
             for m, fs in acc.items()},
            len(runs)]


def _aggregate(experiment_dir: Path) -> dict:
    manifest = json.loads((experiment_dir / "experiment.json").read_text(encoding="utf-8"))
    models = manifest["config"]["models"]

    cov: dict = defaultdict(lambda: defaultdict(list))
    fmeas: dict = defaultdict(lambda: defaultdict(list))
    fill: dict = defaultdict(lambda: defaultdict(list))     # (t,m) -> field -> [gap per run]
    pairsc: dict = defaultdict(lambda: defaultdict(list))
    field_metrics: dict = defaultdict(set)
    targets: dict = {}
    sev_by_scanner: dict = defaultdict(lambda: defaultdict(int))  # scanner -> sev -> count
    sev_seen: set = set()                                         # targets already counted
    detail: dict = defaultdict(_new_detail)   # (t,m) -> drill-down payload
    threshold = None                          # alignment cutoff, from any evaluation

    for r in manifest["runs"]:
        if r["status"] not in ("ok", "cached"):
            continue
        target, model = Path(r["report"]).stem, r["model"]
        targets[target] = r["scanner"]
        key = (target, model)
        cv = r.get("coverage")
        if cv:
            cov[key]["recall"].append(cv["recall"])
            cov[key]["precision"].append(cv["precision"])
            fn = len(cv.get("false_negatives", cv.get("missed", [])))
            fp = len(cv.get("false_positives", cv.get("spurious", [])))
            cov[key]["false_negatives"].append(fn)
            cov[key]["false_positives"].append(fp)
            d = detail[key]
            d["runs"] += 1
            d["base"] += cv.get("baseline_count", 0)
            d["extr"] += cv.get("extraction_count", 0)
            d["match"] += cv.get("matched", 0)
            _tally(d["fn"], [str(nm) for nm in
                             cv.get("false_negatives", cv.get("missed", []))])
            fp_names = []
            for det in cv.get("false_positive_detail", []):
                name = str(det.get("name", "?"))
                fp_names.append(name)
                d["fp"].setdefault(name, [det.get("category"), det.get("best_baseline"),
                                          det.get("best_similarity")])
            _tally(d["fp_n"], fp_names)
        if "cost_usd" in r:
            cov[key]["cost"].append(r["cost_usd"])
        if "duration_s" in r:
            cov[key]["duration"].append(r["duration_s"])
        ep = Path(r["run_dir"]) / "evaluation.json"
        if not ep.is_file():
            continue
        ev = json.loads(ep.read_text(encoding="utf-8"))
        if threshold is None:
            threshold = ev.get("meta", {}).get("threshold")
        for field, ms in ev.get("fields", {}).items():
            fb = fe = None
            for metric, st in ms.items():
                field_metrics[field].add(metric)
                if st.get("n_measured"):
                    fmeas[key][(field, metric)].append(st.get("measured_mean"))
                if fb is None and st.get("fill_rate_baseline") is not None:
                    fb, fe = st["fill_rate_baseline"], st.get("fill_rate_extraction", 0.0)
            if fb is not None:
                fill[key][field].append(max(0.0, fb - (fe or 0.0)))
        for i, pair in enumerate(ev.get("pairs", [])):
            scores = pair.get("scores", {})
            # Key on the baseline row, the only id stable across runs.
            pid = pair.get("baseline_index", i)
            detail[key]["pairs"][pid].append((pair.get("name") or f"#{pid}", scores))
            for metric in _TEXT:
                vals = [ms[metric]["score"] for ms in scores.values()
                        if metric in ms and not ms[metric]["vacuous"]]
                if vals:
                    pairsc[key][metric].append(statistics.fmean(vals))
        if target not in sev_seen:                       # count each report once
            rp = Path(r["run_dir"]) / "results.json"
            if rp.is_file():
                sev_seen.add(target)
                for rec in json.loads(rp.read_text(encoding="utf-8")):
                    s = str(rec.get("severity") or "?").upper()
                    sev_by_scanner[r["scanner"]][s] += 1

    tsorted = sorted(targets)
    seen_metrics = set().union(*field_metrics.values())
    text_present = [m for m in _TEXT if m in seen_metrics]
    det_present = [m for m in _DET if m in seen_metrics]
    sem_fields = sorted(f for f, ms in field_metrics.items() if ms & _TEXT_SET)
    det_fields = sorted(f for f, ms in field_metrics.items() if not (ms & _TEXT_SET))
    omit_fields = sorted({f for c in fill.values() for f in c})

    def pooled(model, key):
        return [v for (t, m), c in cov.items() if m == model for v in c.get(key, ())]

    overall = {m: {k: _ms(pooled(m, k)) for k in
                   ("recall", "precision", "false_negatives", "false_positives",
                    "cost", "duration")}
               for m in models}
    by_target = {t: {m: {"recall": _ms(cov[(t, m)]["recall"]),
                         "precision": _ms(cov[(t, m)]["precision"])}
                     for m in models} for t in tsorted}
    time_cost = {t: {m: {"cost": round(sum(cov[(t, m)]["cost"]), 4),
                         "dur": round(sum(cov[(t, m)]["duration"]), 1)}
                     for m in models} for t in tsorted}

    def field_block(fields, metrics):
        return {metric: {t: {f: {m: _ms(fmeas[(t, m)].get((f, metric), []))
                                 for m in models} for f in fields} for t in tsorted}
                for metric in metrics}

    omission = {t: {f: {m: _ms(fill[(t, m)].get(f, [])) for m in models}
                    for f in omit_fields} for t in tsorted}

    # Per-report drill-down, one entry per (report, model): counts, the actual
    # missed/invented names, and every matched finding's per-field scores.
    detail_out = {}
    for (t, m), d in detail.items():
        n = max(1, d["runs"])
        detail_out[f"{t}|{m}"] = {
            "runs": d["runs"],
            "base": round(d["base"] / n, 1), "extr": round(d["extr"] / n, 1),
            "match": round(d["match"] / n, 1),
            # [name, runs hit, total hits]; the fp rows carry the match detail too.
            "fn": sorted(([k, *v] for k, v in d["fn"].items()), key=lambda x: (-x[2], x[0])),
            "fp": sorted(([k, *d["fp"][k], *v] for k, v in d["fp_n"].items()),
                         key=lambda x: (-x[5], x[0])),
            "pairs": [_fold_pairs(v) for v in d["pairs"].values()],
        }

    def dist_box(metrics):
        return {metric: {m: _box([v for t in tsorted for v in pairsc[(t, m)].get(metric, [])])
                         for m in models} for metric in metrics}

    def dist_box_bt(metrics):
        # Per-report box, same shape as dist: {metric: {target: {model: box}}}
        return {metric: {t: {m: _box(pairsc[(t, m)].get(metric, []))
                             for m in models} for t in tsorted} for metric in metrics}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": manifest["config"], "totals": manifest["totals"],
        "models": models, "targets": tsorted, "scanners": targets,
        "text_metrics": text_present, "det_metrics": det_present,
        "sem_fields": sem_fields, "det_fields": det_fields, "omit_fields": omit_fields,
        "overall": overall, "by_target": by_target,
        "sev_by_scanner": {s: dict(c) for s, c in sev_by_scanner.items()},
        "time_cost": time_cost,
        "text_fields": field_block(sem_fields, text_present),
        "det_field_block": field_block(det_fields, det_present),
        "omission": omission,
        "dist": dist_box(text_present),
        "dist_by_target": dist_box_bt(text_present),
        "detail": detail_out, "threshold": threshold,
    }


def build_report(experiment_dir: Path, out_path: Path | None = None) -> Path:
    data = _aggregate(experiment_dir)
    out_path = out_path or (experiment_dir / "report.html")
    doc = (
        "<!doctype html><html lang=en><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>MulitaMiner - experiment report</title>"
        f"<style>{_CSS}</style>{_BODY}"
        f"<script>const DATA={json.dumps(data, ensure_ascii=False)};{_JS}</script>"
        "</html>"
    )
    out_path.write_text(doc, encoding="utf-8")
    return out_path



_CSS = r"""
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#f4f1ea;--card:#faf8f2;--card2:#efece3;--accent:#d9541e;
  --ink:#1a1a17;--ink2:#52514e;--muted:#8a887f;--grid:#e6e3da;--border:#e2ded4}
body{background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  font-variant-numeric:tabular-nums;max-width:1040px;margin:0 auto;padding:2rem 1.5rem 4rem}
.kick{font:600 11px/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}
h1{font-size:2.2rem;letter-spacing:-.02em;margin:.35rem 0 .1rem;font-family:ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
h1 span{color:var(--accent)}
h2{font-size:1.12rem;margin:.1rem 0}
header{border-bottom:2px solid var(--accent);padding-bottom:1.1rem;margin-bottom:1.2rem;
  display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:1rem}
.meta{display:flex;flex-wrap:wrap;gap:.4rem 1.3rem;font:.7rem/1.4 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;color:var(--muted);text-align:right}
.meta b{color:var(--ink);font-weight:600}
.hero{display:grid;grid-template-columns:minmax(240px,1fr) 1.7fr;gap:1.2rem;margin-bottom:1.6rem;align-items:stretch}
@media(max-width:740px){.hero{grid-template-columns:1fr}}
.hero .dark{background:var(--ink);color:#faf8f2;border-radius:14px;padding:1.4rem 1.5rem;
  display:flex;flex-direction:column;justify-content:space-between;gap:1rem;min-height:150px}
.hero .dark .l{font:600 10px/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.hero .dark .win{display:flex;align-items:center;gap:.55rem;margin-top:.6rem;font:700 1.4rem/1.1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;word-break:break-word}
.hero .dark .big{font:700 2.7rem/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.hero .dark .sub{font:.72rem/1.4 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;color:#c9c7bd;margin-top:.4rem}
.hero .lite{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.2rem 1.3rem;
  display:flex;flex-direction:column;overflow:hidden}
/* Bounded, scrollable ranking: the hero stays compact no matter the model count. */
#verdictBars{overflow-y:auto;overflow-x:hidden;max-height:190px;padding-right:.25rem;margin-right:-.25rem}
.brow{display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem}
.brow:last-child{margin-bottom:0}
.brow .nm{width:84px;text-align:right;font:.7rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.brow .track{flex:1;height:16px;background:var(--card2);border-radius:4px;overflow:hidden}
.brow .fill{height:100%;border-radius:4px}
.brow .vv{width:98px;font:.7rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;flex-shrink:0}
.brow .vv s{color:var(--muted);font-size:.6rem;text-decoration:none}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block;flex-shrink:0}
nav{position:sticky;top:0;z-index:10;background:var(--bg);display:flex;flex-wrap:wrap;gap:.3rem;
  padding:.7rem 0;margin-bottom:1rem;border-bottom:1px solid var(--border)}
nav a{color:var(--ink2);text-decoration:none;font:.7rem/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;padding:.4rem .6rem;border-radius:6px}
nav a:hover{background:var(--card2);color:var(--ink)}
section{margin:2.2rem 0;scroll-margin-top:3.4rem}
.sub{color:var(--ink2);font-size:.85rem;margin:.2rem 0 1rem;max-width:70ch}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.1rem 1.2rem;margin-bottom:1rem}
.card-t{font:600 .72rem/1.2 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  margin-bottom:.7rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:740px){.grid2{grid-template-columns:1fr}}
.chart{width:100%;height:auto;display:block}
.grid{stroke:var(--grid);stroke-width:1}
.tick{fill:var(--muted);font:10px ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.axt{fill:var(--ink2);font:600 11px ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.ylab{fill:var(--ink2);font:11px ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.err{stroke:var(--ink);stroke-opacity:.4;stroke-width:1.4}
.wh{stroke:var(--ink2);stroke-width:1.3}
.toggle{display:flex;flex-wrap:wrap;gap:.3rem;align-items:center}
.toggle .lb{font:600 10px/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-right:.2rem}
.toggle button{background:var(--card2);color:var(--ink2);border:1px solid var(--border);font:.7rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;
  padding:.28rem .6rem;border-radius:999px;cursor:pointer}
.toggle button[aria-pressed=true]{background:var(--accent);color:#fff;border-color:var(--accent)}
.toggle button[disabled]{opacity:.38;cursor:not-allowed;text-decoration:line-through}
.toggle button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
select{background:var(--card2);color:var(--ink);border:1px solid var(--border);border-radius:6px;
  padding:.3rem .55rem;font:.7rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;cursor:pointer}
.ctlbar{display:flex;flex-wrap:wrap;gap:.5rem .9rem;align-items:center;margin:0 0 .9rem}
.selg{display:inline-flex;gap:.4rem;align-items:center}
.selg .lb{font:600 10px/1 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.runsnote{font:.66rem/1.4 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;color:var(--muted);margin:.1rem 0 .9rem}
.dlwrap{margin-left:auto;position:relative;display:inline-block}
.dlwrap>button{background:var(--card2);color:var(--ink2);border:1px solid var(--border);font:.6rem ui-monospace,Consolas,monospace;padding:.24rem .55rem;border-radius:999px;cursor:pointer;text-transform:uppercase;letter-spacing:.05em}
.dlwrap>button:hover{color:var(--ink)}
.dlwrap.open .menu{display:block}
.dlwrap .menu{display:none;position:absolute;right:0;top:118%;background:var(--card);border:1px solid var(--border);border-radius:7px;padding:3px;z-index:8;box-shadow:0 6px 16px #0002}
.dlwrap .menu a{display:block;padding:.26rem .8rem;font:.66rem ui-monospace,Consolas,monospace;color:var(--ink);cursor:pointer;border-radius:5px;white-space:nowrap}
.dlwrap .menu a:hover{background:var(--card2)}
.svgheat text{fill:var(--ink2)}
.legend{display:flex;flex-wrap:wrap;gap:.4rem 1rem;margin-top:.6rem;font:.7rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;color:var(--ink2)}
.legend span{display:inline-flex;align-items:center;gap:.35rem}
.sw{width:11px;height:11px;border-radius:3px;display:inline-block}
.mult{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:.8rem}
.tctab{border-collapse:collapse;width:100%;font:.72rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.tctab th,.tctab td{padding:.4rem .7rem;text-align:right;border-bottom:1px solid var(--border);white-space:nowrap}
.tctab th.l,.tctab td.l{text-align:left}
.tctab thead th{color:var(--muted);font-weight:600;font-size:.64rem}
.tctab tr.tot td{border-top:2px solid var(--border);border-bottom:none;font-weight:700}
.htab-wrap{overflow-x:auto}
.htab{width:100%;border-collapse:collapse;font:.72rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace}
.htab th{font-weight:400;color:var(--muted);font-size:.64rem;padding:.5rem .6rem;border-bottom:1px solid var(--border);white-space:nowrap}
.htab th.l,.htab td.l{text-align:left}.htab th:not(.l){text-align:center}
.htab td{padding:.45rem .6rem;text-align:center;white-space:nowrap}
.htab td.l{color:var(--ink)}
.htab td s{display:block;font-size:.56rem;opacity:.7;text-decoration:none}
.empty{color:var(--muted);font:.75rem ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;padding:.5rem 0}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:#f4f1ea;padding:.4rem .6rem;border-radius:6px;
  font:.68rem/1.35 ui-monospace,'Cascadia Code','JetBrains Mono',Consolas,monospace;box-shadow:0 8px 22px rgba(0,0,0,.28);transform:translate(-50%,-120%);opacity:0;
  transition:opacity .12s;z-index:100;max-width:280px;white-space:pre-line}
#tip.on{opacity:1}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
.dlink{color:var(--accent);cursor:pointer;border-bottom:1px dotted var(--accent)}
.mask{position:fixed;inset:0;background:rgba(26,26,23,.72);z-index:50;overflow:auto;padding:2rem 1rem;display:none}
.mask.on{display:block}
.modal{background:var(--bg);border:1px solid var(--border);border-radius:14px;max-width:1000px;
  margin:0 auto;padding:1.3rem 1.5rem 2rem;position:relative}
.modal .x{position:absolute;top:.5rem;right:.8rem;background:none;border:0;font:1.5rem/1 ui-monospace,Consolas,monospace;color:var(--muted);cursor:pointer}
.modal .x:hover{color:var(--ink)}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(92px,1fr));gap:.6rem;margin:.9rem 0 1.1rem}
.kpi>div{background:var(--card);border:1px solid var(--border);border-radius:9px;padding:.5rem .65rem}
.kpi .k{font:600 9px/1 ui-monospace,Consolas,monospace;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.kpi .v{font:700 1.05rem ui-monospace,Consolas,monospace;margin-top:.28rem}
.kpi .s2{font:.57rem/1.3 ui-monospace,Consolas,monospace;color:var(--muted);margin-top:.2rem}
.mlist{list-style:none;font:.72rem/1.45 ui-monospace,Consolas,monospace;max-height:300px;overflow:auto}
.mlist li{padding:.42rem 0;border-bottom:1px solid var(--border)}
.mlist li:last-child{border-bottom:0}
.mlist .nm{display:flex;gap:.4rem;align-items:baseline;color:var(--ink)}
.mlist .nm b{font-weight:600;flex:1;min-width:0;overflow-wrap:anywhere}
.mlist .mx{display:flex;flex-wrap:wrap;gap:.25rem .5rem;align-items:center;margin-top:.28rem;
  font-size:.64rem;color:var(--muted);overflow-wrap:anywhere}
.mlist s,.card-t s{color:var(--muted);text-decoration:none;font-size:.64rem;font-weight:400;text-transform:none;letter-spacing:0}
.pill{border:1px solid var(--border);background:var(--card2);border-radius:999px;padding:.05rem .42rem;
  font:.59rem/1.5 ui-monospace,Consolas,monospace;color:var(--ink2);white-space:nowrap;flex-shrink:0;text-transform:none;letter-spacing:0}
.pill.rep{background:var(--accent);border-color:var(--accent);color:#fff}
/* Similarity against the alignment threshold: the tick is the cutoff, so a bar
   stopping just short of it reads as a near miss, not an invention. */
.simbar{position:relative;width:62px;height:7px;border-radius:4px;background:var(--card2);
  border:1px solid var(--border);flex-shrink:0}
.simbar i{position:absolute;left:0;top:0;bottom:0;border-radius:4px;background:var(--muted)}
.simbar u{position:absolute;top:-3px;bottom:-3px;width:2px;background:var(--accent);border-radius:1px}
.ptab{width:100%;border-collapse:separate;border-spacing:2px;font:.68rem ui-monospace,Consolas,monospace}
.ptab th{font-weight:600;font-size:.6rem;color:var(--ink2);padding:.3rem .2rem;text-align:center}
.ptab th.l,.ptab td.l{text-align:left;font-size:.68rem;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ptab td{text-align:center;padding:.28rem .2rem;border-radius:4px}
.ptab th.runs,.ptab td.runs{width:1%;white-space:nowrap;padding-left:.5rem;padding-right:.5rem}
.ptab td.runs{color:var(--muted);font-size:.62rem}
"""

_BODY = r"""
<header>

  <div>
    <div class="kick">Experiment report</div>
    <h1>Mulita<span>Miner</span></h1>
  </div>
  <div class="meta" id="meta"></div>
</header>

<div class="hero">
  <div class="dark" id="verdict"></div>
  <div class="lite"><div class="card-t" id="vbTitle">Overall recall by model · mean across reports (±std)</div>
    <div id="verdictBars"></div></div>
</div>

<nav>
  <a href="#coverage">Coverage</a><a href="#dataset">Dataset</a><a href="#consistency">By report</a>
  <a href="#fields">Field quality</a><a href="#omission">Omission</a>
  <a href="#dist">Distribution</a><a href="#errors">Errors &amp; cost</a>
</nav>

<section id="coverage">
  <div class="kick">Coverage</div>
  <h2>Precision × recall - where each model sits</h2>
  <p class="sub">Top-right = extracts everything (recall) without hallucinating (precision).
     Whiskers = spread across runs. Averaged over reports and runs.</p>
  <div class="card"><div class="card-t">Precision × Recall by model (±std)<span class="dlwrap" id="dl_scatter"></span></div>
    <div id="scatter"></div><div class="legend" id="scLegend"></div></div>
</section>

<section id="dataset">
  <div class="kick">Dataset</div>
  <h2>What each scanner's findings look like</h2>
  <p class="sub">Severity mix per scanner, normalized to 100% so scanners of different sizes stay
     comparable. N = findings behind each bar. Info groups the informational tiers (none/log/info).</p>
  <div class="card"><div class="card-t">Severity composition by scanner<span class="dlwrap" id="dl_sev"></span></div>
    <div id="sevBar"></div><div class="legend" id="sevLegend"></div></div>
</section>

<section id="consistency">
  <div class="kick">Consistency</div>
  <h2 id="smH2">Does the winner hold across reports?</h2>
  <p class="sub" id="smSub">One panel per report (recall by model). If the order changes panel to panel,
     the overall mean is hiding it. Click a report or a model name to open its detail.</p>
  <div class="mult" id="sm"></div>
  <div class="legend" id="smLegend"></div>
</section>

<section id="fields">
  <div class="kick">Field quality</div>
  <h2>Where each model gets fields right</h2>
  <p class="sub">Rows = fields; you choose the columns - scanner (baselines aggregated), baseline, or model -
     and a scope to focus on. Mean per field, empty×empty pairs excluded; a field empty everywhere is
     never scored and is listed below. Darker = better; color scale fit to the data.</p>
  <div class="ctlbar">
    <span class="toggle" id="fqCols"><span class="lb">Columns</span></span>
    <span class="selg"><span class="lb">Scope</span><select id="fqScope"></select></span>
    <span class="selg" id="fqModelWrap"><span class="lb">Model</span><select id="fqModel"></select></span>
  </div>
  <div class="card">
    <div class="card-t">Text fields · semantic similarity
      <span class="toggle" id="txtMetric"><span class="lb">Metric</span></span>
      <span class="dlwrap" id="dl_txtHeat"></span>
    </div>
    <div class="htab-wrap"><div id="txtHeat"></div></div>
    <div class="legend" id="txtLegend"></div>
  </div>
  <div class="card">
    <div class="card-t">Structured fields · deterministic match
      <span class="toggle" id="detMetric"><span class="lb">Metric</span></span>
      <span class="dlwrap" id="dl_detHeat"></span>
    </div>
    <div class="htab-wrap"><div id="detHeat"></div></div>
    <div class="legend" id="detLegend"></div>
  </div>
</section>

<section id="omission">
  <div class="kick">Omission</div>
  <h2>Which fields each model leaves empty</h2>
  <p class="sub">Proxy: fraction of pairs where the baseline fills the field and the extraction does not
     (baseline-filled − extraction-filled). Every field is shown; a pale cell means no omission.
     Redder = more omitted.</p>
  <div class="ctlbar">
    <span class="toggle" id="omCols"><span class="lb">Columns</span></span>
    <span class="selg"><span class="lb">Scope</span><select id="omScope"></select></span>
    <span class="selg" id="omModelWrap"><span class="lb">Model</span><select id="omModel"></select></span>
  </div>
  <div class="card">
    <div class="card-t">Field omission <span class="dlwrap" id="dl_omheat"></span></div>
    <div class="htab-wrap"><div id="omheat"></div></div>
    <div class="legend" id="omLegend"></div>
  </div>
</section>

<section id="dist">
  <div class="kick">Distribution</div>
  <h2>How per-pair scores spread</h2>
  <p class="sub">Box plot: box = interquartile range, line = median, ticks = min/max. The real spread of
     per-pair scores, with no threshold bands - a tight box at 1.0 means the field is nailed, a wide box
     means it varies.</p>
  <div class="card"><div class="card-t"><span class="toggle" id="distMetric"><span class="lb">Metric</span></span>
      <span style="margin-left:auto;display:flex;gap:.4rem;align-items:center">
        <span class="lb" style="font:600 10px/1 monospace;color:var(--muted)">Report</span><select id="distTarget"></select></span>
      <span class="dlwrap" id="dl_distBox" style="margin-left:.5rem"></span></div>
    <div id="distBox"></div>
  </div>
</section>

<section id="errors">
  <div class="kick">Errors &amp; cost</div>
  <h2>Where coverage fails, and at what cost</h2>
  <p class="sub">Per run, against the baseline (the gold): false negatives = baseline vulns not
     recovered; false positives = extracted records with no baseline match.</p>
  <div class="card" id="paretoCard" style="display:none"><div class="card-t">Cost vs recall · Pareto (mean/run)<span class="dlwrap" id="dl_pareto"></span></div>
    <div id="pareto"></div><div class="legend" id="paretoLegend"></div></div>
  <div class="card"><div class="card-t">False negatives vs false positives by model (mean/run)<span class="dlwrap" id="dl_err"></span></div>
    <div id="err"></div>
    <div class="legend" id="errLegend"><span><span class="sw" style="background:var(--accent)"></span>False negatives (FN)</span>
      <span><span class="sw" style="background:var(--muted)"></span>False positives (FP)</span></div></div>
  <div class="grid2" id="cost" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))"></div>
  <div class="card" style="margin-top:1rem"><div class="card-t">Time &amp; cost per report</div>
    <div style="overflow-x:auto"><table class="tctab" id="timecost"></table></div></div>
</section>
<div id="tip" role="tooltip"></div>

<div class="mask" id="mask">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="mTitle">
    <button class="x" id="mClose" aria-label="Close">&times;</button>
    <div class="kick">Report detail</div>
    <h2 id="mTitle"></h2>
    <div class="ctlbar" id="mCtl" style="margin:.8rem 0 0"></div>
    <div id="mBody"></div>
  </div>
</div>
"""

_JS = r"""
const M=DATA.models,TGT=DATA.targets,OV=DATA.overall;
const PAL=['#2a78d6','#008300','#a24bb0','#0f9d9d','#4a3aa7','#c81d54','#7a6a00','#946037'];
const MC={};M.forEach((m,i)=>MC[m]=PAL[i%PAL.length]);
const pct=v=>v==null?'-':(v*100).toFixed(1)+'%';
const f3=v=>v==null?'-':v.toFixed(3);
const avg=a=>{const x=a.filter(v=>v!=null);return x.length?x.reduce((s,v)=>s+v,0)/x.length:null;};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const el=id=>document.getElementById(id);
const orec=m=>OV[m].recall.m;

const tip=el('tip');
document.addEventListener('mouseover',e=>{const t=e.target.closest('[data-tip]');if(t){tip.textContent=t.getAttribute('data-tip');tip.classList.add('on');}});
document.addEventListener('mousemove',e=>{if(tip.classList.contains('on')){tip.style.left=e.clientX+'px';tip.style.top=e.clientY+'px';}});
document.addEventListener('mouseout',e=>{if(e.target.closest('[data-tip]'))tip.classList.remove('on');});

function axis(padL,plotW,top,bottom,min,max){let s='';[0,.25,.5,.75,1].forEach(t=>{
  const v=min+(max-min)*t,x=padL+t*plotW;
  s+=`<line class="grid" x1="${x}" y1="${top}" x2="${x}" y2="${bottom}"/>`+
     `<text class="tick" x="${x}" y="${top-7}" text-anchor="middle">${v.toFixed(2)}</text>`;});return s;}

function hDot(rows,{W=760,rowH=28,padL=120,min=0,max=1,ticks=true}={}){
  const padR=40,top=ticks?30:12,plotW=W-padL-padR,H=top+rows.length*rowH+12,bottom=H-12;
  const X=v=>padL+((v-min)/(max-min))*plotW;let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`;
  if(ticks)s+=axis(padL,plotW,top,bottom,min,max);
  else [0,.5,1].forEach(t=>{const x=padL+t*plotW;s+=`<line class="grid" x1="${x}" y1="${top}" x2="${x}" y2="${bottom}"/>`;});
  rows.forEach((r,i)=>{const y=top+i*rowH+rowH/2;
    s+=`<text class="ylab" x="${padL-10}" y="${y+4}" text-anchor="end">${esc(r.label)}</text>`;
    // Hit area over the label only, so the dots keep their tooltips.
    if(r.det)s+=`<rect x="0" y="${y-rowH/2}" width="${padL}" height="${rowH}" fill="#000" fill-opacity="0"`+
      ` pointer-events="all" style="cursor:pointer" data-det="${esc(r.det)}"${r.detM?` data-det-m="${esc(r.detM)}"`:''}/>`;
    r.points.forEach(p=>{if(p.v==null)return;const cx=X(p.v);
      if(p.err)s+=`<line class="err" x1="${X(Math.max(min,p.v-p.err))}" y1="${y}" x2="${X(Math.min(max,p.v+p.err))}" y2="${y}"/>`;
      s+=`<circle cx="${cx}" cy="${y}" r="6" fill="${p.color}" data-tip="${esc(p.tip)}"/>`;});});
  return s+'</svg>';
}

function hBox(rows,{W=760,rowH=38,padL=null}={}){
  // Fit the gutter to the labels: a fixed 120px clipped "mulita-qwen2.5-1.5b-v4"
  // into "a-qwen2.5-1.5b-v4", since the label is right-anchored at padL.
  padL=padL??Math.min(260,Math.max(90,Math.max(...rows.map(r=>String(r.label).length))*6.9+22));
  const padR=40,top=30,plotW=W-padL-padR,H=top+rows.length*rowH+12,bottom=H-12;
  const X=v=>padL+v*plotW;let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`+axis(padL,plotW,top,bottom,0,1);
  rows.forEach((r,i)=>{const y=top+i*rowH+rowH/2;
    s+=`<text class="ylab" x="${padL-10}" y="${y+4}" text-anchor="end">${esc(r.label)}</text>`;
    const b=r.box;if(!b){s+=`<text class="tick" x="${padL+6}" y="${y+4}">no data</text>`;return;}
    const bh=rowH*.46,tp=esc(`${r.label}\nmin ${b.min.toFixed(2)}  Q1 ${b.q1.toFixed(2)}  med ${b.med.toFixed(2)}  Q3 ${b.q3.toFixed(2)}  max ${b.max.toFixed(2)}\nn=${b.n} pairs`);
    s+=`<line class="wh" x1="${X(b.min)}" y1="${y}" x2="${X(b.q1)}" y2="${y}"/>`+
       `<line class="wh" x1="${X(b.q3)}" y1="${y}" x2="${X(b.max)}" y2="${y}"/>`+
       `<line class="wh" x1="${X(b.min)}" y1="${y-4}" x2="${X(b.min)}" y2="${y+4}"/>`+
       `<line class="wh" x1="${X(b.max)}" y1="${y-4}" x2="${X(b.max)}" y2="${y+4}"/>`+
       `<rect x="${X(b.q1)}" y="${y-bh/2}" width="${Math.max(1,X(b.q3)-X(b.q1))}" height="${bh}" rx="2" fill="${r.color}" fill-opacity=".28" stroke="${r.color}" data-tip="${tp}"/>`+
       `<line x1="${X(b.med)}" y1="${y-bh/2}" x2="${X(b.med)}" y2="${y+bh/2}" stroke="${r.color}" stroke-width="2.5"/>`;});
  return s+'</svg>';
}

// stacked horizontal bar (each row sums to ~1). rows:[{label,vals:[...]}], cats colors
function hStack(rows,cats,colors,{W=760,rowH=30,padL=120}={}){
  const padR=20,top=30,plotW=W-padL-padR,H=top+rows.length*rowH+12,bottom=H-12;
  const X=v=>padL+v*plotW;let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`;
  [0,.25,.5,.75,1].forEach(t=>{s+=`<line class="grid" x1="${X(t)}" y1="${top}" x2="${X(t)}" y2="${bottom}"/>`+
    `<text class="tick" x="${X(t)}" y="${top-7}" text-anchor="middle">${(t*100).toFixed(0)}%</text>`;});
  rows.forEach((r,i)=>{const y=top+i*rowH+rowH*.2,bh=rowH*.55;
    s+=`<text class="ylab" x="${padL-10}" y="${y+bh/2+4}" text-anchor="end">${esc(r.label)}</text>`;
    let cum=0;r.vals.forEach((v,ci)=>{if(v<=0){return;}const x=X(cum),w=X(cum+v)-x;
      s+=`<rect x="${x}" y="${y}" width="${Math.max(0.5,w)}" height="${bh}" fill="${colors[ci]}" data-tip="${esc(r.label+' · '+cats[ci]+': '+(v*100).toFixed(1)+'%')}"/>`;cum+=v;});});
  return s+'</svg>';
}

function hBars(rows,{W=760,rowH=40,padL=120}={}){
  const padR=54,top=12,plotW=W-padL-padR,H=top+rows.length*rowH+12;
  const max=Math.max(1,...rows.flatMap(r=>r.bars.map(b=>b.v)));const X=v=>(v/max)*plotW;
  let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`;
  rows.forEach((r,i)=>{const y0=top+i*rowH+6,n=r.bars.length,bh=(rowH-10)/n;
    s+=`<text class="ylab" x="${padL-10}" y="${y0+rowH/2-4}" text-anchor="end">${esc(r.label)}</text>`;
    r.bars.forEach((b,j)=>{const y=y0+j*bh,w=X(b.v);
      s+=`<rect x="${padL}" y="${y}" width="${Math.max(0,w)}" height="${bh-2}" rx="2" fill="${b.color}" data-tip="${esc(b.tip)}"/>`+
         `<text class="tick" x="${padL+w+5}" y="${y+bh/2+1}">${b.v.toFixed(1)}</text>`;});});
  return s+'</svg>';
}

function scatter(pts,{W=760,H=520,min=0.5}={}){
  const pad={t:16,r:20,b:48,l:56},plotW=W-pad.l-pad.r,plotH=H-pad.t-pad.b;
  const X=v=>pad.l+((v-min)/(1-min))*plotW,Y=v=>pad.t+plotH-((v-min)/(1-min))*plotH;
  let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`;
  [0,.25,.5,.75,1].forEach(t=>{const v=min+(1-min)*t;
    s+=`<line class="grid" x1="${X(v)}" y1="${pad.t}" x2="${X(v)}" y2="${pad.t+plotH}"/>`+
       `<line class="grid" x1="${pad.l}" y1="${Y(v)}" x2="${pad.l+plotW}" y2="${Y(v)}"/>`+
       `<text class="tick" x="${X(v)}" y="${pad.t+plotH+16}" text-anchor="middle">${v.toFixed(2)}</text>`+
       `<text class="tick" x="${pad.l-8}" y="${Y(v)+3}" text-anchor="end">${v.toFixed(2)}</text>`;});
  s+=`<text class="axt" x="${pad.l+plotW/2}" y="${H-8}" text-anchor="middle">Precision →</text>`+
     `<text class="axt" x="${-(pad.t+plotH/2)}" y="14" text-anchor="middle" transform="rotate(-90)">Recall →</text>`;
  pts.forEach(p=>{if(p.x==null||p.y==null)return;const cx=X(p.x),cy=Y(p.y);
    if(p.ex)s+=`<line class="err" x1="${X(Math.max(min,p.x-p.ex))}" y1="${cy}" x2="${X(Math.min(1,p.x+p.ex))}" y2="${cy}"/>`;
    if(p.ey)s+=`<line class="err" x1="${cx}" y1="${Y(Math.max(min,p.y-p.ey))}" x2="${cx}" y2="${Y(Math.min(1,p.y+p.ey))}"/>`;
    s+=`<circle cx="${cx}" cy="${cy}" r="8" fill="${p.color}" fill-opacity=".85" stroke="${p.color}" data-tip="${esc(p.label+'\nprecision '+f3(p.x)+' · recall '+f3(p.y))}"/>`+
       `<text x="${cx+11}" y="${cy+3}" class="ylab" style="font-size:10px">${esc(p.label)}</text>`;});
  return s+'</svg>';
}

// sequential color: v mapped from [min,max] to cream -> deep hue (green good, red bad).
function ramp(v,min,max,hue){const t=Math.max(0,Math.min(1,(v-min)/(max-min)));const L=(a,b)=>Math.round(a+(b-a)*t);
  const to=hue==='red'?[176,26,69]:[26,94,99];
  return{bg:`rgb(${L(244,to[0])},${L(241,to[1])},${L(234,to[2])})`,tx:t>0.5?'#faf8f2':'#1a1a17'};}

function legend(id,items){el(id).innerHTML=items.map(([l,c])=>
  `<span><span class="sw" style="background:${c}"></span>${esc(l)}</span>`).join('');}
// What each scorer measures, in the reader's terms. Same text feeds the
// toggle tooltips and the modal's caption, so there is one definition.
const METRIC_DOC={
  token_f1:'Bag-of-words overlap: F1 over the two token multisets. Order and phrasing do not matter, only which words appear and how often.',
  rouge_l:'Longest common subsequence, as F1. Rewards keeping the same wording in the same order; purely lexical, no stemming.',
  bertscore:'Embedding similarity: matches meaning rather than words, so a paraphrase still scores high. Needs the eval extras.',
  nli:'1 minus the strongest contradiction an NLI model finds between the extraction and each baseline sentence. Catches negation flips a word-overlap score would miss.',
  exact:'Normalized equality, 1 or 0. Numbers compare as numbers, so 8019.0 equals 8019.',
  set_f1:'F1 over the two sets of items, compared as written. For list fields such as references.',
  set_f1_ids:'set_f1 over canonicalized identifiers, so the same CVE counts as a match however it was formatted.',
  structural:'Nested fields (a dict, or a list of objects such as instances): sub-fields are aligned and scored one by one, then averaged.',
};
function toggle(id,opts,active,cb){const h=el(id);
  h.querySelectorAll('button').forEach(b=>b.remove());
  h.insertAdjacentHTML('beforeend',opts.map(o=>`<button data-v="${o}" aria-pressed="${o===active}"`+
    `${METRIC_DOC[o]?` data-tip="${esc(o+': '+METRIC_DOC[o])}"`:''}>${o}</button>`).join(''));
  h.querySelectorAll('button').forEach(b=>b.onclick=()=>{h.querySelectorAll('button').forEach(x=>x.setAttribute('aria-pressed',x===b));cb(b.dataset.v);});}
function fillSel(id,opts,onch){const s=el(id);s.innerHTML=opts.map(o=>`<option value="${o}">${o}</option>`).join('');s.onchange=()=>onch(s.value);}

// ---- meta ----
const T=DATA.totals,C=DATA.config;
const fmtDur=s=>{s=Math.round(s);if(s<90)return s+'s';const h=Math.floor(s/3600),m=Math.round((s%3600)/60);return h?`${h}h ${m}m`:`${m}m ${s%60}s`;};
el('meta').innerHTML=[['models',M.length],['reports',TGT.length],['runs',C.runs],
  ['done',`${T.done}/${T.planned}`],['cost',`$${T.cost_usd.toFixed(4)}`],
  ['time',fmtDur(T.active_seconds)]].map(([k,v])=>`<span>${k} <b>${v}</b></span>`).join('');

// ---- verdict ----
const ranked=[...M].filter(m=>orec(m)!=null).sort((a,b)=>orec(b)-orec(a));
if(!ranked.length){el('verdict').innerHTML='<div class="l">no coverage evaluated</div>';}
else if(M.length===1){const m=ranked[0],o=OV[m],c=MC[m];
  el('verdict').innerHTML=`<div><div class="l">Model under test</div>
    <div class="win"><span class="dot" style="background:${c}"></span>${esc(m)}</div></div>
    <div><div class="big" style="color:${c}">${orec(m).toFixed(3)}</div>
    <div class="sub">mean recall · ranking view appears with 2+ models</div></div>`;
  el('vbTitle').textContent='Model summary · mean across reports (±std)';
  const rows=[['recall',pct(o.recall.m),'±'+pct(o.recall.s)],['precision',pct(o.precision.m),'±'+pct(o.precision.s)],
    ['false neg / run',(o.false_negatives.m??0).toFixed(1),'±'+(o.false_negatives.s??0).toFixed(1)],
    ['false pos / run',(o.false_positives.m??0).toFixed(1),'±'+(o.false_positives.s??0).toFixed(1)],
    ['cost / run',o.cost.m!=null?'$'+o.cost.m.toFixed(4):'-',''],
    ['time / run',o.duration.m!=null?fmtDur(o.duration.m):'-','']];
  el('verdictBars').innerHTML='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:.7rem .9rem">'+
    rows.map(([k,v,s])=>`<div><div style="font:600 9px/1 ui-monospace,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:.3rem">${k}</div>
      <div style="font:700 .95rem ui-monospace,monospace">${v} <span style="font-weight:400;font-size:.6rem;color:var(--muted)">${s}</span></div></div>`).join('')+'</div>';
}else{const win=ranked[0],c=MC[win],delta=orec(win)-orec(ranked[1]);
  el('verdict').innerHTML=`<div><div class="l">Best model · overall recall</div>
    <div class="win"><span class="dot" style="background:${c}"></span>${esc(win)}</div></div>
    <div><div class="big" style="color:${c}">${orec(win).toFixed(3)}</div>
    <div class="sub">mean recall · +${delta.toFixed(3)} ahead of ${esc(ranked[1])}</div></div>`;
  el('verdictBars').innerHTML=ranked.map(m=>{const v=orec(m),s=OV[m].recall.s||0;
    return `<div class="brow"><span class="nm">${esc(m)}</span>
      <div class="track"><div class="fill" style="width:${(v*100).toFixed(1)}%;background:${MC[m]}"></div></div>
      <span class="vv">${v.toFixed(3)} <s>±${s.toFixed(3)}</s></span></div>`;}).join('');}

// ---- scatter ----
(function(){const vals=M.flatMap(m=>[OV[m].recall.m,OV[m].precision.m]).filter(v=>v!=null);
  const lo=vals.length?Math.max(0,Math.floor((Math.min(...vals)-0.06)*10)/10):0.5;
  el('scatter').innerHTML=scatter(M.map(m=>({x:OV[m].precision.m,y:OV[m].recall.m,
    ex:OV[m].precision.s,ey:OV[m].recall.s,color:MC[m],label:m})),{min:lo});
  legend('scLegend',M.map(m=>[m,MC[m]]));mkDL('dl_scatter','scatter','coverage-scatter','scLegend');})();

// ---- small multiples ----
if(M.length===1){  // single model: small multiples degenerate to one dot each; show one bar chart instead
  const m=M[0];
  const rows=[...TGT].map(t=>({label:t,det:t,points:[{v:DATA.by_target[t][m].recall.m,err:DATA.by_target[t][m].recall.s,color:MC[m],
    tip:`${t}\nrecall ${pct(DATA.by_target[t][m].recall.m)}`}]}))
    .sort((a,b)=>(b.points[0].v??-1)-(a.points[0].v??-1));
  el('sm').style.display='block';
  el('sm').innerHTML=`<div class="card"><div class="card-t">Recall by report<span class="dlwrap" id="dl_sm"></span></div>${hDot(rows,{W:800,padL:250,rowH:26,ticks:true})}</div>`;
  el('smH2').textContent='How does recall vary across reports?';
  el('smSub').textContent='Recall per report for the single model under test. Short bars are the reports it struggles on. Click a report name to open its detail.';
  mkDL('dl_sm','sm','recall-by-report','smLegend');
}else{
  el('sm').innerHTML=TGT.map(t=>{
    const rows=[...M].sort((a,b)=>(DATA.by_target[t][b].recall.m??-1)-(DATA.by_target[t][a].recall.m??-1))
      .map(m=>({label:m,det:t,detM:m,points:[{v:DATA.by_target[t][m].recall.m,err:DATA.by_target[t][m].recall.s,color:MC[m],
        tip:`${m} @ ${t}\nrecall ${pct(DATA.by_target[t][m].recall.m)} ±${((DATA.by_target[t][m].recall.s||0)*100).toFixed(1)}`}]}));
    return `<div class="card"><div class="card-t"><span class="dlink" data-det="${esc(t)}">${esc(t)}</span></div>${hDot(rows,{W:480,padL:150,rowH:30})}</div>`;
  }).join('')||'<div class="empty">no reports evaluated</div>';
}
legend('smLegend',M.map(m=>[m,MC[m]]));

// ---- field quality & omission: fields × chosen dimension ----
const SCAN_OF=DATA.scanners||{};
const SCANNERS=[...new Set(TGT.map(t=>SCAN_OF[t]).filter(Boolean))];
const RUNS_N=(C.runs)||1, SHOW_STD=RUNS_N>1;
// Short column label for a report. The abbreviation comes from the report's own
// scanner, with a generic fallback: a hardcoded chain ending in "OV" labelled
// every unlisted scanner as OpenVAS. The trailing-version strip requires a
// separator, so "openvas_tomcat_7.0.70" loses its version but "ZAP_JBoss7"
// keeps the 7 that is part of the product name.
const SCAN_ABBR={openvas:'OV','openvas-v2':'OV',nessus:'NS',qualys:'QL',
                 tenable:'TN',tenablewas:'TN','tenable-vm':'TVM',acunetix:'AX',zap:'ZAP'};
const shortT=tg=>{const sc=(SCAN_OF[tg]||'').toLowerCase();
  const pre=SCAN_ABBR[sc]||(sc?sc.toUpperCase().slice(0,3):'?');
  const n=tg.replace(new RegExp('^'+sc.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'[_-]','i'),'')
            .replace(/[_-]v?\d+(\.\d+)*$/,'');
  return pre+'·'+n;};
function scopeTargets(scope){if(scope==='all')return TGT;const i=scope.indexOf(':'),k=scope.slice(0,i),x=scope.slice(i+1);
  return k==='scanner'?TGT.filter(t=>SCAN_OF[t]===x):[x];}
function dimCols(colDim,tgts){return colDim==='model'?M:colDim==='baseline'?tgts:[...new Set(tgts.map(t=>SCAN_OF[t]))];}
// Only a real report gets shortened; the trailing "Avg" column is a summary,
// not a target, and has no scanner to abbreviate.
function colLabel(colDim,c){return (colDim==='baseline'&&SCAN_OF[c])?shortT(c):c;}
function dimCell(field,col,colDim,tgts,model,getMS){
  let ts,mdl;
  if(colDim==='model'){ts=tgts;mdl=col;}
  else if(colDim==='baseline'){ts=[col];mdl=model;}
  else{ts=tgts.filter(t=>SCAN_OF[t]===col);mdl=model;}
  const vs=ts.map(t=>getMS(t,field,mdl)).filter(d=>d&&d.m!=null);
  if(!vs.length)return{m:null};
  return{m:vs.reduce((a,d)=>a+d.m,0)/vs.length,s:SHOW_STD?Math.max(...vs.map(d=>d.s||0)):null,n:vs.length};}
function svgHeat(mountId,legId,fields,colDim,tgts,model,getMS,ramperFactory,legFn,L,cw){
  const host=el(mountId),cols=dimCols(colDim,tgts);
  const cell=(f,c)=>dimCell(f,c,colDim,tgts,model,getMS);
  const scored=fields.filter(f=>cols.some(c=>cell(f,c).m!=null));
  const unscored=fields.filter(f=>!scored.includes(f));
  if(!scored.length){host.innerHTML='<div class="empty">no data for this scope</div>';if(legId)el(legId).innerHTML='';return;}
  const vals=scored.flatMap(f=>cols.map(c=>cell(f,c).m)).filter(v=>v!=null);
  const cf=ramperFactory(vals);
  const allC=cols.concat(['Avg']),ch=29,g=3;
  const labs=allC.map(c=>colLabel(colDim,c));
  // Prefer horizontal headers: widen columns to fit the longest label as long as
  // the table still fits the card without scrolling; only then go diagonal.
  const maxLabW=Math.ceil(Math.max(...labs.map(l=>l.length))*7.6+14);
  let LONG=false;
  if(maxLabW>cw){
    if(L+maxLabW*allC.length+4<=(host.clientWidth||900))cw=maxLabW;
    else LONG=true;
  }
  const HT=LONG?96:46;
  const W=L+cw*allC.length+(LONG?84:4),H=HT+ch*scored.length+6;  // extra right room for the last slanted label
  let s=`<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" font-family="ui-monospace,Consolas,monospace">`;
  s+=`<text x="${L-8}" y="${HT-8}" text-anchor="end" font-size="10.5" fill="var(--muted)">Field</text>`;
  allC.forEach((c,j)=>{const cx=L+cw*j+cw/2,lab=esc(labs[j]);
    s+=LONG?`<text x="${cx-8}" y="${HT-10}" transform="rotate(-38 ${cx-8} ${HT-10})" text-anchor="start" font-size="12" font-weight="600" fill="var(--ink2)">${lab}</text>`
          :`<text x="${cx}" y="${HT-17}" text-anchor="middle" font-size="12.5" font-weight="600" fill="var(--ink2)">${lab}</text>`;});
  scored.forEach((f,i)=>{const y=HT+ch*i,row=[];
    s+=`<text x="${L-8}" y="${y+ch/2+4}" text-anchor="end" font-size="12" fill="var(--ink2)">${esc(f)}</text>`;
    cols.forEach((c,j)=>{const d=cell(f,c),v=d.m,x=L+cw*j;
      if(v==null){s+=`<rect x="${x+g/2}" y="${y+g/2}" width="${cw-g}" height="${ch-g}" rx="4" fill="var(--card2)"/><text x="${x+cw/2}" y="${y+ch/2+4}" text-anchor="middle" font-size="12.5" fill="var(--muted)">·</text>`;return;}
      row.push(v);const col=cf(v);
      const sd=(SHOW_STD&&d.s!=null)?`<tspan font-weight="400" font-size="9" opacity="0.75"> ±${d.s.toFixed(2)}</tspan>`:'';
      s+=`<rect x="${x+g/2}" y="${y+g/2}" width="${cw-g}" height="${ch-g}" rx="4" fill="${col.bg}"><title>${esc(f)} / ${esc(String(c))}: ${v.toFixed(3)}${d.n?' (n='+d.n+')':''}</title></rect>`;
      s+=`<text x="${x+cw/2}" y="${y+ch/2+4}" text-anchor="middle" font-size="12.5" font-weight="600" fill="${col.tx}">${v.toFixed(2)}${sd}</text>`;});
    const a=avg(row),ac=cf(a),x=L+cw*cols.length;
    s+=`<rect x="${x+g/2}" y="${y+g/2}" width="${cw-g}" height="${ch-g}" rx="4" fill="${ac.bg}"/><text x="${x+cw/2}" y="${y+ch/2+4}" text-anchor="middle" font-size="12.5" font-weight="700" fill="${ac.tx}">${a.toFixed(2)}</text>`;});
  host.innerHTML=s+'</svg>';
  if(legId)el(legId).innerHTML=legFn(cf);
}
function dlBlob(blob,name){const a=document.createElement('a'),u=URL.createObjectURL(blob);a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1500);}
// The HTML legend is a sibling div; render its items into SVG so the export is self-contained.
function _legendSvg(legEl,width,y0,ink){
  const FONT=`font-family:ui-monospace,Consolas,monospace;font-size:11px;fill:${ink}`;
  let x=10,y=y0+15,h=26,s='',grad='';
  [...legEl.children].forEach(sp=>{
    const sw=sp.querySelector('.sw');
    const bgImg=getComputedStyle(sp).backgroundImage||'';
    const isGrad=bgImg.indexOf('gradient')>=0;
    const txt=sp.textContent.trim();
    const estW=(sw?18:isGrad?157:0)+txt.length*6.3+18;
    if(x+estW>width-8){x=10;y+=19;h+=19;}
    if(sw){s+=`<rect x="${x}" y="${y-9}" width="11" height="11" rx="3" fill="${getComputedStyle(sw).backgroundColor}"/>`;x+=17;}
    else if(isGrad){const rgbs=bgImg.match(/rgb\([^)]*\)/g)||['rgb(244,241,234)','rgb(26,94,99)'];
      grad=`<defs><linearGradient id="lgrad"><stop offset="0" stop-color="${rgbs[0]}"/><stop offset="1" stop-color="${rgbs[rgbs.length-1]}"/></linearGradient></defs>`;
      s+=`<rect x="${x}" y="${y-9}" width="150" height="11" rx="3" fill="url(#lgrad)"/>`;x+=157;}
    if(txt){s+=`<text x="${x}" y="${y}" style="${FONT}">${esc(txt)}</text>`;x+=txt.length*6.3+18;}
  });
  return {svg:grad+`<g>${s}</g>`,h};
}
function svgExport(mountId,name,fmt,legId){const svg=el(mountId).querySelector('svg');if(!svg)return;
  const vb=svg.viewBox&&svg.viewBox.baseVal;
  const w=(vb&&vb.width)||+svg.getAttribute('width')||760;
  const h=(vb&&vb.height)||+svg.getAttribute('height')||400;
  const bcs=getComputedStyle(document.body);
  const ink=bcs.getPropertyValue('--ink2').trim()||'#52514e';
  const c=svg.cloneNode(true);
  // Grid/ticks/fonts come from CSS classes that don't travel with a detached SVG;
  // inline each element's computed style so the file renders identically standalone.
  const src=svg.querySelectorAll('*'),dst=c.querySelectorAll('*');
  const PROPS=['fill','fill-opacity','stroke','stroke-width','stroke-opacity','stroke-dasharray','opacity','font-family','font-size','font-weight','text-anchor'];
  for(let i=0;i<src.length;i++){const gc=getComputedStyle(src[i]);let st='';
    PROPS.forEach(p=>{const v=gc.getPropertyValue(p);if(v)st+=`${p}:${v};`;});dst[i].setAttribute('style',st);}
  const leg=legId?el(legId):null;
  const lg=(leg&&leg.children.length)?_legendSvg(leg,w,h+6,ink):{svg:'',h:0};
  const H=h+lg.h,S=3;  // export at 3x so the file opens large and the PNG is high-res
  c.setAttribute('viewBox',`0 0 ${w} ${H}`);c.setAttribute('width',w*S);c.setAttribute('height',H*S);
  c.setAttribute('font-family',bcs.fontFamily);
  // Splice the legend into the serialized string (insertAdjacentHTML would parse
  // it in the HTML namespace and it would not render as SVG). No background rect:
  // the export is transparent.
  let inner=new XMLSerializer().serializeToString(c);
  if(lg.svg)inner=inner.replace(/<\/svg>\s*$/,`${lg.svg}</svg>`);
  const str='<?xml version="1.0" encoding="UTF-8"?>\n'+inner;
  if(fmt==='svg'){dlBlob(new Blob([str],{type:'image/svg+xml'}),name+'.svg');return;}
  const img=new Image();img.onload=()=>{const cv=document.createElement('canvas');cv.width=w*S;cv.height=H*S;
    const x=cv.getContext('2d');x.drawImage(img,0,0,w*S,H*S);cv.toBlob(b=>dlBlob(b,name+'.png'),'image/png');};
  img.src='data:image/svg+xml;base64,'+btoa(unescape(encodeURIComponent(str)));}
function mkDL(wrapId,mountId,name,legId){const wrap=el(wrapId);if(!wrap||wrap.dataset.wired)return;wrap.dataset.wired='1';
  wrap.innerHTML='<button>download</button><div class="menu"><a data-f="svg">SVG</a><a data-f="png">PNG</a></div>';
  wrap.querySelector('button').onclick=e=>{e.stopPropagation();document.querySelectorAll('.dlwrap').forEach(o=>o!==wrap&&o.classList.remove('open'));wrap.classList.toggle('open');};
  wrap.querySelectorAll('a').forEach(a=>a.onclick=()=>{svgExport(mountId,name,a.dataset.f,legId);wrap.classList.remove('open');});}
document.addEventListener('click',()=>document.querySelectorAll('.dlwrap').forEach(d=>d.classList.remove('open')));
function dimController(colsId,scopeId,modelWrapId,modelId,onChange){
  let colDim='scanner',scope='all',model=M[0];
  const scopeSel=el(scopeId),modelWrap=el(modelWrapId);
  function scopeOpts(){const o=[['All','all']];
    if(colDim!=='scanner')SCANNERS.forEach(s=>o.push(['scanner: '+s,'scanner:'+s]));
    if(colDim==='model')TGT.forEach(t=>o.push(['baseline: '+shortT(t),'baseline:'+t]));return o;}
  function syncScope(){const o=scopeOpts();scopeSel.innerHTML=o.map(([l,v])=>`<option value="${v}">${esc(l)}</option>`).join('');
    if(!o.some(x=>x[1]===scope))scope=o[0][1];scopeSel.value=scope;}
  function syncModel(){modelWrap.style.display=(colDim!=='model'&&M.length>1)?'inline-flex':'none';}
  function fire(){onChange({colDim,scope,model});}
  toggle(colsId,['scanner','baseline','model'],colDim,v=>{colDim=v;syncScope();syncModel();fire();});
  scopeSel.onchange=()=>{scope=scopeSel.value;fire();};
  if(M.length>1)fillSel(modelId,M,v=>{model=v;fire();}); else modelWrap.style.display='none';
  syncScope();syncModel();fire();
}
const GRAMP=vals=>{let lo=Math.min(...vals),hi=Math.max(...vals);
  lo=Math.max(0,Math.floor((lo-0.02)*50)/50);hi=Math.min(1,Math.ceil(hi*50)/50);if(hi-lo<0.1)lo=Math.max(0,hi-0.1);
  const f=v=>ramp(v,lo,hi,'green');f.lo=lo;f.hi=hi;return f;};
const RRAMP=()=>{const f=v=>ramp(v,0,0.4,'red');f.lo=0;f.hi=0.4;return f;};
const greenLeg=cf=>`<span style="color:var(--muted)">${cf.lo.toFixed(2)}</span>
  <span style="width:150px;height:11px;border-radius:3px;background:linear-gradient(90deg,rgb(244,241,234),rgb(26,94,99));display:inline-block"></span>
  <span style="color:var(--muted)">${cf.hi.toFixed(2)} · darker = better · scale fit to data</span>`;
const redLeg=()=>`<span style="color:var(--muted)">0.00</span>
  <span style="width:150px;height:11px;border-radius:3px;background:linear-gradient(90deg,rgb(244,241,234),rgb(176,26,69));display:inline-block"></span>
  <span style="color:var(--muted)">higher · redder = more omitted</span>`;
if(!SHOW_STD)document.querySelectorAll('.ctlbar').forEach(b=>b.insertAdjacentHTML('beforebegin',
  '<div class="runsnote">single run per cell (runs=1) - no variance to show; std hidden. Run with --runs N for error bars.</div>'));
// field quality (SVG heatmaps; text & structured share L/cw so their columns align)
(function(){let st={colDim:'scanner',scope:'all',model:M[0]},txtM=DATA.text_metrics[0],detM=DATA.det_metrics[0];
  const maxLen=Math.max(1,...DATA.sem_fields.concat(DATA.det_fields).map(f=>f.length));
  const L=Math.min(248,maxLen*7.4+20),CW=SHOW_STD?106:74;
  function render(){const tgts=scopeTargets(st.scope);
    const gT=(t,f,m)=>{const c=DATA.text_fields[txtM]&&DATA.text_fields[txtM][t];return c&&c[f]&&c[f][m]?c[f][m]:{m:null};};
    const gD=(t,f,m)=>{const c=DATA.det_field_block[detM]&&DATA.det_field_block[detM][t];return c&&c[f]&&c[f][m]?c[f][m]:{m:null};};
    svgHeat('txtHeat','txtLegend',DATA.sem_fields,st.colDim,tgts,st.model,gT,GRAMP,greenLeg,L,CW);
    svgHeat('detHeat','detLegend',DATA.det_fields,st.colDim,tgts,st.model,gD,GRAMP,greenLeg,L,CW);}
  toggle('txtMetric',DATA.text_metrics,txtM,v=>{txtM=v;render();});
  toggle('detMetric',DATA.det_metrics,detM,v=>{detM=v;render();});
  dimController('fqCols','fqScope','fqModelWrap','fqModel',s=>{st=s;render();});
  mkDL('dl_txtHeat','txtHeat','field-quality-text','txtLegend');mkDL('dl_detHeat','detHeat','field-quality-structured','detLegend');})();

// ---- omission ----
(function(){let st={colDim:'scanner',scope:'all',model:M[0]};
  const maxLen=Math.max(1,...DATA.omit_fields.map(f=>f.length));
  const L=Math.min(248,maxLen*7.4+20),CW=SHOW_STD?106:74;
  function render(){const tgts=scopeTargets(st.scope);
    const g=(t,f,m)=>{const c=DATA.omission[t];return c&&c[f]&&c[f][m]?c[f][m]:{m:null};};
    svgHeat('omheat','omLegend',DATA.omit_fields,st.colDim,tgts,st.model,g,RRAMP,redLeg,L,CW);}
  dimController('omCols','omScope','omModelWrap','omModel',s=>{st=s;render();});
  mkDL('dl_omheat','omheat','omission','omLegend');})();

// ---- distribution: box only ----
(function(){let metric=DATA.text_metrics[0]||null,target='__all__';
  const DBT=DATA.dist_by_target||null;
  const box=m=>(target!=='__all__'&&DBT&&DBT[metric]&&DBT[metric][target])?DBT[metric][target][m]:DATA.dist[metric][m];
  function render(){if(!metric){el('distBox').innerHTML='<div class="empty">no per-pair scores</div>';return;}
    el('distBox').innerHTML=hBox(M.map(m=>({label:m,box:box(m),color:MC[m]})));}
  const sel=el('distTarget');
  if(DBT){sel.innerHTML='<option value="__all__">all reports</option>'+TGT.map(t=>`<option value="${t}">${esc(t)}</option>`).join('');
    sel.onchange=()=>{target=sel.value;render();};}
  if(DATA.text_metrics.length)toggle('distMetric',DATA.text_metrics,metric,v=>{metric=v;render();});
  render();mkDL('dl_distBox','distBox','distribution');})();

// ---- errors + cost ----
if(M.length>1){el('paretoCard').style.display='';
  const cmax=Math.max(...M.map(m=>OV[m].cost.m||0))*1.15||1;
  const recs=M.map(m=>orec(m)).filter(v=>v!=null);
  const rlo=Math.max(0,Math.floor((Math.min(...recs)-0.03)*20)/20);
  const W=760,H=380,pad={t:16,r:20,b:48,l:56},pw=W-pad.l-pad.r,ph=H-pad.t-pad.b;
  const X=v=>pad.l+(v/cmax)*pw,Y=v=>pad.t+ph-((v-rlo)/(1-rlo))*ph;
  let s=`<svg viewBox="0 0 ${W} ${H}" class="chart">`;
  [0,.25,.5,.75,1].forEach(t=>{s+=`<line class="grid" x1="${pad.l+t*pw}" y1="${pad.t}" x2="${pad.l+t*pw}" y2="${pad.t+ph}"/><text class="tick" x="${pad.l+t*pw}" y="${pad.t+ph+16}" text-anchor="middle">$${(t*cmax).toFixed(3)}</text>`;
    const rv=rlo+(1-rlo)*t;s+=`<line class="grid" x1="${pad.l}" y1="${Y(rv)}" x2="${pad.l+pw}" y2="${Y(rv)}"/><text class="tick" x="${pad.l-8}" y="${Y(rv)+3}" text-anchor="end">${rv.toFixed(2)}</text>`;});
  s+=`<text class="axt" x="${pad.l+pw/2}" y="${H-8}" text-anchor="middle">Cost per run →</text><text class="axt" x="${-(pad.t+ph/2)}" y="14" text-anchor="middle" transform="rotate(-90)">Recall →</text>`;
  M.forEach(m=>{const c=OV[m].cost.m,r=orec(m);if(c==null||r==null)return;
    s+=`<circle cx="${X(c)}" cy="${Y(r)}" r="8" fill="${MC[m]}" fill-opacity=".85" stroke="${MC[m]}" data-tip="${esc(m+'\ncost $'+c.toFixed(4)+'/run · recall '+f3(r))}"/><text x="${X(c)+11}" y="${Y(r)+3}" class="ylab" style="font-size:10px">${esc(m)}</text>`;});
  el('pareto').innerHTML=s+'</svg>';legend('paretoLegend',M.map(m=>[m,MC[m]]));mkDL('dl_pareto','pareto','pareto','paretoLegend');}
el('err').innerHTML=hBars(M.map(m=>({label:m,bars:[
  {v:OV[m].false_negatives.m??0,color:'var(--accent)',tip:`${m} · false negatives ${(OV[m].false_negatives.m??0).toFixed(1)}/run`},
  {v:OV[m].false_positives.m??0,color:'var(--muted)',tip:`${m} · false positives ${(OV[m].false_positives.m??0).toFixed(1)}/run`}]})));
mkDL('dl_err','err','errors','errLegend');
el('cost').innerHTML=M.map(m=>{const c=OV[m].cost.m,d=OV[m].duration.m;
  return `<div class="card" style="margin:0"><div class="card-t" style="margin:0 0 .4rem">${esc(m)}</div>
    <div style="font:700 1.05rem ui-monospace,monospace;color:${MC[m]}">${c?'$'+c.toFixed(4):'-'}</div>
    <div style="font:.65rem ui-monospace,monospace;color:var(--muted)">${d!=null?Math.round(d)+'s/run':''}</div></div>`;}).join('');

// ---- severity composition per scanner (100% stacked) ----
(function(){
  const SEV=DATA.sev_by_scanner||{},scs=Object.keys(SEV);
  if(!scs.length){el('sevBar').innerHTML='<div class="empty">no severity data</div>';return;}
  const CATS=['Critical','High','Medium','Low','Info'],COL={Critical:'#c81d54',High:'#d9541e',Medium:'#d9a200',Low:'#7a9a2f',Info:'var(--muted)'};
  const bucket=k=>{k=(k||'').toUpperCase();return k==='CRITICAL'?'Critical':k==='HIGH'?'High':k==='MEDIUM'?'Medium':k==='LOW'?'Low':'Info';};
  const rows=scs.map(sc=>{const c=SEV[sc],b={Critical:0,High:0,Medium:0,Low:0,Info:0};let n=0;
    for(const k in c){b[bucket(k)]+=c[k];n+=c[k];}
    return{label:`${sc} · n=${n}`,vals:CATS.map(x=>n?b[x]/n:0)};})
    .sort((a,b)=>(b.vals[0]+b.vals[1])-(a.vals[0]+a.vals[1]));  // most severe on top
  el('sevBar').innerHTML=hStack(rows,CATS,CATS.map(x=>COL[x]),{W:760,rowH:36,padL:150});
  legend('sevLegend',CATS.map(x=>[x,COL[x]]));
  mkDL('dl_sev','sevBar','severity-by-scanner','sevLegend');
})();

// ---- time & cost per report ----
(function(){
  const TC=DATA.time_cost||{},tg=Object.keys(TC),tbl=el('timecost');
  if(!tg.length){tbl.innerHTML='<tbody><tr><td class="empty">no runs</td></tr></tbody>';return;}
  const fmtT=s=>s==null?'-':s>=90?(s/60).toFixed(1)+' min':Math.round(s)+' s';
  let h=`<thead><tr><th class="l">Report</th>${M.map(m=>`<th>${esc(m)} time</th><th>${esc(m)} cost</th>`).join('')}</tr></thead><tbody>`;
  tg.forEach(t=>{h+=`<tr><td class="l"><span class="dlink" data-det="${esc(t)}">${esc(t)}</span></td>`;
    M.forEach(m=>{const v=TC[t][m]||{};h+=`<td>${fmtT(v.dur)}</td><td>${v.cost?'$'+v.cost.toFixed(4):'-'}</td>`;});h+='</tr>';});
  h+=`<tr class="tot"><td class="l">Total</td>`;
  M.forEach(m=>{let dt=0,ct=0;tg.forEach(t=>{const v=TC[t][m]||{};dt+=v.dur||0;ct+=v.cost||0;});
    h+=`<td>${fmtT(dt)}</td><td>$${ct.toFixed(4)}</td>`;});
  tbl.innerHTML=h+'</tr></tbody>';
})();

// ---- per-report drill-down (modal) ----
(function(){
  const DET=DATA.detail||{},mask=el('mask'),THR=DATA.threshold??0.7;
  if(!Object.keys(DET).length)return;
  let cT=null,cM=M[0],cMet=null;
  const cell=()=>DET[cT+'|'+cM];
  const card=(t,inner)=>`<div class="card"><div class="card-t">${t}</div>${inner}</div>`;

  function controls(d){
    // Show every metric the experiment ran, and disable the ones this report has
    // no data for: a scanner with no nested field is never scored 'structural',
    // and a missing button looked like the metric did not exist at all.
    const seen=new Set();d.pairs.forEach(([,by])=>{for(const k in by)seen.add(k);});
    const all=DATA.text_metrics.concat(DATA.det_metrics);
    const mets=all.filter(x=>seen.has(x));
    if(!mets.includes(cMet))cMet=mets[0]||null;
    let h='';
    if(M.length>1)h+='<span class="selg"><span class="lb">Model</span><select id="mModel">'+
      M.map(m=>`<option value="${esc(m)}"${m===cM?' selected':''}>${esc(m)}</option>`).join('')+'</select></span>';
    if(all.length)h+='<span class="toggle" id="mMetric"><span class="lb">Metric</span>'+
      all.map(x=>{const on=seen.has(x);
        const tip=(METRIC_DOC[x]||'')+(on?'':'\n\nNot scored on this report: no field here is measured by it.');
        return `<button data-v="${esc(x)}" aria-pressed="${x===cMet}"${on?'':' disabled'}`+
          ` data-tip="${esc(x+': '+tip)}">${esc(x)}</button>`;}).join('')+'</span>';
    el('mCtl').innerHTML=h;
    const sel=el('mModel');if(sel)sel.onchange=()=>{cM=sel.value;render();};
    const tg=el('mMetric');
    if(tg)tg.querySelectorAll('button:not([disabled])').forEach(
      b=>b.onclick=()=>{cMet=b.dataset.v;render();});
  }

  // n is the run count; it lives in render(), so pass it rather than closing
  // over a name that is not in scope here.
  function pairTable(d,n){
    if(!cMet)return '';
    // Every matched finding stays a row whatever the metric: one this metric
    // scores nothing of reads as a blank row, not a vanished one. The row set
    // is the union over runs, so it can exceed the per-run matched count.
    const rows=d.pairs.map(([nm,by,seenIn])=>[nm,by[cMet]||{},seenIn||n]);
    if(!rows.length)return card(`Per-finding scores · ${esc(cMet)}`,'<div class="empty">no matched pairs</div>');
    const fields=[...new Set(rows.flatMap(r=>Object.keys(r[1])))].sort();
    const rowAvg=r=>{const v=fields.map(f=>r[1][f]).filter(x=>x!=null);
      return v.length?v.reduce((a,b)=>a+b,0)/v.length:2;};  // nothing scored sorts last
    rows.sort((a,b)=>rowAvg(a)-rowAvg(b));   // worst first: the rows worth reading
    const vals=rows.flatMap(r=>fields.map(f=>r[1][f])).filter(v=>v!=null);
    const cf=GRAMP(vals.length?vals:[0,1]);
    // The run count needs its own column: the name cell is ellipsised at a max
    // width, so anything appended to it is the first thing clipped away.
    const runCol=n>1;
    let t=`<table class="ptab"><thead><tr><th class="l">Finding</th>`
      +(runCol?'<th class="runs">runs</th>':'')
      +`${fields.map(f=>`<th>${esc(f)}</th>`).join('')}</tr></thead><tbody>`;
    rows.forEach(([nm,by,seenIn])=>{
      t+=`<tr><td class="l" title="${esc(nm)}">${esc(nm)}</td>`;
      if(runCol)t+=`<td class="runs">`
        +(seenIn<n?`<span class="pill rep">${seenIn}/${n}</span>`:`${seenIn}/${n}`)
        +'</td>';
      fields.forEach(f=>{const v=by[f];
        if(v==null){t+='<td style="color:var(--muted)">·</td>';return;}
        const c=cf(v);t+=`<td style="background:${c.bg};color:${c.tx}">${v.toFixed(2)}</td>`;});
      t+='</tr>';});
    const blank=rows.length-rows.filter(r=>Object.keys(r[1]).length).length;
    const partial=rows.filter(r=>r[2]<n).length;
    // Counts go in pills, like the missing/extra cards; the prose that explains
    // them goes in the caption above, not in the title.
    const why=[METRIC_DOC[cMet]||''];
    if(n>1)why.push(`Every finding matched in at least one of the ${n} runs is a row, `+
                    `so the list is longer than the ${d.match} matched per run, and a `+
                    `k/${n} badge marks the ones not matched every run.`);
    why.push('A blank cell is a field empty on both sides, which is not scored.');
    const pill=(v,l)=>`<span class="pill">${v} ${l}</span>`;
    return `<p class="sub" style="margin:.1rem 0 .7rem">${esc(why.filter(Boolean).join(' '))}</p>`
      + card(`Per-finding scores · ${esc(cMet)} <s>worst first</s> `
             + pill(rows.length, 'findings')
             + (partial ? pill(partial, 'partial') : '')
             + (blank ? pill(blank, 'unscored') : ''),
             '<div class="htab-wrap">'+t+'</tbody></table></div>');
  }

  function render(){
    const d=cell(),bt=(DATA.by_target[cT]||{})[cM]||{};
    el('mTitle').innerHTML=esc(cT)+` <span style="color:var(--muted);font-weight:400">· ${esc(SCAN_OF[cT]||'')} · ${esc(cM)}</span>`;
    if(!d){el('mCtl').innerHTML='';el('mBody').innerHTML='<div class="empty">this model has no evaluated run for this report</div>';return;}
    controls(d);
    // Counts come rounded to one decimal; subtracting them in binary floating
    // point does not, so 246 - 240.4 renders as 5.599999999999966.
    const r1=v=>Math.round(v*10)/10;
    const n=d.runs||1,miss=r1(Math.max(0,d.base-d.match)),extra=r1(Math.max(0,d.extr-d.match));
    let h=`<p class="sub">Counts are per run${n>1?`, averaged over ${n} runs`:''}. Missing and extra are
      alignment outcomes at threshold ${THR}: a baseline finding left unpaired is missing, an extraction
      left unpaired is extra. Pairing is one-to-one, so an extraction can sit above the threshold and still
      be extra when that baseline is already claimed. The lists group by name, so a name the model repeats
      is one entry; the bar shows its closest baseline's similarity and the tick marks the threshold.</p>`;
    // Missing/extra count occurrences; the lists below group by name. When a name
    // repeats the two differ, so each KPI says how many distinct names it covers.
    const fnOcc=d.fn.reduce((s,r)=>s+r[2],0),fpOcc=d.fp.reduce((s,r)=>s+r[5],0);
    const nsub=(names,occ)=>names<occ?`${names} distinct name${names===1?'':'s'}`:'';
    h+='<div class="kpi">'+[['baseline vulns',d.base],['extracted',d.extr],['matched',d.match],
      ['missing',miss,nsub(d.fn.length,fnOcc)],['extra',extra,nsub(d.fp.length,fpOcc)],
      ['recall',pct(bt.recall&&bt.recall.m)],['precision',pct(bt.precision&&bt.precision.m)]]
      .map(([k,v,s])=>`<div><div class="k">${k}</div><div class="v">${v}</div>`+
        `${s?`<div class="s2">${s}</div>`:''}</div>`).join('')+'</div>';
    h+='<div class="grid2">';
    // Frequency pill: runs the name appeared in, and repeats within a single run.
    const freq=(hit,tot)=>{const b=[];
      if(n>1)b.push(`${hit}/${n} runs`);
      if(tot>hit)b.push(`${tot}x`);
      return b.length?`<span class="pill rep">${b.join(' · ')}</span>`:'';};
    const head=(t,names,occ)=>`${t} <span class="pill">${names} name${names===1?'':'s'}`+
      `${occ>names?` · ${occ} total`:''}</span>`;
    const simbar=s=>{const p=Math.max(0,Math.min(1,s||0));
      return `<span class="simbar" data-tip="similarity ${p.toFixed(2)} · threshold ${THR.toFixed(2)}">`+
        `<i style="width:${(p*100).toFixed(0)}%"></i><u style="left:${(THR*100).toFixed(0)}%"></u></span>`;};
    h+=card(head('Missing <s>baseline findings not recovered</s>',d.fn.length,fnOcc),d.fn.length
      ?'<ul class="mlist">'+d.fn.map(([nm,hit,tot])=>
        `<li><div class="nm"><b>${esc(nm)}</b>${freq(hit,tot)}</div></li>`).join('')+'</ul>'
      :'<div class="empty">none</div>');
    h+=card(head('Extra <s>extracted with no baseline match</s>',d.fp.length,fpOcc),d.fp.length
      ?'<ul class="mlist">'+d.fp.map(([nm,kind,best,sim,hit,tot])=>
        `<li><div class="nm"><b>${esc(nm)}</b>${freq(hit,tot)}</div><div class="mx">`+
        `<span class="pill">${esc(kind||'?')}</span>`+
        `${best?`<span>closest: ${esc(best)}</span>${simbar(sim)}<span>${(sim||0).toFixed(2)}</span>`:''}`+
        '</div></li>').join('')+'</ul>'
      :'<div class="empty">none</div>');
    h+='</div>';
    el('mBody').innerHTML=h+pairTable(d,n);
  }

  function open(t,m){
    cT=t;
    if(m&&DET[t+'|'+m])cM=m;
    else if(!DET[t+'|'+cM]){const alt=M.find(x=>DET[t+'|'+x]);if(alt)cM=alt;}
    render();mask.classList.add('on');document.body.style.overflow='hidden';
    el('mClose').focus();
  }
  function close(){mask.classList.remove('on');document.body.style.overflow='';}
  el('mClose').onclick=close;
  mask.onclick=e=>{if(e.target===mask)close();};
  document.addEventListener('keydown',e=>{if(e.key==='Escape')close();});
  document.addEventListener('click',e=>{
    const h=e.target.closest&&e.target.closest('[data-det]');
    if(h)open(h.getAttribute('data-det'),h.getAttribute('data-det-m'));});
})();
"""
