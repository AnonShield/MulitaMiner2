import json

import pandas as pd

from mulitaminer.evaluation.errors import classify_run

REPORT = """Summary: The remote server leaks memory through the OPTIONS method.
Quality of Detection (QoD): 80%
Solution: Update to version 2.4.28 or later.
References: cert-bund: CB-K16/1776
https://example.org/advisories/optionsbleed-http-options-method-can-le
ak-apache-server-memory.html"""


def _run(tmp_path, ext_desc, gold_desc, ext_refs=(), gold_refs=(), sim=0.0):
    (tmp_path / "results.json").write_text(json.dumps([
        {"Name": "X", "description": ext_desc, "references": list(ext_refs)}]))
    (tmp_path / "evaluation.json").write_text(json.dumps({"pairs": [{
        "extraction_index": 0, "baseline_index": 0, "name": "X",
        "scores": {"description": {"token_f1": {}}, "references": {"set_f1": {}}}}]}))
    xlsx = tmp_path / "gold.xlsx"
    pd.DataFrame([{"Name": "X", "description": str(gold_desc),
                   "references": str(list(gold_refs))}]).to_excel(xlsx, index=False)
    return classify_run(tmp_path, xlsx, REPORT, similarity=lambda pairs: [sim] * len(pairs))


def test_copy_of_gold_is_correct_and_report_text_elsewhere_is_copied_off(tmp_path):
    gold = ["The remote server leaks memory through the OPTIONS method."]
    res = _run(tmp_path, gold + ["Quality of Detection (QoD): 80%"], gold)
    assert res["counts"]["description"] == {"correct": 1, "copied_off": 1}


def test_text_absent_from_report_is_paraphrase_or_invented_by_similarity(tmp_path):
    gold = ["The remote server leaks memory through the OPTIONS method."]
    new = ["Apache discloses heap contents when answering OPTIONS requests."]
    assert _run(tmp_path, new, gold, sim=0.9)["counts"]["description"]["paraphrase"] == 1
    far = _run(tmp_path, new, gold, sim=0.1)["counts"]["description"]
    assert far["invented"] == 1 and far["omitted"] == 1


def test_empty_extraction_omits_and_empty_gold_is_extra(tmp_path):
    gold = ["The remote server leaks memory through the OPTIONS method."]
    assert _run(tmp_path, [], gold)["counts"]["description"] == {"omitted": 1}
    assert _run(tmp_path, gold, [])["counts"]["description"]["extra"] == 1


def test_kept_reference_label_is_instruction_ignored_and_wrapped_url_is_not_invented(tmp_path):
    url = "https://example.org/advisories/optionsbleed-http-options-method-can-leak-apache-server-memory.html"
    res = _run(tmp_path, ["The remote server leaks memory through the OPTIONS method."],
               ["The remote server leaks memory through the OPTIONS method."],
               ext_refs=["cert-bund: CB-K16/1776", url, "CB-K16/1777"],
               gold_refs=["CB-K16/1776", "CB-K16/1777"])
    # the labeled reference is not also counted as an omission of its gold item
    assert res["counts"]["references"] == {"instruction_ignored": 1, "copied_off": 1, "correct": 1}
