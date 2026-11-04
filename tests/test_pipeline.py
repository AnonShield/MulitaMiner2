"""End-to-end pipeline test on a real baseline PDF with a fake LLM (no network)."""
import json
from pathlib import Path

from mulitaminer.models import TokenUsage
from mulitaminer.pipeline import RunConfig, run

BASELINE_PDF = Path("resources/openvas/OpenVAS_JuiceShop.pdf")


class EchoClient:
    """Answers every chunk correctly from the block IDs it sees in the prompt."""

    class _Profile:
        max_output_tokens = 100_000
        encoding = "cl100k_base"

    profile = _Profile()

    def runtime_info(self):
        return {"profile": "echo"}

    def extract(self, system_prompt, user_content, response_model, usage=None):
        import re

        if usage is not None:
            usage.add(10, 5, 0.001)

        ids = [int(m) for m in re.findall(r"### BLOCK (\d+)", user_content)]
        items = [
            {"block_id": i, "Name": f"Vuln {i}", "severity": "HIGH", "cvss": 7.5}
            for i in ids
        ]
        parsed = response_model.model_validate({"items": items})
        return parsed, {"prompt_tokens": 10, "completion_tokens": 5,
                        "cost_usd": 0.001, "raw": json.dumps({"items": items})}


def test_end_to_end_run_with_fake_llm(tmp_path):
    config = RunConfig(
        input_path=BASELINE_PDF,
        scanner="openvas",
        model="deepseek",           # profile only; client is injected
        formats=("xlsx",),
        output_dir=tmp_path,
        debug=True,
    )
    result, run_dir = run(config, client=EchoClient())

    # Count parity: every one of the 34 segmented blocks became a record.
    assert result.block_count == 34
    assert len(result.records) == 34
    assert not result.warnings

    # Artifacts.
    assert (run_dir / "results.json").exists()
    assert (run_dir / "results.xlsx").exists()
    run_meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run_meta["raw_record_count"] == 34
    assert run_meta["usage"]["calls"] > 0

    # Debug dumps (in-memory pipeline: these exist ONLY because debug=True).
    assert (run_dir / "layout.txt").exists()
    assert (run_dir / "blocks.txt").exists()
    assert (run_dir / "llm_traffic.jsonl").exists()

    data = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    assert data[0]["source"] == "OPENVAS"
    assert data[0]["host"]  # recovered from the report preamble


def test_no_intermediate_files_without_debug(tmp_path):
    config = RunConfig(
        input_path=BASELINE_PDF,
        scanner="openvas",
        model="deepseek",
        output_dir=tmp_path,
        debug=False,
    )
    _, run_dir = run(config, client=EchoClient())
    names = {p.name for p in run_dir.iterdir()}
    # run.log is always written; the debug-only inspection dumps are not.
    assert names == {"results.json", "run.json", "run.log"}
    for dump in ("layout.txt", "blocks.txt", "llm_traffic.jsonl", "debug.log"):
        assert not (run_dir / dump).exists()


def test_usage_accumulates(tmp_path):
    usage = TokenUsage()
    usage.add(10, 5, 0.001)
    usage.add(10, 5, 0.001)
    assert usage.calls == 2 and usage.prompt_tokens == 20


def test_progress_receives_events(tmp_path):
    from mulitaminer.ui import Progress

    seen = {"stages": [], "segmented": None, "chunks": 0}

    class Rec(Progress):
        def stage(self, name):
            seen["stages"].append(name)

        def segmented(self, total):
            seen["segmented"] = total

        def chunk_done(self, got, expected):
            seen["chunks"] += 1

    config = RunConfig(input_path=BASELINE_PDF, scanner="openvas", model="deepseek",
                       output_dir=tmp_path, debug=False)
    result, _ = run(config, client=EchoClient(), progress=Rec())
    assert seen["segmented"] == result.block_count
    assert seen["chunks"] >= 1
    assert {"reading", "segmenting"} <= set(seen["stages"])


def test_limit_keeps_only_the_first_blocks(tmp_path):
    config = RunConfig(input_path=BASELINE_PDF, scanner="openvas", model="deepseek",
                       output_dir=tmp_path, limit=5)
    result, run_dir = run(config, client=EchoClient())
    assert result.block_count == 5
    assert json.loads((run_dir / "run.json").read_text(encoding="utf-8"))["config"]["limit"] == 5
