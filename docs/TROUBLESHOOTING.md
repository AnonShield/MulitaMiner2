# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `No API key for model '...'` | Env var missing from `.env` | Add the var shown in the message (see `mulitaminer models`) |
| `Unknown scanner '...'` | Typo or config not registered | `mulitaminer scanners`; check `MULITAMINER_SCANNERS_DIR` |
| `Cannot determine the scanner for '...'` | Directory mode: the PDF's parent folder is not a registered scanner | Put the PDF under a scanner-named folder, or pass `-s` to force one for the whole batch (see [USAGE.md](USAGE.md#directory-mode-batch)) |
| `No finding blocks found` | Wrong `--scanner` for this PDF, or marker mismatch | Run `mulitaminer segment` and check the block count/preview |
| Block count differs from the report | Marker regex too loose or too strict | Iterate on `marker_pattern` with `mulitaminer segment` (see SCANNER_CONFIGS.md) |
| Warning `input truncated ... instances omitted` | A single block exceeds the model's output budget | Expected for findings with many instances; core fields survive. A larger-output model avoids it |
| Warning `block N yielded no record ... dropped` | Model failed that block in every retry | Re-run (transient model variance) or try another model; the block id is named |
| Connection error with a local model | Local server not running | Start Ollama / LM Studio and confirm the port in `mulitaminer models` |
| `request (N tokens) exceeds the available context size (4096 tokens)` | Recent Ollama (seen on 0.40.14) ignores the per-request `num_ctx` on its OpenAI-compatible endpoint, so a registered model keeps its 4096 default | Start Ollama with `OLLAMA_CONTEXT_LENGTH=16384` (the compose file does), or bake it into a model variant: `ollama create mulita-v4-16k -f -` with `FROM mulita-qwen2.5-1.5b-v4` + `PARAMETER num_ctx 16384`, then `--model-name mulita-v4-16k` |
| Merged records you did not expect | Consolidation found fully identical repeats | Compare `results.raw.json` with `results.json` using `run.json`'s merge log |
| Slow extraction | Many retry rounds (see log) | Normal for payload-heavy reports; consider a model with a larger output cap |
| `KEV/EPSS feeds not found` on `prioritize` | Feeds never synced | Run `mulitaminer sync-feeds` first (needs internet once) |
| `prioritize` fails validating an old results.json | The file predates a schema fix | Re-run the extraction; the current pipeline produces valid output |

Still stuck? Run with `--debug` and inspect `blocks.txt` (is the information
inside the block?) and `llm_traffic.jsonl` (what did the model actually
return?) in the run directory.
