# Adding a Model

Every provider MulitaMiner talks to speaks the OpenAI-compatible chat API, so
adding a model means **dropping one JSON file**, no Python. Built-in profiles
live in `src/mulitaminer/configs/llms/`; your own profiles go in any directory
pointed to by the `MULITAMINER2_LLMS_DIR` environment variable (same plug-in
mechanism as scanners).

## The three cases

| Case | base_url | api_key_env |
| --- | --- | --- |
| Cloud provider | The provider's endpoint | The env var holding the key |
| Local server (Ollama, LM Studio) | The localhost endpoint | **Omit the field** (keyless) |
| Any OpenAI-compatible server (vLLM, llama.cpp, TGI) | Wherever it runs | Omit, or a var if it needs one |

## Cloud model

`mistral-large.json` in your `MULITAMINER2_LLMS_DIR`:

```json
{
  "key": "mistral-large",
  "model": "mistral-large-latest",
  "base_url": "https://api.mistral.ai/v1",
  "api_key_env": "MISTRAL_API_KEY",
  "context_window": 128000,
  "max_output_tokens": 8000,
  "price_in": 2.0,
  "price_out": 6.0
}
```

Then `uv run mulitaminer extract report.pdf -s openvas -m mistral-large`.

Anthropic's Claude works through its OpenAI-compatible endpoint, see the
built-in `haiku.json` (`base_url` `https://api.anthropic.com/v1/`, key in
`CLAUDE_API_KEY`).

## Local model

Ollama and LM Studio expose an OpenAI-compatible server on localhost and need
no key: local configs simply **have no `api_key_env` field**. The built-in
local profiles (`qwen2.5-1.5b`, the base model, and `mulita-extractor`,
its [fine-tuned version](../README.md#fine-tuned-local-model)) point at the
Ollama endpoint; `--model-name` overrides the provider model id at runtime
when the server hosts something else.

```bash
# Local model via Ollama, no API key
uv run mulitaminer extract report.pdf -s openvas -m qwen2.5-1.5b
```

**One profile per model is the pattern**: `max_output_tokens` drives chunk
sizing, so each local model should carry its own honest numbers rather than
one-size metadata. `qwen3.json`:

```json
{
  "key": "qwen3",
  "model": "qwen3",
  "base_url": "http://localhost:11434/v1",
  "context_window": 40000,
  "max_output_tokens": 16000,
  "reasoning_tags": true
}
```

Any other OpenAI-compatible server (vLLM, llama.cpp, TGI, LM Studio) works by
setting `base_url` to its address.

## Structured output: the one field that matters

`supports_json_schema` decides how the model is asked to return JSON:

- `true`: strict JSON-Schema response format. The server constrains decoding
  to the schema, so the format cannot come out malformed. Use it for OpenAI,
  LM Studio, and Ollama (all constrain natively). Strongly preferred for
  small local models: on a 1.5B it recovered 6 findings a small model
  otherwise dropped to invalid JSON, and ran ~3.5x faster.
- `false` (the default): `json_object` mode plus validation on our side. Use
  it for providers without strict schema support (DeepSeek, Groq).

If unsure, leave it out. A wrong `true` fails fast with a provider error;
`false` always works, just with our validation and retry doing the enforcing.

## Field reference

Required: `key`, `model`, `context_window`, `max_output_tokens`. Everything
else is optional with sensible defaults.

| Field | Meaning |
| --- | --- |
| `key` | CLI name (`--model`) |
| `model` | Provider model id (`--model-name` overrides at runtime) |
| `base_url` | Provider endpoint; omit for api.openai.com |
| `api_key_env` | Env var with the key; **omit for local/keyless** |
| `context_window` | Provider context limit (informational) |
| `max_output_tokens` | Output cap; this drives chunk sizing, so keep it honest |
| `supports_json_schema` | Strict schema vs `json_object` + validation (default `false`) |
| `price_in` / `price_out` | USD per 1M tokens, for the run cost report (default 0) |

The reported cost is `prompt_tokens * price_in + completion_tokens * price_out`,
a flat rate per token. One pair of numbers cannot express a provider that prices
prompt-cache hits, off-peak hours or batch tiers differently, so pick the tier
your runs actually use and record which one; the figure is for comparing models
in a run, never the invoice. The built-in `deepseek` profile uses the off-peak
cache-miss rates, exact on output and an upper bound on input.

The exact cost does not depend on getting this right. Every numeric field the
provider reports is summed into `usage.provider` in each run's `run.json`, under
the provider's own names, so a finished run can be repriced from its own record
against any table.
| `reasoning_tags` | `true` strips `<think>` blocks (reasoning models like Qwen3) |
| `temperature` | Sampling temperature; set per model to override. **Default `0`** |
| `encoding` | tiktoken encoding for token counting; default `cl100k_base` |
| `request_timeout_s` | Per-request deadline; default `120`. Raise it for a model served from slow hardware |

**Temperature is `0` by default for every model** (deterministic extraction, the
single most important knob for fidelity). This is sent on every call, so it also
overrides a provider's own default (e.g. Ollama's `0.7`). Raise it in a model's
JSON only if you have a reason to; extraction almost always wants `0`.

A config with an unknown or missing field fails at load with an error naming
the file and the valid field list.

## Verify

```bash
uv run mulitaminer models    # your new profile should be listed
```

Then run a small extraction. If a cloud key is missing you get a clear
`No API key for model '...'` naming the env var to set.
