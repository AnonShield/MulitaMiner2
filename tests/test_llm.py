"""LLM client tests with a stubbed transport; no network."""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from mulitaminer.llm import (
    FatalLLMError,
    LLMClient,
    all_models,
    clean_response,
    get_model,
    load_llm_profile,
    _provider_counters,
    _resolve_api_key,
)
from mulitaminer.models import TokenUsage

# Profiles now come from configs/llms/*.json; the dict shape is unchanged.
MODELS = all_models()


class Items(BaseModel):
    items: list[int]


class FakeTransport:
    def __init__(self, content: str):
        self._content = content
        self.last_kwargs = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self._content))],
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=50),
        )


def test_local_profiles_are_keyless():
    assert _resolve_api_key(MODELS["qwen2.5-1.5b"]) == "local"


def test_cloud_profile_without_env_raises_actionable_error(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(FatalLLMError, match="DEEPSEEK_API_KEY"):
        _resolve_api_key(MODELS["deepseek"])


def test_clean_response_strips_think_and_fences():
    raw = "<think>let me reason...</think>\n```json\n{\"items\": [1]}\n```"
    assert json.loads(clean_response(raw, reasoning_tags=True)) == {"items": [1]}
    # Without reasoning_tags the think block is kept (cloud models don't emit it).
    assert "<think>" in clean_response(raw, reasoning_tags=False)


def test_extract_parses_validates_and_accounts_usage():
    transport = FakeTransport('{"items": [1, 2, 3]}')
    # Pinned prices: the arithmetic is what is under test, not the shipped rates,
    # which change whenever the provider's table does.
    profile = replace(MODELS["deepseek"], price_in=2.0, price_out=6.0)
    client = LLMClient(profile, transport=transport)
    parsed, usage = client.extract("sys", "user", Items)
    assert parsed.items == [1, 2, 3]
    assert usage["prompt_tokens"] == 100 and usage["completion_tokens"] == 50
    assert usage["cost_usd"] == pytest.approx(100 / 1e6 * 2.0 + 50 / 1e6 * 6.0)
    # DeepSeek has no json_schema support -> json_object mode.
    assert transport.last_kwargs["response_format"] == {"type": "json_object"}
    assert transport.last_kwargs["temperature"] == 0.0


def test_extract_uses_json_schema_when_supported():
    transport = FakeTransport('{"items": []}')
    client = LLMClient(MODELS["gpt-4o-mini"], transport=transport)
    client.extract("sys", "user", Items)
    assert transport.last_kwargs["response_format"]["type"] == "json_schema"


def test_extract_propagates_invalid_json_for_retry_policy():
    client = LLMClient(MODELS["deepseek"], transport=FakeTransport("not json at all"))
    with pytest.raises(json.JSONDecodeError):
        client.extract("sys", "user", Items)


def test_envelope_slips_are_rewrapped():
    """Models sometimes skip the {"items": [...]}
    envelope, especially on single-block calls. Shape is adapted; content
    is never repaired."""

    class Item(BaseModel):
        block_id: int

    class Envelope(BaseModel):
        items: list[Item]

    bare_object = FakeTransport('{"block_id": 44}')
    parsed, _ = LLMClient(MODELS["deepseek"], transport=bare_object).extract("s", "u", Envelope)
    assert [i.block_id for i in parsed.items] == [44]

    bare_list = FakeTransport('[{"block_id": 1}, {"block_id": 2}]')
    parsed, _ = LLMClient(MODELS["deepseek"], transport=bare_list).extract("s", "u", Envelope)
    assert [i.block_id for i in parsed.items] == [1, 2]

    garbage = FakeTransport('{"nothing": true}')
    with pytest.raises(Exception):
        LLMClient(MODELS["deepseek"], transport=garbage).extract("s", "u", Envelope)


def test_unknown_model_key_raises():
    with pytest.raises(ValueError, match="Unknown model"):
        get_model("gpt4")


# --- JSON registry -----------------------------------------------------------


def test_registry_loads_builtin_profiles():
    models = all_models()
    for key in ("deepseek", "gpt-4o-mini", "llama-3.3-70b",
                "qwen2.5-1.5b", "haiku"):
        assert key in models
    assert models["haiku"].api_key_env == "CLAUDE_API_KEY"
    assert models["haiku"].base_url.startswith("https://api.anthropic.com")


def test_registry_local_profile_omits_api_key_field():
    # qwen2.5-1.5b.json has no api_key_env at all -> keyless local profile
    assert all_models()["qwen2.5-1.5b"].is_local
    assert all_models()["qwen2.5-1.5b"].price_in == 0.0


def test_registry_user_dir_plugs_new_model(tmp_path, monkeypatch):
    from mulitaminer.llm import _registry

    (tmp_path / "mymodel.json").write_text(json.dumps({
        "key": "mymodel", "model": "my-model-v1",
        "base_url": "http://localhost:9999/v1",
        "context_window": 16000, "max_output_tokens": 4000,
    }), encoding="utf-8")
    monkeypatch.setenv("MULITAMINER2_LLMS_DIR", str(tmp_path))
    _registry.cache_clear()
    try:
        models = all_models()
        assert "mymodel" in models and models["mymodel"].is_local
    finally:
        _registry.cache_clear()


def test_registry_rejects_unknown_and_missing_fields(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"key": "x", "model": "y", "context_window": 1, '
                   '"max_output_tokens": 1, "api_key": "oops"}', encoding="utf-8")
    with pytest.raises(ValueError, match="unknown field"):
        load_llm_profile(bad)
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text('{"key": "x"}', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        load_llm_profile(incomplete)


def test_provider_counters_capture_billing_detail_we_do_not_model():
    # DeepSeek reports the cache split at the top level, OpenAI nests it. Both
    # must survive into run.json so a finished run can be repriced later.
    class Usage(BaseModel):
        model_config = ConfigDict(extra="allow")
        prompt_tokens: int
        completion_tokens: int

    usage = Usage(prompt_tokens=100, completion_tokens=50,
                  prompt_cache_hit_tokens=80, prompt_cache_miss_tokens=20,
                  prompt_tokens_details={"cached_tokens": 80},
                  model_name="deepseek-flash", free=False)
    counters = _provider_counters(usage)
    assert counters["prompt_cache_hit_tokens"] == 80
    assert counters["prompt_cache_miss_tokens"] == 20
    assert counters["prompt_tokens_details.cached_tokens"] == 80
    # Non-numeric and boolean fields are not counters.
    assert "model_name" not in counters and "free" not in counters


def test_provider_counters_tolerate_an_unusable_usage_object():
    assert _provider_counters(None) == {}
    assert _provider_counters(SimpleNamespace(prompt_tokens=1)) == {}


def test_token_usage_sums_provider_counters_across_calls():
    usage = TokenUsage()
    usage.add(100, 50, 0.1, {"prompt_cache_hit_tokens": 80})
    usage.add(200, 60, 0.2, {"prompt_cache_hit_tokens": 150})
    assert usage.calls == 2 and usage.prompt_tokens == 300
    assert usage.provider == {"prompt_cache_hit_tokens": 230}
    # A run whose provider reports nothing keeps an empty dict, not a crash.
    plain = TokenUsage()
    plain.add(10, 5, 0.0)
    assert plain.provider == {}


def test_provider_counters_read_the_real_sdk_usage_object():
    # The capture is only worth anything if it survives the SDK's own model.
    # DeepSeek returns the cache split as extra fields on CompletionUsage; an
    # SDK upgrade that dropped them would silently lose the billing detail.
    from openai.types.completion_usage import CompletionUsage

    usage = CompletionUsage.model_validate({
        "prompt_tokens": 5000, "completion_tokens": 200, "total_tokens": 5200,
        "prompt_cache_hit_tokens": 4200, "prompt_cache_miss_tokens": 800,
    })
    counters = _provider_counters(usage)
    assert counters["prompt_cache_hit_tokens"] == 4200
    assert counters["prompt_cache_miss_tokens"] == 800
    assert "prompt_tokens_details" not in counters  # null, not a counter


def test_a_response_that_fails_to_parse_is_still_charged():
    # The provider bills whatever it answered. Charging only on success hid the
    # calls that ran into the output cap, which are the expensive ones, and hid
    # them worst for the models that fail most.
    transport = FakeTransport('{"items": [1, 2,')  # truncated, not valid JSON
    usage = TokenUsage()
    client = LLMClient(replace(MODELS["deepseek"], price_in=2.0, price_out=6.0),
                       transport=transport)
    with pytest.raises(json.JSONDecodeError):
        client.extract("sys", "user", Items, usage)
    assert usage.calls == 1
    assert usage.prompt_tokens == 100 and usage.completion_tokens == 50
    assert usage.cost_usd == pytest.approx(100 / 1e6 * 2.0 + 50 / 1e6 * 6.0)


def test_a_response_that_fails_the_schema_is_still_charged():
    transport = FakeTransport('{"items": [{"nope": 1}]}')
    usage = TokenUsage()
    client = LLMClient(MODELS["deepseek"], transport=transport)
    with pytest.raises(ValidationError):
        client.extract("sys", "user", Items, usage)
    assert usage.calls == 1 and usage.prompt_tokens == 100


def test_usage_is_charged_once_per_call_not_twice():
    transport = FakeTransport('{"items": [1]}')
    usage = TokenUsage()
    client = LLMClient(MODELS["deepseek"], transport=transport)
    client.extract("sys", "user", Items, usage)
    client.extract("sys", "user", Items, usage)
    assert usage.calls == 2 and usage.prompt_tokens == 200


def test_ollama_num_ctx_is_read_from_the_show_payload():
    from mulitaminer.llm import ollama_num_ctx

    assert ollama_num_ctx({"parameters": "num_gpu 0\nnum_ctx                        16384\n"}) == 16384
    assert ollama_num_ctx({"parameters": ""}) is None
    assert ollama_num_ctx({}) is None


def test_context_size_rejection_is_fatal_with_the_fix_named():
    import httpx
    from openai import BadRequestError

    class RejectingTransport:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    raise BadRequestError(
                        "request (5048 tokens) exceeds the available context size (4096 tokens)",
                        response=httpx.Response(400, request=httpx.Request("POST", "http://x/v1")),
                        body=None)

    client = LLMClient(MODELS["deepseek"], transport=RejectingTransport())
    with pytest.raises(FatalLLMError, match="OLLAMA_CONTEXT_LENGTH"):
        client.extract("sys", "user", Items)
