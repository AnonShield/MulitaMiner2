"""One OpenAI-compatible client for every provider, cloud or local.
Provider differences reduce to a ModelProfile; local profiles are keyless.
Profiles are loaded from JSON configs (built-ins in configs/llms/, user
profiles via MULITAMINER2_LLMS_DIR) — adding a model needs no Python.
Structured output via JSON-Schema where supported, else json_object +
Pydantic validation."""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, fields
from functools import lru_cache
from pathlib import Path

import httpx
from openai import APIStatusError, AuthenticationError, OpenAI, PermissionDeniedError
from pydantic import BaseModel, ValidationError

from mulitaminer import settings
from mulitaminer.models import TokenUsage

log = logging.getLogger(__name__)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class FatalLLMError(Exception):
    """Unrecoverable provider error (auth, quota, unknown model); abort the run."""


@dataclass(frozen=True)
class ModelProfile:
    key: str                      # CLI name
    model: str                    # provider model id
    context_window: int
    max_output_tokens: int
    base_url: str | None = None   # None = api.openai.com
    # Absent in local/keyless configs (ollama, lmstudio) — a local model has
    # no API key, so the JSON simply omits the field.
    api_key_env: str | None = None
    supports_json_schema: bool = False
    price_in: float = 0.0         # USD per 1M input tokens (0 for local)
    price_out: float = 0.0
    reasoning_tags: bool = False  # strip <think>…</think> from responses
    # "high"/"medium"/"low"/"none" for thinking models; "none" disables thinking.
    reasoning_effort: str | None = None
    temperature: float = 0.0      # deterministic extraction
    encoding: str = "cl100k_base"
    # Per-request deadline. The default suits GPU-class throughput; a profile
    # served from slower hardware must raise it or healthy calls are cut.
    request_timeout_s: float = settings.REQUEST_TIMEOUT_S

    @property
    def is_local(self) -> bool:
        return self.api_key_env is None


_BUILTIN_LLM_DIR = Path(__file__).parent / "configs" / "llms"
_PROFILE_FIELDS = {f.name for f in fields(ModelProfile)}


def profile_from_dict(cfg: dict, source: str) -> ModelProfile:
    """Validate a profile dict (a config file or the web form) into a ModelProfile."""
    unknown = set(cfg) - _PROFILE_FIELDS
    if unknown:
        raise ValueError(
            f"LLM config {source} has unknown field(s) {sorted(unknown)}; "
            f"valid fields: {sorted(_PROFILE_FIELDS)}"
        )
    try:
        return ModelProfile(**cfg)
    except TypeError as exc:
        raise ValueError(f"LLM config {source} is invalid: {exc}") from exc


def load_llm_profile(config_path: Path) -> ModelProfile:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    return profile_from_dict(cfg, str(config_path))


@lru_cache
def _registry(extra_dir: str | None) -> dict[str, ModelProfile]:
    profiles: dict[str, ModelProfile] = {}
    dirs = [_BUILTIN_LLM_DIR]
    if extra_dir:
        user_dir = Path(extra_dir)
        # Accept both a flat user dir and one mirroring the llms/ split.
        dirs += [user_dir, user_dir / "llms"]
    for directory in dirs:
        for config in sorted(directory.glob("*.json")):
            profile = load_llm_profile(config)
            profiles[profile.key] = profile
    return profiles


def all_models() -> dict[str, ModelProfile]:
    return _registry(os.getenv("MULITAMINER2_LLMS_DIR"))


def get_model(key: str) -> ModelProfile:
    models = all_models()
    try:
        return models[key.lower()]
    except KeyError:
        raise ValueError(f"Unknown model '{key}'. Available: {sorted(models)}")


def _resolve_api_key(profile: ModelProfile) -> str:
    if profile.is_local:
        return "local"  # dummy; keyless servers ignore it
    if value := os.getenv(profile.api_key_env):
        return value
    raise FatalLLMError(
        f"No API key for model '{profile.key}'. "
        f"Set {profile.api_key_env} in your .env (see .env.example)."
    )


def clean_response(text: str, reasoning_tags: bool) -> str:
    """Strip markdown fences and reasoning blocks before JSON parsing."""
    if reasoning_tags:
        text = _THINK_RE.sub("", text)
    text = _FENCE_RE.sub("", text.strip())
    return text.strip()


class LLMClient:
    """Chat calls with structured output and per-call usage accounting."""

    def __init__(
        self,
        profile: ModelProfile,
        model_name: str | None = None,
        transport: OpenAI | None = None,
    ) -> None:
        self.profile = profile
        self.model = model_name or profile.model
        # Provider's own id for what answered; often more specific than what
        # was asked for, and the only record of which version ran.
        self.served_model: str | None = None
        # SDK built-in exponential backoff covers rate limits / transient 5xx.
        self._client = transport or OpenAI(
            base_url=profile.base_url,
            api_key=_resolve_api_key(profile),
            max_retries=settings.SDK_MAX_RETRIES,
            timeout=profile.request_timeout_s,
        )

    def extract(
        self, system_prompt: str, user_content: str, response_model: type[BaseModel],
        usage: "TokenUsage | None" = None,
    ) -> tuple[BaseModel, dict]:
        """One structured extraction call. Returns (validated model, usage dict).

        ``usage``, when given, is charged as soon as the provider answers, so a
        response that fails to parse still counts: it was billed.

        Raises FatalLLMError for auth/quota/unknown-model, and lets Pydantic
        ValidationError / json.JSONDecodeError propagate so the extraction
        loop can apply its targeted-retry policy.
        """
        if self.profile.supports_json_schema:
            response_format = {
                "type": "json_schema",
                "json_schema": {
                    "name": "vulnerability_extraction",
                    "schema": response_model.model_json_schema(by_alias=True),
                },
            }
        else:
            # json_object mode: providers require the word "JSON" in the
            # conversation; both prompt templates mention it.
            response_format = {"type": "json_object"}

        extra_body: dict = {}
        if self.profile.reasoning_effort:
            extra_body["reasoning_effort"] = self.profile.reasoning_effort
        if self.profile.is_local:
            # Ollama truncates to num_ctx (default 4096); set it per request so a
            # chunk that outgrows the default is not silently cut.
            extra_body["options"] = {"num_ctx": self.profile.context_window}

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                temperature=self.profile.temperature,
                max_tokens=self.profile.max_output_tokens,
                response_format=response_format,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                extra_body=extra_body or None,
            )
        except (AuthenticationError, PermissionDeniedError) as exc:
            raise FatalLLMError(
                f"Provider rejected the credentials for '{self.profile.key}': {exc}"
            ) from exc
        except APIStatusError as exc:
            if exc.status_code in (402, 404):  # quota exhausted / unknown model
                raise FatalLLMError(
                    f"Fatal provider error for '{self.profile.key}' "
                    f"(HTTP {exc.status_code}): {exc}"
                ) from exc
            raise

        self.served_model = getattr(response, "model", None) or self.served_model
        raw = response.choices[0].message.content or ""
        # Account before parsing. The provider bills a response whether or not
        # it is valid JSON, and a response that fails to parse is usually one
        # that ran into the output cap, so the calls dropped here were the
        # expensive ones. Charging them only on success under-reported cost,
        # and under-reported it most for the models that fail most.
        call = self._package(getattr(response, "usage", None), raw)
        if usage is not None:
            usage.add(call["prompt_tokens"], call["completion_tokens"],
                      call["cost_usd"], call["provider"])

        cleaned = clean_response(raw, self.profile.reasoning_tags)
        data = json.loads(cleaned)
        return self._validate_envelope(data, response_model), call

    @staticmethod
    def _validate_envelope(data, response_model: type[BaseModel]) -> BaseModel:
        """Validate, tolerating one shape slip: items returned without the
        {"items": [...]} envelope get re-wrapped. Content is never repaired."""
        try:
            return response_model.model_validate(data)
        except ValidationError:
            if isinstance(data, list):
                return response_model.model_validate({"items": data})
            if isinstance(data, dict) and "block_id" in data:
                return response_model.model_validate({"items": [data]})
            raise

    def runtime_info(self) -> dict:
        """What actually served this run, for run.json. Call after extraction:
        a local server only reports its loaded model while it is loaded."""
        info = {
            "profile": self.profile.key,
            "requested_model": self.model,
            "served_model": self.served_model,
            "base_url": self.profile.base_url,
            "request_timeout_s": self.profile.request_timeout_s,
        }
        if self.profile.is_local and self.profile.base_url:
            info |= _probe_ollama(self.profile.base_url.rsplit("/v1", 1)[0])
        return info

    def _package(self, usage, raw: str) -> dict:
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
        cost = (
            prompt_tokens / 1e6 * self.profile.price_in
            + completion_tokens / 1e6 * self.profile.price_out
        )
        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": cost,
            "provider": _provider_counters(usage),
            "raw": raw,
        }


def _provider_counters(usage) -> dict:
    """Every numeric field in the provider's usage object, one nesting level
    flattened with dotted keys. Providers put the billing detail we do not model
    here, under names we cannot know in advance: DeepSeek reports
    prompt_cache_hit_tokens at the top level, OpenAI nests cached_tokens under
    prompt_tokens_details. Recording them verbatim makes a finished run
    repriceable without re-running it."""
    if usage is None:
        return {}
    try:
        data = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)
    except Exception:  # noqa: BLE001 - accounting detail is never worth a failed run
        return {}

    def numbers(source: dict, prefix: str = "") -> dict:
        out: dict = {}
        for name, value in source.items():
            if isinstance(value, bool) or value is None:
                continue
            if isinstance(value, (int, float)):
                out[prefix + name] = value
            elif isinstance(value, dict) and not prefix:
                out |= numbers(value, f"{name}.")
        return out

    return numbers(data)


def _probe_ollama(root: str) -> dict:
    """Server version and whether the model ran on GPU or CPU. Neither is
    visible in an OpenAI-compatible response, and both decide whether a run
    is comparable to another. Best effort: a provenance probe never fails a run."""
    out: dict = {}
    try:
        with httpx.Client(timeout=5.0) as http:
            out["server_version"] = http.get(f"{root}/api/version").json().get("version")
            loaded = http.get(f"{root}/api/ps").json().get("models") or []
            if loaded:
                total = loaded[0].get("size") or 0
                vram = loaded[0].get("size_vram") or 0
                out["processor"] = (
                    f"{round(vram / total * 100)}% GPU" if total and vram else "100% CPU"
                )
    except Exception as exc:  # noqa: BLE001 - provenance is never worth a failed run
        log.debug("runtime probe failed for %s: %s", root, exc)
    return out
