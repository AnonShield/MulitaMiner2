"""Typed data models; single source of truth for the vulnerability record.
The LLM contract (`extraction_model_for`) is derived from the record model."""
from __future__ import annotations

from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field, create_model

# Marks fields the LLM is NOT responsible for producing; the pipeline fills
# them. Used to derive the LLM response contract (see extraction_model_for).
_PIPELINE_FILLED = {"json_schema_extra": {"llm_produced": False}}


class VulnRecord(BaseModel):
    """Canonical core shared by every scanner. Validated, stable.

    Scanner-specific fields (cvss, plugin, instances, insight, ...) are declared
    in each scanner's JSON config under "fields" and added on top of this core;
    """

    # allow undeclared keys; accept `Name` and `name`; keep post-validation
    # writes schema-checked.
    model_config = ConfigDict(extra="allow", populate_by_name=True, validate_assignment=True)

    name: str = Field(alias="Name")
    description: list[str] = []
    solution: list[str] = []
    impact: list[str] = []
    references: list[str] = []
    severity: str # prioritization owns the known labels and warns on the rest.

    # Filled by the pipeline from report context, prompt only if not defined in the json.
    host: str | None = Field(default=None, **_PIPELINE_FILLED)
    # port is numeric or absent; the str is legacy. _to_record drops the
    # scanner pseudo-ports ("general") that the header can carry.
    port: int | str | None = None
    protocol: str | None = None

    # Stamped from the scanner profile, never prompted.
    source: str = Field(default="", **_PIPELINE_FILLED)


class PluginDetails(BaseModel):
    """Tenable's Plugin Details block. Empty ({}) for OpenVAS."""

    model_config = ConfigDict(extra="allow")

    publication_date: str | None = None
    modification_date: str | None = None
    family: str | None = None
    severity: str | None = None
    plugin_id: int | None = None


class Instance(BaseModel):
    """One Tenable WAS instance (a URL/endpoint the finding was seen on)."""

    model_config = ConfigDict(extra="allow")

    instance: str = ""
    input_type: str = ""
    input_name: str = ""
    payload: str = ""
    proof: str = ""
    output: str = ""
    request_method: str = ""
    http_status_code: int | None = None
    http_protocol: str = ""
    response_content_type: str = ""


def record_type_for_source(source: str | None) -> type[VulnRecord]:
    """The record type of the scanner whose profile stamps `source`
    (registry-driven, so config-declared fields are included); VulnRecord if
    none matches. Lazy import avoids a cycle with scanner_engine."""
    from mulitaminer.scanner_engine import all_scanners

    for profile in all_scanners().values():
        if profile.source == source:
            return profile.record_type
    return VulnRecord


def _is_llm_produced(field) -> bool:
    extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
    return extra.get("llm_produced", True)


@lru_cache
def extraction_model_for(record_type: type[VulnRecord]) -> type[BaseModel]:
    """LLM response-item model: `block_id` + the record's LLM-produced fields.
    extra="forbid" closes the JSON Schema, as structured-output modes require."""
    fields: dict = {"block_id": (int, Field(description="ID of the source block (### BLOCK n)"))}
    for name, f in record_type.model_fields.items():
        if not _is_llm_produced(f):
            continue
        fields[name] = (f.annotation, f)
    return create_model(
        f"{record_type.__name__}Extraction",
        __config__=ConfigDict(extra="forbid", populate_by_name=True),
        **fields,
    )


# --- Pipeline flow objects ---------------------------------------------------


class Block(BaseModel):
    """One marker-delimited report segment: exactly one candidate finding.
    host/port/protocol/severity_hint are context recovered from headers around
    the block; they feed the prompt header and field backfill."""

    id: int
    text: str
    host: str | None = None
    port: int | str | None = None
    protocol: str | None = None
    severity_hint: str | None = None


class Chunk(BaseModel):
    """An ordered group of whole blocks sent to the LLM in one call."""

    index: int
    blocks: list[Block]
    token_estimate: int


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    cost_usd: float = 0.0
    cached_tokens: int = 0         # input tokens the provider served from its cache
    # Every numeric field the provider reported, summed verbatim across calls.
    # cost_usd is one price table applied to two token counts; providers bill on
    # more than that (cache hits, tiers), so keep the raw counters to reprice a
    # finished run instead of paying to re-run it.
    provider: dict = {}

    def add(self, prompt: int, completion: int, cost: float,
            provider: dict | None = None, cached: int = 0) -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.calls += 1
        self.cost_usd += cost
        self.cached_tokens += cached
        for name, value in (provider or {}).items():
            self.provider[name] = self.provider.get(name, 0) + value


# block_id reconciliation drop categories, in a fixed order so the output always
# lists all four (0-filled) and is self-explanatory.
DROP_CATEGORIES = ("unknown_id", "duplicate_id", "validation_error", "unrecovered")


def full_drops(counts: dict | None) -> dict:
    """Every drop category present, 0-filled, from a partial/empty counter."""
    counts = counts or {}
    return {c: int(counts.get(c, 0)) for c in DROP_CATEGORIES}


# Chunk-level retry reasons: bad_json (response not valid JSON, usually output
# truncated at the token cap), bad_shape (JSON parsed but failed the schema),
# timeout (call outran the client deadline; a slow model on a heavy block).
RETRY_CATEGORIES = ("bad_json", "bad_shape", "timeout")


def full_retries(counts: dict | None) -> dict:
    """Every retry reason present, 0-filled, from a partial/empty counter."""
    counts = counts or {}
    return {c: int(counts.get(c, 0)) for c in RETRY_CATEGORIES}


class RunResult(BaseModel):
    """Everything a run produced, in memory. Writers serialize from this."""

    records: list[VulnRecord]
    warnings: list[str] = []
    drops: dict = {}  # block_id reconciliation drops by category
    retries: dict = {}  # chunk retries by reason (bad_json, bad_shape)
    usage: TokenUsage = Field(default_factory=TokenUsage)
    duration_s: float = 0.0
    started_at: str = ""   # local time with UTC offset, ISO 8601
    finished_at: str = ""
    block_count: int = 0
    chunk_count: int = 0
    config: dict = {}
