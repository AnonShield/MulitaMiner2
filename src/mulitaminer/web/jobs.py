"""Extraction jobs: one directory each under the data dir, one worker thread.

The API key lives only on the in-memory Job while it is queued or running; it
is never written to job.json, the run dir, or a log line.
"""
from __future__ import annotations

import json
import logging
import queue
import secrets
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openai import OpenAI

from mulitaminer import settings
from mulitaminer.llm import LLMClient, ModelProfile, profile_from_dict
from mulitaminer.pipeline import RunConfig
from mulitaminer.pipeline import run as pipeline_run
from mulitaminer.ui import Progress

log = logging.getLogger(__name__)

# Every exporter runs at the end of a job (cheap: they serialise the records
# already in memory). DOWNLOADS maps a URL slug to the file each one leaves in
# the run dir and the label the page shows; results.json is always written.
EXPORTS = ("xlsx", "csv", "sarif", "csaf", "generic", "cais")
DOWNLOADS = {
    "xlsx": ("results.xlsx", "XLSX"),
    "csv": ("results.csv", "CSV"),
    "json": ("results.json", "JSON"),
    "sarif": ("results.sarif", "SARIF 2.1.0"),
    "csaf": ("results.csaf.json", "CSAF 2.0"),
    "defectdojo": ("results.generic.json", "DefectDojo"),
    "cais": ("results.cais.csv", "CAIS CSV"),
    "cais-json": ("results.cais.json", "CAIS JSON"),
}
# Marks a web-form profile as keyed; the dataclass means "keyless" by None.
FORM_KEY_ENV = "WEB_FORM"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Job:
    id: str
    scanner: str
    model: str                      # profile key, or "custom"
    profile_json: dict | None       # the custom profile as submitted (no key)
    created_at: str
    status: str = "queued"          # queued | running | done | failed
    stage: str = ""
    total_blocks: int = 0
    done_blocks: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str = ""
    error: str | None = None
    records: int | None = None
    duration_s: float | None = None
    cost_usd: float | None = None
    # Never persisted: see asdict filtering in JobStore.save.
    profile: ModelProfile | None = field(default=None, repr=False, compare=False)
    api_key: str | None = field(default=None, repr=False, compare=False)

    @property
    def finished(self) -> bool:
        return self.status in ("done", "failed")


def custom_profile(cfg: dict, api_key: str | None) -> ModelProfile:
    """A ModelProfile from the form's JSON. The key field, not api_key_env,
    decides whether the provider is keyed."""
    if "api_key_env" in cfg:
        raise ValueError("api_key_env is not accepted here; paste the key in the API key field")
    if not str(cfg.get("base_url", "")).startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    profile = profile_from_dict(cfg, "custom profile")
    return replace(profile, api_key_env=FORM_KEY_ENV if api_key else None)


def build_client(profile: ModelProfile, api_key: str | None) -> LLMClient:
    # Same construction as LLMClient's own, with the key passed explicitly
    # instead of read from the environment (which would leak between jobs).
    transport = OpenAI(
        base_url=profile.base_url,
        api_key=api_key or "local",
        max_retries=settings.SDK_MAX_RETRIES,
        timeout=profile.request_timeout_s,
    )
    return LLMClient(profile, transport=transport)


class JobStore:
    """Jobs on disk under data_dir/jobs/<id>/, mirrored in memory."""

    def __init__(self, data_dir: Path):
        self.root = data_dir / "jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def job_dir(self, job_id: str) -> Path:
        return self.root / job_id

    def load(self) -> None:
        """Reload finished jobs after a restart; anything unfinished is lost."""
        for meta in self.root.glob("*/job.json"):
            data = json.loads(meta.read_text(encoding="utf-8"))
            job = Job(**data)
            if not job.finished:
                job.status, job.error = "failed", "The server restarted before this job finished; please resubmit."
                job.finished_at = _now()
            self._jobs[job.id] = job
            self.save(job)

    def create(self, pdf: bytes, scanner: str, model: str, profile: ModelProfile,
               api_key: str | None, profile_json: dict | None = None) -> Job:
        job = Job(id=secrets.token_urlsafe(16), scanner=scanner, model=model,
                  profile_json=profile_json, created_at=_now(),
                  profile=profile, api_key=api_key)
        d = self.job_dir(job.id)
        d.mkdir()
        (d / "input.pdf").write_bytes(pdf)
        with self._lock:
            self._jobs[job.id] = job
        self.save(job)
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def save(self, job: Job) -> None:
        job.updated_at = _now()
        data = {k: v for k, v in asdict(job).items() if k not in ("profile", "api_key")}
        (self.job_dir(job.id) / "job.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8")

    def queue_position(self, job: Job) -> int:
        """Queued jobs created before this one (0 = next up)."""
        return sum(1 for j in self._jobs.values()
                   if j.status == "queued" and j.created_at < job.created_at)

    def purge_older_than(self, hours: float) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        gone = 0
        for job in list(self._jobs.values()):
            if not job.finished:
                continue
            stamp = datetime.fromisoformat(job.finished_at or job.created_at)
            if stamp < cutoff:
                shutil.rmtree(self.job_dir(job.id), ignore_errors=True)
                with self._lock:
                    self._jobs.pop(job.id, None)
                gone += 1
        return gone


class JobProgress(Progress):
    """Routes pipeline events into the job's counters."""

    def __init__(self, store: JobStore, job: Job):
        self.store, self.job = store, job

    def stage(self, name: str) -> None:
        self.job.stage = name
        self.store.save(self.job)

    def segmented(self, total: int) -> None:
        self.job.total_blocks, self.job.stage = total, "extracting"
        self.store.save(self.job)

    def chunk_done(self, got: int, expected: int) -> None:
        self.job.done_blocks += got
        self.store.save(self.job)


class Worker:
    """Runs queued jobs one at a time on a daemon thread."""

    def __init__(self, store: JobStore):
        self.store = store
        self._queue: queue.Queue[str] = queue.Queue()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="mulita-web-worker")

    def start(self) -> None:
        self._thread.start()

    def submit(self, job: Job) -> None:
        self._queue.put(job.id)

    def _loop(self) -> None:
        while True:
            job = self.store.get(self._queue.get())
            if job is not None:
                self._run(job)

    def _run(self, job: Job) -> None:
        job.status, job.started_at = "running", _now()
        self.store.save(job)
        d = self.store.job_dir(job.id)
        try:
            config = RunConfig(input_path=d / "input.pdf", scanner=job.scanner,
                               model=job.model, formats=EXPORTS, output_dir=d)
            client = build_client(job.profile, job.api_key)
            result, _ = pipeline_run(config, client=client, run_dir=d / "run",
                                     progress=JobProgress(self.store, job))
            job.status = "done"
            job.records = len(result.records)
            job.duration_s = result.duration_s
            job.cost_usd = round(result.usage.cost_usd, 4)
        except Exception as exc:  # any failure is the job's, not the server's
            msg = str(exc) or exc.__class__.__name__
            if job.api_key and job.api_key in msg:
                msg = "The model provider rejected the request."
            job.status, job.error = "failed", msg
            log.warning("job %s failed: %s", job.id, msg)
        finally:
            job.finished_at = _now()
            job.profile, job.api_key = None, None
            self.store.save(job)


class Cleaner:
    """Purges finished jobs older than `hours`, once at start then hourly."""

    def __init__(self, store: JobStore, hours: float):
        self.store, self.hours = store, hours
        self._thread = threading.Thread(target=self._loop, daemon=True, name="mulita-web-cleaner")

    def start(self) -> None:
        self._thread.start()

    def _loop(self) -> None:
        while True:
            try:
                n = self.store.purge_older_than(self.hours)
                if n:
                    log.info("purged %d job(s) older than %sh", n, self.hours)
            except Exception:
                log.exception("cleanup failed")
            time.sleep(3600)
