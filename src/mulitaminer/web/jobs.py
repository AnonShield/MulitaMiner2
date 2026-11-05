"""Extraction jobs: one directory each under the data dir, a few worker threads.

Secrets never touch the disk. The API key lives only on the in-memory Job
while it is queued or running. The job link carries a random token that is
both the job's name (its id is the token's hash) and the key that encrypts
the PDF and every result file at rest; the server keeps neither.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import logging
import queue
import re
import secrets
import shutil
import socket
import tarfile
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
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
ENC = ".enc"
RESULTS = "results.tar" + ENC   # the whole run dir, one encrypted archive
# The precomputed job shown at /example: its downloads plus this metadata file
# (`mulitaminer web-example` writes them; docs/WEB.md).
EXAMPLE_DIR = Path(__file__).parent / "example"
EXAMPLE_META = "example.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def job_id(token: str) -> str:
    """The public id is the token's hash: knowing the id proves nothing."""
    digest = hashlib.sha256(token.encode()).digest()
    return base64.urlsafe_b64encode(digest)[:22].decode()


def fernet(token: str) -> Fernet:
    key = hashlib.sha256(b"mulitaminer-web:" + token.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


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
    cipher: Fernet | None = field(default=None, repr=False, compare=False)
    log: list[str] = field(default_factory=list, repr=False, compare=False)  # live view only

    @property
    def finished(self) -> bool:
        return self.status in ("done", "failed")


def _is_private(host: str) -> bool:
    """True when the host resolves to a loopback, private, link-local or
    reserved address. Unresolvable hosts pass: the job fails on its own later."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return True
    return False


def custom_profile(cfg: dict, api_key: str | None, allow_private: bool = False) -> ModelProfile:
    """A ModelProfile from the form's JSON. The key field, not api_key_env,
    decides whether the provider is keyed. On a public deployment base_url may
    not point inside the server's network (SSRF), hence allow_private."""
    if "api_key_env" in cfg:
        raise ValueError("api_key_env is not accepted here; paste the key in the API key field")
    url = urlsplit(str(cfg.get("base_url", "")))
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError("base_url must be an http(s) URL with a host")
    if not allow_private and _is_private(url.hostname):
        raise ValueError("base_url points to a local or private address; the public demo "
                         "only reaches public endpoints (run the tool locally for that)")
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


def safe_stem(filename: str) -> str:
    """The upload's base name, without extension, reduced to a safe charset."""
    stem = Path(filename or "report").stem
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "report"
    return stem[:60]


class JobLogHandler(logging.Handler):
    """Collects the pipeline's log lines for one job: only records emitted
    from the worker thread, so concurrent server logging never mixes in."""

    def __init__(self, job: Job, ident: int, keep: int = 300):
        super().__init__(level=logging.INFO)
        self.job, self.ident, self.keep = job, ident, keep
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self.ident or not record.name.startswith("mulitaminer"):
            return
        self.job.log.append(self.format(record))
        del self.job.log[:-self.keep]


def _seal(run_dir: Path, cipher: Fernet, job_dir: Path) -> None:
    """Pack the run dir into one encrypted archive in the job dir. One archive
    rather than a .enc per file: the per-file rename-and-delete pattern is
    what desktop antivirus heuristics call ransomware."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(run_dir, arcname="run")
    (job_dir / RESULTS).write_bytes(cipher.encrypt(buf.getvalue()))


def _shred(job_dir: Path) -> None:
    """Delete any plaintext left behind (a job cut short by a restart)."""
    (job_dir / "input.pdf").unlink(missing_ok=True)
    shutil.rmtree(job_dir / "run", ignore_errors=True)


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
                _shred(meta.parent)
            self._jobs[job.id] = job
            self.save(job)

    def create(self, pdf: bytes, scanner: str, model: str, profile: ModelProfile,
               api_key: str | None, profile_json: dict | None = None,
               filename: str = "report.pdf") -> tuple[Job, str]:
        """Store the job and return it with its token (the link; never kept)."""
        token = secrets.token_urlsafe(32)
        cipher = fernet(token)
        job = Job(id=job_id(token), scanner=scanner, model=model,
                  profile_json=profile_json, created_at=_now(),
                  profile=profile, api_key=api_key, cipher=cipher)
        d = self.job_dir(job.id)
        d.mkdir()
        (d / f"input.pdf{ENC}").write_bytes(cipher.encrypt(pdf))
        # The upload's name can say whose network it is: ciphertext like the rest.
        (d / f"name{ENC}").write_bytes(cipher.encrypt(safe_stem(filename).encode()))
        with self._lock:
            self._jobs[job.id] = job
        self.save(job)
        return job, token

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def save(self, job: Job) -> None:
        job.updated_at = _now()
        data = {k: v for k, v in asdict(job).items()
                if k not in ("profile", "api_key", "cipher", "log")}
        (self.job_dir(job.id) / "job.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8")

    def read_name(self, job: Job, cipher: Fernet) -> str:
        path = self.job_dir(job.id) / f"name{ENC}"
        return cipher.decrypt(path.read_bytes()).decode() if path.is_file() else "report"

    def read_result(self, job: Job, cipher: Fernet, filename: str) -> bytes | None:
        path = self.job_dir(job.id) / RESULTS
        if job.status != "done" or not path.is_file():
            return None
        with tarfile.open(fileobj=io.BytesIO(cipher.decrypt(path.read_bytes()))) as tar:
            try:
                member = tar.extractfile(f"run/{filename}")
            except KeyError:
                return None
            return member.read() if member else None

    def queue_position(self, job: Job) -> int:
        """Queued jobs created before this one (0 = next up)."""
        return sum(1 for j in self._jobs.values()
                   if j.status == "queued" and j.created_at < job.created_at)

    def pending(self) -> int:
        return sum(1 for j in self._jobs.values() if not j.finished)

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
    """Routes pipeline events into the job's counters (and to disk, when the
    job has a store)."""

    def __init__(self, store: JobStore | None, job: Job):
        self.store, self.job = store, job

    def _save(self) -> None:
        if self.store is not None:
            self.store.save(self.job)

    def stage(self, name: str) -> None:
        self.job.stage = name
        self._save()

    def segmented(self, total: int) -> None:
        self.job.total_blocks, self.job.stage = total, "extracting"
        self._save()

    def chunk_done(self, got: int, expected: int) -> None:
        self.job.done_blocks += got
        self._save()


def build_example(pdf: Path, scanner: str, model: str, out_dir: Path,
                  client: LLMClient | None = None) -> dict:
    """Run one extraction and leave its downloads plus example.json in out_dir:
    the finished job that /example shows without running anything."""
    out_dir.mkdir(parents=True, exist_ok=True)
    job = Job(id="example", scanner=scanner, model=model, profile_json=None, created_at=_now())
    handler = JobLogHandler(job, threading.get_ident())
    logging.getLogger().addHandler(handler)
    logging.getLogger("mulitaminer").setLevel(logging.INFO)
    try:
        with tempfile.TemporaryDirectory(prefix="mulitaminer-example-") as tmp:
            work = Path(tmp)
            config = RunConfig(input_path=pdf, scanner=scanner, model=model,
                               formats=EXPORTS, output_dir=work)
            result, run_dir = pipeline_run(config, client=client, run_dir=work / "run",
                                           progress=JobProgress(None, job))
            for filename, _label in DOWNLOADS.values():
                shutil.copyfile(run_dir / filename, out_dir / filename)
    finally:
        logging.getLogger().removeHandler(handler)
    meta = {"name": safe_stem(pdf.name), "scanner": scanner, "model": model,
            "created_at": job.created_at, "total_blocks": job.total_blocks,
            "done_blocks": job.done_blocks, "records": len(result.records),
            "duration_s": result.duration_s, "cost_usd": round(result.usage.cost_usd, 4),
            "log": job.log}
    (out_dir / EXAMPLE_META).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


class Worker:
    """Runs queued jobs on daemon threads: `workers` at a time for cloud
    models, whose work happens at the provider, and one at a time for local
    models, which share one GPU."""

    def __init__(self, store: JobStore, workers: int = 1):
        self.store = store
        self._queue: queue.Queue[str] = queue.Queue()
        self._threads = [threading.Thread(target=self._loop, daemon=True, name=f"mulita-web-worker-{i}")
                         for i in range(max(1, workers))]
        self._local = threading.Lock()
        # The CLI sets this through basicConfig; the server has no such setup,
        # and without it the pipeline's INFO lines (the live log) never reach a handler.
        logging.getLogger("mulitaminer").setLevel(logging.INFO)

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def submit(self, job: Job) -> None:
        self._queue.put(job.id)

    def _loop(self) -> None:
        while True:
            job = self.store.get(self._queue.get())
            if job is not None:
                self._run(job)

    def _run(self, job: Job) -> None:
        is_local = job.profile is not None and job.profile.is_local
        with self._local if is_local else contextlib.nullcontext():
            self._execute(job)

    def _execute(self, job: Job) -> None:
        job.status, job.started_at = "running", _now()
        self.store.save(job)
        d = self.store.job_dir(job.id)
        # The pipeline reads and writes files, so plaintext exists for the run
        # only, in the OS temp dir. The data dir only ever holds ciphertext:
        # desktop antivirus stalls a process that writes random-looking files
        # into Documents, and on a dev machine the data dir may live there.
        handler = JobLogHandler(job, threading.get_ident())
        logging.getLogger().addHandler(handler)
        with tempfile.TemporaryDirectory(prefix="mulitaminer-job-") as tmp:
            work = Path(tmp)
            pdf = work / "input.pdf"
            try:
                pdf.write_bytes(job.cipher.decrypt((d / f"input.pdf{ENC}").read_bytes()))
                config = RunConfig(input_path=pdf, scanner=job.scanner,
                                   model=job.model, formats=EXPORTS, output_dir=work)
                client = build_client(job.profile, job.api_key)
                result, _ = pipeline_run(config, client=client, run_dir=work / "run",
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
                logging.getLogger().removeHandler(handler)
                if (work / "run").is_dir():
                    _seal(work / "run", job.cipher, d)   # also on failure: run.log is the evidence
                job.finished_at = _now()
                job.profile, job.api_key, job.cipher = None, None, None
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


class RateLimit:
    """Sliding-window submissions per client address, in memory."""

    def __init__(self, per_hour: int):
        self.per_hour = per_hour
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(client, []) if now - t < 3600]
            if len(hits) >= self.per_hour:
                self._hits[client] = hits
                return False
            hits.append(now)
            self._hits[client] = hits
            return True
