"""FastAPI app: landing page, upload form, job page, downloads (docs/WEB.md)."""
from __future__ import annotations

import hashlib
import importlib.metadata
import io
import json
import os
import zipfile
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mulitaminer.llm import ModelProfile, all_models
from mulitaminer.scanner_engine import all_scanners
from mulitaminer.web.i18n import LANGS, pick_lang, strings
from mulitaminer.web.jobs import (DOWNLOADS, EXAMPLE_DIR, EXAMPLE_META, Cleaner, JobStore, RateLimit,
                                  Worker, custom_profile, fernet, job_id)

MEDIA = {".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         ".csv": "text/csv", ".json": "application/json", ".sarif": "application/json"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                               "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                               "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

HERE = Path(__file__).parent
CUSTOM = "custom"
try:
    VERSION = importlib.metadata.version("mulitaminer")
except importlib.metadata.PackageNotFoundError:
    VERSION = "dev"
# Cache-buster for /static URLs: changes whenever a static file changes, so a
# browser never keeps an old stylesheet or logo across deployments.
STATIC_V = hashlib.sha256(b"".join(
    p.read_bytes() for p in sorted((HERE / "static").iterdir()) if p.is_file())).hexdigest()[:10]
PROFILE_TEMPLATE = json.dumps({
    "key": "my-model",
    "model": "provider-model-id",
    "base_url": "https://api.example.com/v1",
    "context_window": 128000,
    "max_output_tokens": 8000,
    "supports_json_schema": False,
}, indent=2)

# Display names for the built-in profiles; unknown keys fall back to the key.
MODEL_LABELS = {
    "deepseek": "DeepSeek Flash",
    "gpt-4o-mini": "GPT-4o mini",
    "haiku": "Claude Haiku 4.5",
    "llama-3.3-70b": "Llama 3.3 70B",
    "mulita-qwen2.5-1.5b-v4": "Mulita 1.5B (fine-tuned)",
    "qwen2.5-1.5b": "Qwen2.5 1.5B (base)",
}
# Provider name and where to create a key, by the env var the profile names.
PROVIDERS = {
    "DEEPSEEK_API_KEY": ("DeepSeek", "https://platform.deepseek.com/api_keys"),
    "OPENAI_API_KEY": ("OpenAI", "https://platform.openai.com/api-keys"),
    "GROQ_API_KEY": ("Groq", "https://console.groq.com/keys"),
    "CLAUDE_API_KEY": ("Anthropic", "https://console.anthropic.com/settings/keys"),
}
SCANNERS = {
    "openvas": ("OpenVAS / Greenbone", "Greenbone Security Assistant, PDF report"),
    "nessus": ("Tenable Nessus", "Nessus Professional / Essentials, PDF export"),
    "tenable": ("Tenable Web App Scanning", "Tenable WAS, detailed scan export"),
    "tenable-vm": ("Tenable Vulnerability Management", "Tenable VM, 'Vulnerabilities by Asset'"),
    "qualys": ("Qualys", "Qualys VMDR scan report"),
    "acunetix": ("Acunetix 360", "Acunetix 360 / Invicti scan report"),
    "zap": ("OWASP ZAP", "ZAP traditional report, printed to PDF"),
}
# Union of the authors of the four MulitaMiner papers, in author order:
# (name, affiliation, ORCID iD).
TEAM = [
    ("Beatriz Machado", "UNIPAMPA", "0009-0002-2750-0323"),
    ("Douglas Lautert", "UNIPAMPA", "0009-0005-9036-5453"),
    ("Cristhian Kapelinski", "UNIPAMPA", "0009-0005-5750-022X"),
    ("Diego Kreutz", "UNIPAMPA", "0000-0003-0830-0238"),
    ("Isadora Garcia Ferrão", "UBO", "0000-0002-0612-486X"),
    ("Alessandro Bof", "UNIPAMPA", "0000-0003-2198-5788"),
]
# Strings the page scripts need (file checks, model switch, job polling).
JS_KEYS = ("err_not_pdf", "err_too_big", "f_custom_id", "f_modelid", "f_served_local",
           "f_key_local", "f_key_custom", "f_key_req", "f_key_hint", "f_get_key", "show",
           "hide", "f_uploading", "st_queued", "st_running", "st_done", "st_failed", "q_pos",
           "q_next", "starting", "findings", "stage_reading", "stage_segmenting",
           "stage_extracting", "recent_forget", "recent_open", "recent_none", "f_drop_many",
           "p_json", "p_customize", "p_hint")


def _env_models() -> list[str]:
    raw = os.getenv("MULITAMINER_WEB_MODELS", "")
    return [m.strip() for m in raw.split(",") if m.strip()]


def model_view(p: ModelProfile) -> dict:
    provider, key_url = PROVIDERS.get(p.api_key_env or "", ("local server" if p.is_local else "custom", ""))
    # The profile as the CLI reads it, minus api_key_env (the form's key field
    # replaces it), so a user can read the numbers and edit a copy as "custom".
    shown = {k: v for k, v in asdict(p).items() if k != "api_key_env" and v is not None}
    return {"key": p.key, "label": MODEL_LABELS.get(p.key, p.key), "model": p.model,
            "is_local": p.is_local, "provider": provider, "key_url": key_url,
            "json": json.dumps(shown, indent=2)}


def scanner_view(key: str) -> dict:
    label, desc = SCANNERS.get(key, (key, "custom scanner profile"))
    return {"key": key, "label": label, "desc": desc}


def create_app(data_dir: Path | None = None, models: list[str] | None = None,
               max_mb: float | None = None, retention_h: float | None = None,
               max_queue: int | None = None, allow_private: bool | None = None,
               rate_per_hour: int | None = None, workers: int | None = None,
               example_dir: Path | None = None) -> FastAPI:
    # Default outside the project tree: on a dev machine the repo tends to live
    # under Documents, where desktop antivirus watches every write.
    data_dir = data_dir or Path(os.getenv("MULITAMINER_WEB_DATA", Path.home() / ".mulitaminer" / "web"))
    models = models or _env_models() or sorted(all_models())
    max_bytes = int((max_mb or float(os.getenv("MULITAMINER_WEB_MAX_MB", "20"))) * 1024 * 1024)
    retention_h = retention_h or float(os.getenv("MULITAMINER_WEB_RETENTION_H", "24"))
    # Pending jobs (queued + running) accepted before the form answers "busy".
    max_queue = max_queue or int(os.getenv("MULITAMINER_WEB_MAX_QUEUE", "20"))
    # PDFs accepted in one submission (one job each, one queue slot each).
    max_batch = int(os.getenv("MULITAMINER_WEB_MAX_BATCH", "10"))
    # Custom base_url may reach localhost / the Docker network only when the
    # user runs the app themselves (docker-compose.web.yml sets it).
    if allow_private is None:
        allow_private = os.getenv("MULITAMINER_WEB_ALLOW_PRIVATE_URLS", "") == "1"
    # Submissions per client address per hour (behind Caddy, uvicorn's
    # --proxy-headers makes request.client the real address).
    rate = RateLimit(rate_per_hour or int(os.getenv("MULITAMINER_WEB_RATE_PER_HOUR", "10")))
    # Jobs run concurrently (cloud models: the work happens at the provider);
    # local-model jobs still go one at a time, see Worker.
    workers = workers or int(os.getenv("MULITAMINER_WEB_WORKERS", "3"))
    example_dir = example_dir or Path(os.getenv("MULITAMINER_WEB_EXAMPLE_DIR", EXAMPLE_DIR))
    build = os.getenv("MULITAMINER_WEB_BUILD", "")[:7]   # the image's commit, set at build time
    unknown = [m for m in models if m not in all_models()]
    if unknown:
        raise ValueError(f"MULITAMINER_WEB_MODELS names unknown profile(s) {unknown}")

    store = JobStore(data_dir)
    worker = Worker(store, workers)
    cleaner = Cleaner(store, retention_h)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        store.load()
        worker.start()
        cleaner.start()
        yield

    app = FastAPI(title="MulitaMiner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # The job link is a secret: no Referer to other sites, no framing, and
        # scripts only from this origin (the pages inline their own).
        resp = await call_next(request)
        resp.headers.update(SECURITY_HEADERS)
        return resp
    templates = Jinja2Templates(directory=HERE / "templates")
    app.state.store = store   # tests reach the store through here

    def lang_of(request: Request) -> str:
        return pick_lang(request.query_params.get("lang"), request.cookies.get("lang"),
                         request.headers.get("accept-language"))

    def render(request: Request, name: str, ctx: dict, status_code: int = 200):
        lang = lang_of(request)
        t = strings(lang)
        base = {
            "request": request, "lang": lang, "t": t,
            "tjs": {k: t[k] for k in JS_KEYS},
            "langs": [{"code": c, "label": lbl, "url": f"{request.url.path}?lang={c}"}
                      for c, lbl in LANGS.items()],
            "retention_h": int(retention_h), "max_mb": max_bytes // (1024 * 1024),
            "v": STATIC_V, "site_url": str(request.base_url).rstrip("/"),
            "version": VERSION, "build": build,
            "example_ok": (example_dir / EXAMPLE_META).is_file(),
        }
        resp = templates.TemplateResponse(request, name, base | ctx, status_code=status_code)
        if request.query_params.get("lang") in LANGS:
            resp.set_cookie("lang", lang, max_age=365 * 24 * 3600, samesite="lax")
        return resp

    def form_context(error: str | None = None, **values) -> dict:
        profiles = all_models()
        return {
            "scanners": [scanner_view(s) for s in sorted(all_scanners())],
            "models": [model_view(profiles[m]) for m in models],
            "custom": CUSTOM, "profile_template": PROFILE_TEMPLATE,
            "error": error, "values": values,
        }

    @app.get("/")
    def index(request: Request):
        return render(request, "index.html", {
            "scanner_labels": [scanner_view(s)["label"] for s in sorted(all_scanners())],
            "model_labels": [MODEL_LABELS.get(m, m) for m in models],
            "team": [{"name": n, "affiliation": a, "orcid": o} for n, a, o in TEAM],
        })

    @app.get("/app")
    def form(request: Request):
        return render(request, "app.html", form_context())

    @app.get("/privacy")
    def privacy(request: Request):
        return render(request, "privacy.html", {})

    def example_meta() -> dict:
        path = example_dir / EXAMPLE_META
        if not path.is_file():
            raise HTTPException(404, "No example on this server.")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/example")
    def example_page(request: Request):
        """A finished job, precomputed by `mulitaminer web-example`: the job
        page and its downloads without running anything."""
        m = example_meta()
        job = {"id": "example", "status": "done", "stage": "", "name": m["name"],
               "created_at": m["created_at"], "updated_at": m["created_at"], "queue_position": None,
               "total_blocks": m["total_blocks"], "done_blocks": m["done_blocks"],
               "records": m["records"], "duration_s": m["duration_s"], "cost_usd": m["cost_usd"],
               "error": None, "scanner": m["scanner"], "model": m["model"],
               "model_label": MODEL_LABELS.get(m["model"], m["model"]), "log": m.get("log", [])[-200:]}
        return render(request, "job.html", {"job": job, "token": "example", "downloads": DOWNLOADS,
                                            "dl": "/example/download", "example": True})

    @app.get("/example/download/{fmt}")
    def example_download(fmt: str):
        m = example_meta()
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "Unknown format.")
        filename, _label = DOWNLOADS[fmt]
        path = example_dir / filename
        if not path.is_file():
            raise HTTPException(404, "Not available.")
        suffix = filename.split("results", 1)[1]
        return Response(path.read_bytes(), media_type=MEDIA.get(Path(filename).suffix, "application/octet-stream"),
                        headers={"Content-Disposition": f'attachment; filename="{m["scanner"]}-{m["name"]}{suffix}"'})

    @app.post("/jobs")
    async def submit(request: Request, report: list[UploadFile] = File(...),
                     scanner: str = Form(...), model: str = Form(...),
                     api_key: str = Form(""), profile_json: str = Form("")):
        """One job per uploaded PDF; several PDFs (same scanner, model and key)
        land on a batch page with a zip download."""
        t = strings(lang_of(request))
        api_key = api_key.strip() or None
        values = dict(scanner=scanner, model=model, profile_json=profile_json)

        def bad(msg: str):
            return render(request, "app.html", form_context(error=msg, **values), status_code=400)

        if len(report) > max_batch:
            return bad(t["e_batch"].format(n=max_batch))
        if store.pending() + len(report) > max_queue:
            return render(request, "app.html", form_context(error=t["e_busy"], **values),
                          status_code=503)
        if not rate.allow(request.client.host if request.client else "?"):
            return render(request, "app.html", form_context(error=t["e_rate"], **values),
                          status_code=429)
        pdfs = []
        for upload in report:
            pdf = await upload.read(max_bytes + 1)
            if len(pdf) > max_bytes:
                return bad(t["e_too_big"].format(mb=max_bytes // (1024 * 1024)))
            if not pdf.startswith(b"%PDF"):
                return bad(t["e_not_pdf"])
            pdfs.append((pdf, upload.filename or "report.pdf"))
        if scanner not in all_scanners():
            return bad(t["e_scanner"].format(s=scanner))

        cfg = None
        if model == CUSTOM:
            try:
                cfg = json.loads(profile_json)
                if not isinstance(cfg, dict):
                    raise ValueError("the profile must be a JSON object")
                profile = custom_profile(cfg, api_key, allow_private=allow_private)
            except (ValueError, TypeError) as exc:
                return bad(t["e_custom"].format(e=exc))
        elif model in models:
            profile = all_models()[model]
            if not profile.is_local and not api_key:
                return bad(t["e_need_key"].format(m=MODEL_LABELS.get(model, model)))
            if profile.is_local:
                api_key = None
        else:
            return bad(t["e_model"].format(m=model))

        tokens = []
        for pdf, filename in pdfs:
            job, token = store.create(pdf, scanner, model, profile, api_key, profile_json=cfg,
                                      filename=filename)
            worker.submit(job)
            tokens.append(token)
        if len(tokens) == 1:
            return RedirectResponse(f"/jobs/{tokens[0]}", status_code=303)
        return RedirectResponse(f"/batch/{'.'.join(tokens)}", status_code=303)

    def batch_jobs(tokens: str) -> list[tuple[str, object]]:
        """The jobs of a batch link, in order; a token the server no longer
        knows is skipped rather than failing the whole page."""
        found = []
        for token in tokens.split("."):
            job = store.get(job_id(token))
            if job is not None:
                found.append((token, job))
        if not found:
            raise HTTPException(404, "No such batch.")
        return found

    @app.get("/batch/{tokens}")
    def batch_page(request: Request, tokens: str):
        jobs = [{"token": tok, **status_payload(job, tok)} for tok, job in batch_jobs(tokens)]
        return render(request, "batch.html", {"jobs": jobs, "tokens": tokens, "downloads": DOWNLOADS})

    @app.get("/batch/{tokens}/download/{fmt}")
    def batch_download(tokens: str, fmt: str):
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "Unknown format.")
        filename, _label = DOWNLOADS[fmt]
        suffix = filename.split("results", 1)[1]
        buf = io.BytesIO()
        n = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for tok, job in batch_jobs(tokens):
                data = store.read_result(job, fernet(tok), filename)
                if data is not None:
                    zf.writestr(f"{job.scanner}-{store.read_name(job, fernet(tok))}{suffix}", data)
                    n += 1
        if n == 0:
            raise HTTPException(404, "Nothing finished yet.")
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="mulitaminer-{fmt}-{n}.zip"'})

    def job_or_404(token: str):
        """The link's token names the job (by hash) and decrypts its files."""
        job = store.get(job_id(token))
        if job is None:
            raise HTTPException(404, "No such job (results are deleted after "
                                     f"{int(retention_h)} hours).")
        return job

    def status_payload(job, token: str) -> dict:
        label = MODEL_LABELS.get(job.model, job.model)
        if job.model == CUSTOM and job.profile_json:
            label = f"custom · {job.profile_json.get('key', '')}"
        return {
            "id": job.id, "status": job.status, "stage": job.stage,
            "name": store.read_name(job, fernet(token)), "created_at": job.created_at,
            "queue_position": store.queue_position(job) if job.status == "queued" else None,
            "total_blocks": job.total_blocks, "done_blocks": job.done_blocks,
            "records": job.records, "duration_s": job.duration_s, "cost_usd": job.cost_usd,
            "error": job.error, "updated_at": job.updated_at,
            "scanner": job.scanner, "model": job.model, "model_label": label,
            "log": job.log[-200:],
        }

    @app.get("/jobs/{token}")
    def job_page(request: Request, token: str):
        job = job_or_404(token)
        return render(request, "job.html", {"job": status_payload(job, token), "token": token,
                                            "downloads": DOWNLOADS, "dl": f"/jobs/{token}/download"})

    @app.get("/api/jobs/{token}")
    def job_status(token: str):
        return JSONResponse(status_payload(job_or_404(token), token))

    @app.get("/jobs/{token}/download/{fmt}")
    def download(token: str, fmt: str):
        job = job_or_404(token)
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "Unknown format.")
        filename, _label = DOWNLOADS[fmt]
        data = store.read_result(job, fernet(token), filename)
        if data is None:
            raise HTTPException(404, "Not ready.")
        suffix = filename.split("results", 1)[1]   # ".xlsx", ".cais.csv", ...
        name = f"{job.scanner}-{store.read_name(job, fernet(token))}{suffix}"
        return Response(data, media_type=MEDIA.get(Path(filename).suffix, "application/octet-stream"),
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
