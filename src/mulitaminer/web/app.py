"""FastAPI app: upload form, job page, downloads (docs/WEB.md)."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mulitaminer.llm import all_models
from mulitaminer.scanner_engine import all_scanners
from mulitaminer.web.jobs import EXPORTS, Cleaner, JobStore, Worker, custom_profile

HERE = Path(__file__).parent
CUSTOM = "custom"
PROFILE_TEMPLATE = json.dumps({
    "key": "my-model",
    "model": "provider-model-id",
    "base_url": "https://api.example.com/v1",
    "context_window": 128000,
    "max_output_tokens": 8000,
    "supports_json_schema": False,
}, indent=2)


def _env_models() -> list[str]:
    raw = os.getenv("MULITAMINER_WEB_MODELS", "")
    return [m.strip() for m in raw.split(",") if m.strip()]


def create_app(data_dir: Path | None = None, models: list[str] | None = None,
               max_mb: float | None = None, retention_h: float | None = None) -> FastAPI:
    data_dir = data_dir or Path(os.getenv("MULITAMINER_WEB_DATA", "outputs/web"))
    models = models or _env_models() or sorted(all_models())
    max_bytes = int((max_mb or float(os.getenv("MULITAMINER_WEB_MAX_MB", "20"))) * 1024 * 1024)
    retention_h = retention_h or float(os.getenv("MULITAMINER_WEB_RETENTION_H", "24"))
    unknown = [m for m in models if m not in all_models()]
    if unknown:
        raise ValueError(f"MULITAMINER_WEB_MODELS names unknown profile(s) {unknown}")

    store = JobStore(data_dir)
    worker = Worker(store)
    cleaner = Cleaner(store, retention_h)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        store.load()
        worker.start()
        cleaner.start()
        yield

    app = FastAPI(title="MulitaMiner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    app.state.store = store   # tests reach the store through here

    def form_context(request: Request, error: str | None = None, **values):
        profiles = all_models()
        return {
            "request": request,
            "scanners": sorted(all_scanners()),
            "models": [profiles[m] for m in models],
            "custom": CUSTOM,
            "profile_template": PROFILE_TEMPLATE,
            "max_mb": max_bytes // (1024 * 1024),
            "retention_h": int(retention_h),
            "error": error,
            "values": values,
        }

    @app.get("/")
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", form_context(request))

    @app.post("/jobs")
    async def submit(request: Request, report: UploadFile = File(...),
                     scanner: str = Form(...), model: str = Form(...),
                     api_key: str = Form(""), profile_json: str = Form("")):
        api_key = api_key.strip() or None
        values = dict(scanner=scanner, model=model, profile_json=profile_json)

        def bad(msg: str):
            return templates.TemplateResponse(
                request, "index.html", form_context(request, error=msg, **values), status_code=400)

        pdf = await report.read(max_bytes + 1)
        if len(pdf) > max_bytes:
            return bad(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
        if not pdf.startswith(b"%PDF"):
            return bad("That file is not a PDF.")
        if scanner not in all_scanners():
            return bad(f"Unknown scanner '{scanner}'.")

        cfg = None
        if model == CUSTOM:
            try:
                cfg = json.loads(profile_json)
                if not isinstance(cfg, dict):
                    raise ValueError("the profile must be a JSON object")
                profile = custom_profile(cfg, api_key)
            except (ValueError, TypeError) as exc:
                return bad(f"Custom profile: {exc}")
        elif model in models:
            profile = all_models()[model]
            if not profile.is_local and not api_key:
                return bad(f"'{profile.key}' is a cloud model: paste your API key.")
            if profile.is_local:
                api_key = None
        else:
            return bad(f"Unknown model '{model}'.")

        job = store.create(pdf, scanner, model, profile, api_key, profile_json=cfg)
        worker.submit(job)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    def job_or_404(job_id: str):
        job = store.get(job_id)
        if job is None:
            raise HTTPException(404, "No such job (results are deleted after "
                                     f"{int(retention_h)} hours).")
        return job

    def status_payload(job) -> dict:
        return {
            "id": job.id, "status": job.status, "stage": job.stage,
            "queue_position": store.queue_position(job) if job.status == "queued" else None,
            "total_blocks": job.total_blocks, "done_blocks": job.done_blocks,
            "records": job.records, "duration_s": job.duration_s, "cost_usd": job.cost_usd,
            "error": job.error, "updated_at": job.updated_at,
            "scanner": job.scanner, "model": job.model,
        }

    @app.get("/jobs/{job_id}")
    def job_page(request: Request, job_id: str):
        job = job_or_404(job_id)
        return templates.TemplateResponse(request, "job.html", {
            "request": request, "job": status_payload(job), "exports": EXPORTS,
            "retention_h": int(retention_h),
        })

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        return JSONResponse(status_payload(job_or_404(job_id)))

    @app.get("/jobs/{job_id}/download/{fmt}")
    def download(job_id: str, fmt: str):
        job = job_or_404(job_id)
        if fmt not in EXPORTS:
            raise HTTPException(404, "Unknown format.")
        path = store.job_dir(job.id) / "run" / f"results.{fmt}"
        if job.status != "done" or not path.is_file():
            raise HTTPException(404, "Not ready.")
        return FileResponse(path, filename=f"mulitaminer-{job.scanner}-{job.id[:8]}.{fmt}")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
