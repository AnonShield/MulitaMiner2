"""FastAPI app: landing page, upload form, job page, downloads (docs/WEB.md)."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mulitaminer.llm import ModelProfile, all_models
from mulitaminer.scanner_engine import all_scanners
from mulitaminer.web.jobs import DOWNLOADS, Cleaner, JobStore, Worker, custom_profile

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
    "openvas": ("OpenVAS / Greenbone", "Greenbone Security Assistant, the scan's PDF report"),
    "nessus": ("Tenable Nessus", "Nessus Professional or Essentials, PDF export"),
    "tenable": ("Tenable Web App Scanning", "Tenable WAS (tenable.io), detailed scan export"),
    "tenable-vm": ("Tenable Vulnerability Management", "Tenable VM, 'Vulnerabilities by Asset' report"),
    "qualys": ("Qualys", "Qualys VMDR scan report"),
    "acunetix": ("Acunetix 360", "Acunetix 360 / Invicti scan report"),
    "zap": ("OWASP ZAP", "ZAP traditional report, printed to PDF"),
}


def _env_models() -> list[str]:
    raw = os.getenv("MULITAMINER_WEB_MODELS", "")
    return [m.strip() for m in raw.split(",") if m.strip()]


def model_view(p: ModelProfile) -> dict:
    provider, key_url = PROVIDERS.get(p.api_key_env or "", ("local server" if p.is_local else "custom", ""))
    return {"key": p.key, "label": MODEL_LABELS.get(p.key, p.key), "model": p.model,
            "is_local": p.is_local, "provider": provider, "key_url": key_url}


def scanner_view(key: str) -> dict:
    label, desc = SCANNERS.get(key, (key, "custom scanner profile"))
    return {"key": key, "label": label, "desc": desc}


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

    def base_context(request: Request) -> dict:
        return {"request": request, "retention_h": int(retention_h), "max_mb": max_bytes // (1024 * 1024)}

    def form_context(request: Request, error: str | None = None, **values) -> dict:
        profiles = all_models()
        return base_context(request) | {
            "scanners": [scanner_view(s) for s in sorted(all_scanners())],
            "models": [model_view(profiles[m]) for m in models],
            "custom": CUSTOM,
            "profile_template": PROFILE_TEMPLATE,
            "error": error,
            "values": values,
        }

    @app.get("/")
    def index(request: Request):
        profiles = all_models()
        return templates.TemplateResponse(request, "index.html", base_context(request) | {
            "scanner_labels": [scanner_view(s)["label"] for s in sorted(all_scanners())],
            "model_labels": [MODEL_LABELS.get(m, m) for m in models],
            "profiles": profiles,
        })

    @app.get("/app")
    def form(request: Request):
        return templates.TemplateResponse(request, "app.html", form_context(request))

    @app.post("/jobs")
    async def submit(request: Request, report: UploadFile = File(...),
                     scanner: str = Form(...), model: str = Form(...),
                     api_key: str = Form(""), profile_json: str = Form("")):
        api_key = api_key.strip() or None
        values = dict(scanner=scanner, model=model, profile_json=profile_json)

        def bad(msg: str):
            return templates.TemplateResponse(
                request, "app.html", form_context(request, error=msg, **values), status_code=400)

        pdf = await report.read(max_bytes + 1)
        if len(pdf) > max_bytes:
            return bad(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
        if not pdf.startswith(b"%PDF"):
            return bad("That file is not a PDF. Upload the scanner's PDF report export.")
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
                return bad(f"{MODEL_LABELS.get(model, model)} is a cloud model: paste your API key.")
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
        label = MODEL_LABELS.get(job.model, job.model)
        if job.model == CUSTOM and job.profile_json:
            label = f"custom · {job.profile_json.get('key', '')}"
        return {
            "id": job.id, "status": job.status, "stage": job.stage,
            "queue_position": store.queue_position(job) if job.status == "queued" else None,
            "total_blocks": job.total_blocks, "done_blocks": job.done_blocks,
            "records": job.records, "duration_s": job.duration_s, "cost_usd": job.cost_usd,
            "error": job.error, "updated_at": job.updated_at,
            "scanner": job.scanner, "model": job.model, "model_label": label,
        }

    @app.get("/jobs/{job_id}")
    def job_page(request: Request, job_id: str):
        job = job_or_404(job_id)
        return templates.TemplateResponse(request, "job.html", base_context(request) | {
            "job": status_payload(job), "downloads": DOWNLOADS,
        })

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str):
        return JSONResponse(status_payload(job_or_404(job_id)))

    @app.get("/jobs/{job_id}/download/{fmt}")
    def download(job_id: str, fmt: str):
        job = job_or_404(job_id)
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "Unknown format.")
        filename, _label = DOWNLOADS[fmt]
        path = store.job_dir(job.id) / "run" / filename
        if job.status != "done" or not path.is_file():
            raise HTTPException(404, "Not ready.")
        suffix = filename.split("results", 1)[1]   # ".xlsx", ".cais.csv", ...
        return FileResponse(path, filename=f"mulitaminer-{job.scanner}-{job.id[:8]}{suffix}")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
