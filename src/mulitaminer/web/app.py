"""FastAPI app: landing page, upload form, job page, downloads (docs/WEB.md)."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mulitaminer.llm import ModelProfile, all_models
from mulitaminer.scanner_engine import all_scanners
from mulitaminer.web.i18n import LANGS, pick_lang, strings
from mulitaminer.web.jobs import (DOWNLOADS, Cleaner, JobStore, RateLimit, Worker, custom_profile,
                                  fernet, job_id)

MEDIA = {".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         ".csv": "text/csv", ".json": "application/json", ".sarif": "application/json"}

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
    "openvas": ("OpenVAS / Greenbone", "Greenbone Security Assistant, PDF report"),
    "nessus": ("Tenable Nessus", "Nessus Professional / Essentials, PDF export"),
    "tenable": ("Tenable Web App Scanning", "Tenable WAS, detailed scan export"),
    "tenable-vm": ("Tenable Vulnerability Management", "Tenable VM, 'Vulnerabilities by Asset'"),
    "qualys": ("Qualys", "Qualys VMDR scan report"),
    "acunetix": ("Acunetix 360", "Acunetix 360 / Invicti scan report"),
    "zap": ("OWASP ZAP", "ZAP traditional report, printed to PDF"),
}
# Union of the authors of the four MulitaMiner papers, in author order.
TEAM = [
    ("Beatriz Machado", "UNIPAMPA"),
    ("Douglas Lautert", "UNIPAMPA"),
    ("Cristhian Kapelinski", "UNIPAMPA"),
    ("Diego Kreutz", "UNIPAMPA"),
    ("Isadora Garcia Ferrão", "Université de Bretagne Occidentale"),
    ("Alessandro Bof", "UNIPAMPA"),
]
# Strings the page scripts need (file checks, model switch, job polling).
JS_KEYS = ("err_not_pdf", "err_too_big", "f_custom_id", "f_modelid", "f_served_local",
           "f_key_local", "f_key_custom", "f_key_req", "f_key_hint", "f_get_key", "show",
           "hide", "f_uploading", "st_queued", "st_running", "st_done", "st_failed", "q_pos",
           "q_next", "starting", "findings", "stage_reading", "stage_segmenting",
           "stage_extracting")


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
               max_mb: float | None = None, retention_h: float | None = None,
               max_queue: int | None = None, allow_private: bool | None = None,
               rate_per_hour: int | None = None) -> FastAPI:
    data_dir = data_dir or Path(os.getenv("MULITAMINER_WEB_DATA", "outputs/web"))
    models = models or _env_models() or sorted(all_models())
    max_bytes = int((max_mb or float(os.getenv("MULITAMINER_WEB_MAX_MB", "20"))) * 1024 * 1024)
    retention_h = retention_h or float(os.getenv("MULITAMINER_WEB_RETENTION_H", "24"))
    # Pending jobs (queued + running) accepted before the form answers "busy".
    max_queue = max_queue or int(os.getenv("MULITAMINER_WEB_MAX_QUEUE", "20"))
    # Custom base_url may reach localhost / the Docker network only when the
    # user runs the app themselves (docker-compose.web.yml sets it).
    if allow_private is None:
        allow_private = os.getenv("MULITAMINER_WEB_ALLOW_PRIVATE_URLS", "") == "1"
    # Submissions per client address per hour (behind Caddy, uvicorn's
    # --proxy-headers makes request.client the real address).
    rate = RateLimit(rate_per_hour or int(os.getenv("MULITAMINER_WEB_RATE_PER_HOUR", "10")))
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
            "team": [{"name": n, "affiliation": a,
                      "initials": "".join(w[0] for w in n.split()[:2])} for n, a in TEAM],
        })

    @app.get("/app")
    def form(request: Request):
        return render(request, "app.html", form_context())

    @app.post("/jobs")
    async def submit(request: Request, report: UploadFile = File(...),
                     scanner: str = Form(...), model: str = Form(...),
                     api_key: str = Form(""), profile_json: str = Form("")):
        t = strings(lang_of(request))
        api_key = api_key.strip() or None
        values = dict(scanner=scanner, model=model, profile_json=profile_json)

        def bad(msg: str):
            return render(request, "app.html", form_context(error=msg, **values), status_code=400)

        if store.pending() >= max_queue:
            return render(request, "app.html", form_context(error=t["e_busy"], **values),
                          status_code=503)
        if not rate.allow(request.client.host if request.client else "?"):
            return render(request, "app.html", form_context(error=t["e_rate"], **values),
                          status_code=429)
        pdf = await report.read(max_bytes + 1)
        if len(pdf) > max_bytes:
            return bad(t["e_too_big"].format(mb=max_bytes // (1024 * 1024)))
        if not pdf.startswith(b"%PDF"):
            return bad(t["e_not_pdf"])
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

        job, token = store.create(pdf, scanner, model, profile, api_key, profile_json=cfg)
        worker.submit(job)
        return RedirectResponse(f"/jobs/{token}", status_code=303)

    def job_or_404(token: str):
        """The link's token names the job (by hash) and decrypts its files."""
        job = store.get(job_id(token))
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

    @app.get("/jobs/{token}")
    def job_page(request: Request, token: str):
        job = job_or_404(token)
        return render(request, "job.html", {"job": status_payload(job), "token": token,
                                            "downloads": DOWNLOADS})

    @app.get("/api/jobs/{token}")
    def job_status(token: str):
        return JSONResponse(status_payload(job_or_404(token)))

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
        return Response(data, media_type=MEDIA.get(Path(filename).suffix, "application/octet-stream"),
                        headers={"Content-Disposition":
                                 f'attachment; filename="mulitaminer-{job.scanner}-{job.id[:8]}{suffix}"'})

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
