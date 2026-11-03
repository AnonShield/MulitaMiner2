# Web interface design (2026-11-03)

A browser front end for `mulitaminer extract`: upload a scanner PDF, pick the
scanner and the model, get the spreadsheet back. One container, served behind
the AnonShield Caddy as `mulitaminer.anonshield.org`.

## Goals

- Public demo: cloud models only, the user brings their own API key.
- Same image runs on a user's machine with the local fine-tuned model
  (`docker compose up web`), which is how local models are offered.
- Long jobs survive: DeepSeek takes 34 s on a 5-block ZAP report and 2 h on
  the 1053-block Qualys report, so extraction runs in the background and the
  user comes back to a job link.

## Non-goals

- Login, accounts, job history, usage metering.
- More than one extraction at a time.
- Local models on the public site (the server has no GPU; CPU throughput was
  never measured, see Mulita-Training TRAINING.md arm 3).
- Scanner auto-detection: the CLI resolves the scanner from the folder name,
  never from content, so the web form requires an explicit choice.

## Architecture

One Python process: FastAPI serves the pages and the API, a worker thread runs
one job at a time, a cleanup thread deletes old jobs. No database, no Redis,
no Node. State is the filesystem under `MULITAMINER_WEB_DATA` (default
`/data`, a Docker volume).

```
browser --HTTPS--> Caddy (Cristhian's) --HTTP--> web:8000
                                                  |-- FastAPI (upload, status, download)
                                                  |-- worker thread -> pipeline.run()
                                                  |-- cleanup thread (24 h)
                                                  '-- /data/jobs/<id>/
```

### Package layout

```
src/mulitaminer/web/
  __init__.py
  app.py        FastAPI app, routes, templates
  jobs.py       Job dataclass, JobStore (disk), worker queue, cleanup
  templates/    index.html, job.html (Jinja2, no build step)
  static/       one stylesheet
```

Dependencies in a new optional group `web`: `fastapi`, `uvicorn`,
`python-multipart`, `jinja2`. The CLI install stays untouched.

### Components

**JobStore** (`jobs.py`): owns `/data/jobs/<id>/`. Methods: `create(upload,
scanner, model)`, `get(id)`, `set_status(id, ...)`, `purge_older_than(hours)`.
A job directory holds:

| File | Written by | Kept |
| --- | --- | --- |
| `input.pdf` | upload | 24 h (kept so a failed job can be re-run and inspected) |
| `job.json` | store | status, scanner, model, timestamps, block counts, error message |
| `run/` | `pipeline.run(run_dir=...)` | the usual run artifacts: records json, run.log, exports |

Job ids come from `secrets.token_urlsafe(16)`. The id is the only credential:
whoever has the link can read the result. Acceptable for a demo with no
accounts, stated in the UI.

**Worker** (`jobs.py`): a `queue.Queue` and one daemon thread. For each job it
builds the `LLMClient` and calls `pipeline.run(config, client=client,
run_dir=job_dir / "run", progress=JobProgress(job))`. `JobProgress` subclasses
`ui.Progress` and writes `segmented(total)` and `chunk_done` counts to
`job.json`, so the page can show "12 / 34 blocks". Exceptions mark the job
`failed` with the exception message. Queue position is the number of queued
jobs ahead, shown on the page.

**API key handling**: the key lives only in the in-memory `Job` object while
the job is queued or running, and is dropped when it finishes. It never goes
into `job.json`, the run dir, logs, or error messages. The client is built as
`LLMClient(profile, transport=OpenAI(base_url=profile.base_url,
api_key=key, ...))`, mirroring the constructor's own call, so `llm.py` is not
changed and `os.environ` is never touched (a process-wide env var would leak
between jobs). For local profiles (`profile.is_local`) no key is asked for.

Error messages from the provider are passed through verbatim only after a
check that the key string is not in them; otherwise a generic "provider
rejected the request" is shown.

**Cleanup**: a daemon thread calls `purge_older_than(24)` every hour; a job
is purged by its `finished_at` (or `created_at` if it never ran). Also runs
once at startup.

### Routes

| Method | Path | Does |
| --- | --- | --- |
| GET | `/` | form: PDF, scanner (select), model (select), API key (shown only for non-local models) |
| POST | `/jobs` | validates, stores, enqueues; redirects to `/jobs/{id}` |
| GET | `/jobs/{id}` | status page; refreshes itself every 5 s while queued/running |
| GET | `/jobs/{id}/download/{fmt}` | `xlsx` or `csv` from the run dir (404 until done) |
| GET | `/api/jobs/{id}` | JSON status, what the page polls |
| GET | `/api/health` | 200, for Docker healthcheck |

The model list comes from `MULITAMINER_WEB_MODELS` (comma-separated profile
keys; default: every profile in `configs/llms`). Production sets it to the
cloud profiles; the local compose leaves the default, so the v4 shows up.

### Custom model profile

The CLI adds a model by dropping a JSON file (docs/ADDING_A_MODEL.md). The
web keeps that coupling: the model select has a last entry, "Custom
(OpenAI-compatible)", which reveals a textarea prefilled with a profile
template in exactly the `configs/llms/*.json` format:

```json
{
  "key": "my-model",
  "model": "provider-model-id",
  "base_url": "https://api.example.com/v1",
  "context_window": 128000,
  "max_output_tokens": 8000,
  "supports_json_schema": false
}
```

Rules:

- Same validation as `load_llm_profile`: unknown fields are rejected with
  the list of valid ones; the dict is passed to `ModelProfile(**cfg)`.
- `api_key_env` is not accepted (the server has no env for the user); the
  key field decides instead: filled means a keyed provider, empty means a
  keyless server (the profile is marked local by setting `api_key_env` to
  `None`, which is what the dataclass already means by keyless).
- The profile is used for that job only, never written to `configs/llms`
  or shared between jobs. The JSON (never the key) is stored in `job.json`
  so the run is reproducible.
- `base_url` must be `http(s)`; on the public site a `localhost` or private
  address makes no sense but is not blocked (the request would just fail).

### Validation and errors

| Condition | Result |
| --- | --- |
| file is not a PDF (magic bytes) or over `MULITAMINER_WEB_MAX_MB` (default 20) | 400 on the form, nothing stored |
| unknown scanner or model, or model not in the allowed list | 400 |
| cloud model and empty key | 400 |
| `pipeline.run` raises (no blocks found, provider error, fatal LLM error) | job `failed`, message on the page, files kept 24 h |
| process restarts with jobs queued or running | those jobs are marked `failed` ("server restarted") at startup; the user resubmits |

### Page

Two templates, one stylesheet, no JavaScript framework. `job.html` uses a
small inline script to poll `/api/jobs/{id}` and update the counters without
a full reload. Visual design is iterated locally before deployment (see
Local testing); the spec does not fix colors or layout.

## Docker

- `Dockerfile`: new build arg `INSTALL_WEB=true` installs the `web` group. The
  entrypoint stays `mulitaminer`; the web command overrides it.
- `docker-compose.web.yml` (local, with Ollama): adds service `web` next to
  the existing `ollama`/`model-register`/`mulita`, sharing the Ollama network
  namespace like `mulita` does, port `127.0.0.1:8000:8000`, volume
  `webdata:/data`. No `env_file`: cloud keys always come from the form, one
  path for both deployments.
- `docker-compose.prod.yml` (server): service `web` only, no Ollama, no
  published port, `MULITAMINER_WEB_MODELS=deepseek,gpt-4o-mini,haiku,llama-3.3-70b`,
  joined to the Caddy network as an external network, `restart:
  unless-stopped`, CPU and memory limits like AnonShield's sandbox.
- `docs/WEB.md`: how to run both, and the Caddyfile block for Cristhian:

```
mulitaminer.anonshield.org {
    request_body {
        max_size 20MB
    }
    reverse_proxy mulitaminer-web:8000
}
```

The Caddy network name on the server is not known yet (AnonShield's prod
compose calls it `anon-net`; the Compose project prefix depends on how it was
started). Confirm with Cristhian before the deploy; it is one line in
`docker-compose.prod.yml`.

## Tests

`tests/test_web.py`, FastAPI `TestClient`, `pipeline.run` monkeypatched to
write a fake records file and exports:

1. Submit a PDF with a cloud model and a key; the response redirects to a job
   page; polling reaches `done`; `xlsx` download returns the file.
2. The key string appears in no file under the job directory and in no log
   record captured by `caplog`.
3. Missing key on a cloud model and a non-PDF upload both return 400 and
   create no job directory.
4. A job whose `pipeline.run` raises ends `failed` with the message.
5. `purge_older_than(24)` removes a job dated 25 h ago and keeps one dated
   1 h ago.
6. Two submissions run sequentially (the second reports queue position 1
   while the first is running).

## Local testing before the server

- Bare process, fastest loop for the page design:
  `uv sync --group web` then
  `uv run uvicorn mulitaminer.web.app:app --reload --port 8000`, open
  `http://localhost:8000`. Cloud keys come from the form; `.env` is not read
  by the web app.
- Container, same as production minus Caddy:
  `docker compose -f docker-compose.yml -f docker-compose.web.yml up web`,
  which also brings the v4 up on Ollama (CPU) for the local-model path.
- The sample PDFs in `resources/` cover every scanner; `ZAP_ActiveMQ.pdf`
  (5 blocks, 34 s on DeepSeek) is the quick smoke test.

## Out of scope but noted

- Progress for the local model on CPU needs a profile with a larger
  `request_timeout_s`; not part of this work.
- Rate limiting or captcha if the public form gets abused: the key is the
  user's, so the cost of abuse is CPU on the server, bounded by the single
  worker.
