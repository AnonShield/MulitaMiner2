# Web interface

A browser front end for `mulitaminer extract`: upload a scanner PDF, pick the
scanner and the model, download the results. Jobs run in the background one
at a time; the job page is a link you can close and come back to.

Pages: `/` (what the tool is, how it works, the papers), `/app` (the form,
with a guide explaining every field, including the custom-profile JSON) and
`/jobs/<id>` (status, then downloads). Every exporter runs at the end of a
job, so the job page offers XLSX, CSV, JSON, SARIF, CSAF, DefectDojo and CAIS.

Design and rationale: [specs/2026-11-03-web-interface-design.md](specs/2026-11-03-web-interface-design.md).

## Run it on your machine

Bare process (fastest; local models need an Ollama already running on
`localhost:11434`, cloud models take the key from the form):

```bash
uv sync --group web
uv run uvicorn mulitaminer.web.app:app --reload --port 8000
```

Open <http://localhost:8000>.

With Docker, including the fine-tuned local model served by Ollama
([DOCKER.md](DOCKER.md) explains that part):

```bash
docker compose -f docker-compose.yml -f docker-compose.web.yml up web
```

Same address. The v4 model appears in the model list as `mulita-qwen2.5-1.5b-v4`
(local, no key). Without a GPU it runs on the CPU and is slow.

## Settings

All optional, read at startup:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MULITAMINER_WEB_DATA` | `~/.mulitaminer/web` | Where jobs live (`<data>/jobs/<id>/`); only ciphertext and `job.json` are ever written there. Plaintext exists only in the OS temp dir while a job runs |
| `MULITAMINER_WEB_MODELS` | every profile in `configs/llms` | Comma-separated profile keys offered in the form |
| `MULITAMINER_WEB_MAX_MB` | `20` | Upload limit |
| `MULITAMINER_WEB_RETENTION_H` | `24` | Hours a finished job (PDF, results, log) is kept |
| `MULITAMINER_WEB_MAX_QUEUE` | `20` | Pending jobs accepted before the form answers "queue is full" (HTTP 503) |
| `MULITAMINER_WEB_RATE_PER_HOUR` | `10` | Submissions per client address per hour before HTTP 429 |
| `MULITAMINER_WEB_ALLOW_PRIVATE_URLS` | unset | `1` lets a custom profile point at localhost or a private network (your own machine only; on the public site it is an SSRF vector) |
| `MULITAMINER2_LLMS_DIR` | unset | Extra profiles, as for the CLI ([ADDING_A_MODEL.md](ADDING_A_MODEL.md)) |

## Custom model

The last entry in the model list, "Custom (OpenAI-compatible endpoint)",
takes a profile JSON in the same format as `configs/llms/*.json`. It is used
for that job only. `api_key_env` is not accepted: a filled API key field
means a keyed provider, an empty one means a keyless server.

## API keys

The key is sent with the form, held in memory while the job runs, and
dropped when it finishes. It is never written to disk or logged, and provider
error messages that contain it are replaced. Even so, the server operator
could read it in flight, so use a key with a spending limit.

The job link is the only credential for the result: anyone with it can
download the spreadsheet until the retention window ends.

## Security model

What the design does and does not protect, so the operator and the user know
where they stand.

| Asset | Where it is | Who can read it |
| --- | --- | --- |
| API key | the browser's password field until submit; the server's memory while the job runs | the user; the server operator (root on the box could dump memory or patch the code). Never on disk, never in logs, never echoed back into a page. |
| The PDF and the results | `/data/jobs/<id>/`, encrypted at rest (Fernet, AES-128-CBC + HMAC) with a key derived from the job link; the server stores the hash of the link, not the link | whoever has the link. The operator sees only ciphertext on disk, plus the plaintext PDF during the run itself (seconds to hours) |
| The report's content | the LLM provider the user chose | that provider, under its own terms |

The job link is `/jobs/<token>`: the token's hash is the directory name and
the token is the encryption key. Losing the link means losing the result;
the server cannot recover it. Because the token travels in the URL, the
containers run uvicorn with `--no-access-log`, and the Caddy site block
should not log requests either (the AnonShield blocks do).

Measures in the code: HTTPS terminated by Caddy; `type=password` input with
autocomplete off; the key is not part of any URL or re-rendered form;
provider error messages that contain the key are replaced; Jinja autoescaping
on every user-controlled string; downloads are looked up by slug, never by
path; upload magic bytes and size checked server side; a custom `base_url`
may not resolve to a private, loopback or link-local address on the public
site (otherwise a user could make the server call internal services with
their request); a queue cap bounds disk and CPU use; a per-address rate
limit (`MULITAMINER_WEB_RATE_PER_HOUR`, default 10) bounds abuse by one
visitor.

Not covered, by choice: there is no login, so results are only as private as
the link; the rate limit is per address, so a botnet is not stopped (Caddy or
a WAF would be the place for that); the operator is trusted while a job runs.
The honest advice to users is on the form: use a key with a spending limit,
and pseudonymize the report first if it is sensitive.

## Public deployment (behind Caddy)

`docker-compose.prod.yml` runs the web app alone, cloud models only, with no
published port. It joins the Docker network of the Caddy that already serves
the AnonShield domains, and Caddy proxies the subdomain to it.

On the server:

```bash
git clone https://github.com/INARI18/MulitaMiner2.git && cd MulitaMiner2
CADDY_NETWORK=<network of the caddy container> docker compose -f docker-compose.prod.yml up -d --build
```

`docker network ls` shows the candidates; `docker inspect <caddy container>`
confirms which one it is on.

Caddyfile block (the body limit must cover the upload limit; Caddy's default
for the other sites is 1 MB):

```
mulita.anonshield.org {
    request_body {
        max_size 20MB
    }
    # The job link in the URL is the decryption key for that job's files.
    log {
        output discard
    }
    reverse_proxy mulitaminer-web:8000
}
```

Reload Caddy (`docker exec <caddy> caddy reload --config /etc/caddy/Caddyfile`)
and the site is up with HTTPS from Let's Encrypt.

Resource limits in the compose file (1.5 CPU, 2 GB) follow AnonShield's
sandbox convention; the app itself is light, the work happens at the
provider.
