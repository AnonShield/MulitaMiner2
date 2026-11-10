# Web interface

A browser front end for `mulitaminer extract`: upload a scanner PDF, pick the
scanner and the model, download the results. Jobs run in the background, a
few at a time for cloud models (the work happens at the provider) and one at
a time for local models (they share one GPU); the job page is a link you can
close and come back to.

Pages: `/` (what the tool is, how it works, the papers, with a "how to cite"
BibTeX block), `/app` (the form, with a guide explaining every field,
including the custom-profile JSON), `/jobs/<token>` (status, live log, then
downloads), `/batch/<tokens>` (several PDFs submitted together: one job each,
a zip per format of the finished ones), `/example` (a precomputed finished
job, see below) and `/privacy` (what the server stores, in plain words).
Every exporter runs at the end of a job, so the job page offers XLSX, CSV,
JSON, SARIF, CSAF, DefectDojo and CAIS. The browser keeps its own list of
the jobs it opened (localStorage) and shows it on `/app`. The footer shows
the package version and, in the published image, the commit it was built
from.

Design and rationale: [specs/2026-11-03-web-interface-design.md](specs/2026-11-03-web-interface-design.md).

## Run it on your machine

Bare process (fastest; local models need an Ollama already running on
`localhost:11434`, cloud models take the key from the form):

```bash
uv sync --group web
uv run mulitaminer web
```

Open <http://localhost:8000>. `--port` and `--host` change the address;
`--reload` restarts the server when Python files change (templates and the
stylesheet are picked up without it).

With Docker, including the fine-tuned local model served by Ollama
([DOCKER.md](DOCKER.md) explains that part):

```bash
docker compose -f docker-compose.yml -f docker-compose.web.yml up web
```

Same address. The v4 model appears in the model list as `mulita-qwen2.5-1.5b-v4`
(local, no key). Without a GPU it runs on the CPU and is slow.

## Without cloning: the published image

GitHub Actions publishes the image to Docker Hub on
every push to `main` ([.github/workflows/docker-image.yml](../.github/workflows/docker-image.yml)),
so a user needs Docker and nothing else:

```bash
docker run -d --name mulita-web -p 127.0.0.1:8000:8000 -v mulita-web:/data bia18/mulitaminer:web
```

That is the cloud-models setup (the key goes in the form). For the
fine-tuned local model the Ollama service is needed too, which is what
`docker-compose.web.yml` wires up; that one does need the repo, or at least
the two compose files.

## Settings

All optional, read at startup:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MULITAMINER_WEB_DATA` | `~/.mulitaminer/web` | Where jobs live (`<data>/jobs/<id>/`); only ciphertext and `job.json` are ever written there. Plaintext exists only in the OS temp dir while a job runs |
| `MULITAMINER_WEB_MODELS` | every profile in `configs/llms` | Comma-separated profile keys offered in the form |
| `MULITAMINER_WEB_MAX_MB` | `20` | Upload limit |
| `MULITAMINER_WEB_RETENTION_H` | `24` | Hours a finished job (PDF, results, log) is kept |
| `MULITAMINER_WEB_MAX_QUEUE` | `20` | Pending jobs accepted before the form answers "queue is full" (HTTP 503) |
| `MULITAMINER_WEB_MAX_BATCH` | `10` | PDFs accepted in one submission; each becomes a job and a queue slot |
| `MULITAMINER_WEB_RATE_PER_HOUR` | `10` | Submissions per client address per hour before HTTP 429 |
| `MULITAMINER_WEB_ALLOW_PRIVATE_URLS` | unset | `1` lets a custom profile point at localhost or a private network (your own machine only; on the public site it is an SSRF vector) |
| `MULITAMINER_WEB_WORKERS` | `3` | Jobs run at the same time. Local-model jobs are serialised regardless |
| `MULITAMINER_WEB_EXAMPLE_DIR` | the package's `web/example` | Where the precomputed example lives (below) |
| `MULITAMINER_WEB_BUILD` | unset | Commit shown in the footer; the Dockerfile sets it from the `GIT_SHA` build arg |
| `MULITAMINER2_LLMS_DIR` | unset | Extra profiles, as for the CLI ([ADDING_A_MODEL.md](ADDING_A_MODEL.md)) |

## The example page

`/example` is a job page that was computed once and committed: a public
sample report, its live log and every download, so a visitor sees the real
output without a key and without waiting. Regenerate it after a change that
alters the output (a prompt, an exporter, the schema):

```bash
uv run mulitaminer web-example resources/openvas/OpenVAS_JuiceShop.pdf -s openvas -m deepseek
```

That writes the downloads and `example.json` into `src/mulitaminer/web/example/`
(the model's key comes from `.env`, as for `extract`). Without that folder
the page answers 404 and the links to it disappear from the site.

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

Measures in the code: HTTPS terminated by Caddy; security headers on every
response (a Content-Security-Policy that allows scripts from this origin
only, `Referrer-Policy: no-referrer` so the job link never travels to another
site, no framing); `type=password` input with autocomplete off; the key is not part of any URL or re-rendered form;
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

## Public deployment (mulitaminer.anonshield.org)

`docker-compose.prod.yml` runs the web app alone, cloud models only, published
on the server's loopback (`127.0.0.1:18090`). The Caddy that runs on the host
itself (the systemd service, `/etc/caddy/Caddyfile`) owns ports 80 and 443,
terminates TLS and routes each name to a loopback port; Cloudflare proxies the
name in front of it (a proxied CNAME to `anonshield.org`).

On the server, as a user in the `docker` group:

```bash
git clone https://github.com/AnonShield/MulitaMiner2.git && cd MulitaMiner2
docker-compose -f docker-compose.prod.yml up -d --build
curl -s http://127.0.0.1:18090/api/health   # {"status":"ok"}
```

Updating is `git pull` and the same `up -d --build`. `MULITAMINER_WEB_PORT`
changes the loopback port.

Host Caddy block (`/etc/caddy/Caddyfile`, root), in the same shape as the
other AnonShield names: `tls internal` because Cloudflare talks to the origin
in "full" mode, and the `somente_cloudflare` snippet, which answers 403 to
anything not coming from Cloudflare. The body limit must cover the upload
limit (Caddy's default is 1 MB):

```
mulitaminer.anonshield.org {
    tls internal
    import somente_cloudflare
    encode zstd gzip
    request_body {
        max_size 20MB
    }
    header {
        -Server
        X-Content-Type-Options "nosniff"
    }
    # No access log: the job link in the URL is the decryption key for that
    # job's files.
    log {
        output discard
    }
    reverse_proxy 127.0.0.1:18090 {
        # Overwrite, do not append: the app's rate limit counts per this
        # address. Only Cloudflare reaches this block, so its header is the
        # real client; {remote_host} would be a Cloudflare edge.
        header_up X-Forwarded-For {header.CF-Connecting-IP}
    }
}
```

Then `sudo caddy validate --config /etc/caddy/Caddyfile` and
`sudo systemctl reload caddy`. The DNS side is a proxied CNAME
`mulitaminer.anonshield.org -> anonshield.org` in Cloudflare (done 2026-11-10).

Resource limits in the compose file (1.5 CPU, 2 GB) follow AnonShield's
sandbox convention; the app itself is light, the work happens at the
provider.
