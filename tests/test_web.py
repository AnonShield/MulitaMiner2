"""Web front end: submit, poll, download; secrets never on disk; cleanup."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from mulitaminer.models import RunResult
from mulitaminer.web import jobs
from mulitaminer.web.app import create_app

PDF = b"%PDF-1.4 fake report body"
KEY = "sk-super-secret-key-123"
FINDING = b"SMTP too long line on 127.0.0.1"


def fake_run(config, client=None, run_dir=None, doc=None, progress=None):
    """Stand-in for pipeline.run: emits progress and writes every download."""
    import logging
    assert config.formats == jobs.EXPORTS
    assert config.input_path.read_bytes() == PDF   # the worker decrypts the upload for the run
    logging.getLogger("mulitaminer.pipeline").info("Segmented 3 finding blocks")
    progress.stage("reading")
    progress.segmented(3)
    progress.chunk_done(3, 3)
    run_dir.mkdir(parents=True, exist_ok=True)
    for filename, _ in jobs.DOWNLOADS.values():
        (run_dir / filename).write_bytes(FINDING)
    (run_dir / "run.log").write_bytes(FINDING)
    return RunResult(records=[], duration_s=1.5, block_count=3), run_dir


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "pipeline_run", fake_run)
    app = create_app(data_dir=tmp_path, models=["deepseek", "qwen2.5-1.5b"], rate_per_hour=1000)
    with TestClient(app) as c:
        yield c


UPLOAD_NAME = "acme-corp internal scan (final).pdf"   # says whose network it is


def submit(client, **overrides):
    data = {"scanner": "openvas", "model": "deepseek", "api_key": KEY} | overrides
    return client.post("/jobs", data=data, files={"report": (UPLOAD_NAME, PDF, "application/pdf")},
                       follow_redirects=False)


def token_of(response) -> str:
    return response.headers["location"].rsplit("/", 1)[1]


def wait_done(client, token, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/jobs/{token}").json()
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_submit_poll_download(client, tmp_path):
    r = submit(client)
    assert r.status_code == 303
    token = token_of(r)
    status = wait_done(client, token)
    assert status["status"] == "done"
    assert status["done_blocks"] == 3 and status["total_blocks"] == 3
    assert any("Segmented 3 finding blocks" in line for line in status["log"])
    assert "Segmented 3 finding blocks" in client.get(f"/jobs/{token}").text
    for slug, (filename, _) in jobs.DOWNLOADS.items():
        r = client.get(f"/jobs/{token}/download/{slug}")
        assert r.content == FINDING, slug
        suffix = filename.split("results", 1)[1]
        assert f'filename="openvas-acme-corp_internal_scan_final{suffix}"' in r.headers["content-disposition"]
    assert client.get(f"/jobs/{token}/download/pdf").status_code == 404
    assert client.get(f"/jobs/{jobs.job_id(token)}").status_code == 404   # the id alone opens nothing


def test_secrets_and_content_never_on_disk_in_clear(client, tmp_path, caplog):
    token = token_of(submit(client))
    wait_done(client, token)
    job_dir = tmp_path / "jobs" / jobs.job_id(token)
    for path in job_dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert KEY.encode() not in data, path
            assert PDF not in data and FINDING not in data, path
            assert token.encode() not in data and b"acme" not in data, path
    assert KEY not in caplog.text and token not in caplog.text
    job = client.app.state.store.get(jobs.job_id(token))
    assert job.api_key is None and job.cipher is None


def test_validation_creates_no_job(client, tmp_path):
    assert submit(client, api_key="").status_code == 400
    r = client.post("/jobs", data={"scanner": "openvas", "model": "deepseek", "api_key": KEY},
                    files={"report": ("r.pdf", b"not a pdf", "application/pdf")})
    assert r.status_code == 400
    assert submit(client, scanner="nope").status_code == 400
    assert submit(client, model="haiku").status_code == 400   # not in the allowed list
    assert list((tmp_path / "jobs").iterdir()) == []


def test_local_model_needs_no_key(client):
    assert submit(client, model="qwen2.5-1.5b", api_key="").status_code == 303


def test_custom_profile(client, tmp_path):
    cfg = {"key": "mine", "model": "m", "base_url": "https://x.example/v1",
           "context_window": 1000, "max_output_tokens": 100}
    r = submit(client, model="custom", profile_json=json.dumps(cfg))
    assert r.status_code == 303
    token = token_of(r)
    assert wait_done(client, token)["status"] == "done"
    meta = json.loads((tmp_path / "jobs" / jobs.job_id(token) / "job.json").read_text())
    assert meta["profile_json"] == cfg
    bad = submit(client, model="custom", profile_json=json.dumps(cfg | {"api_key_env": "X"}))
    assert bad.status_code == 400
    assert submit(client, model="custom", profile_json="{nope").status_code == 400


def test_custom_profile_rejects_private_hosts_on_public_site(client, tmp_path, monkeypatch):
    for url in ("http://127.0.0.1:11434/v1", "http://localhost:8000/v1", "http://10.0.0.5/v1",
                "http://169.254.169.254/v1", "ftp://x.example/v1"):
        cfg = {"key": "m", "model": "m", "base_url": url, "context_window": 10, "max_output_tokens": 5}
        assert submit(client, model="custom", profile_json=json.dumps(cfg)).status_code == 400, url
    monkeypatch.setattr(jobs, "pipeline_run", fake_run)
    with TestClient(create_app(data_dir=tmp_path / "local", models=["deepseek"], allow_private=True)) as c:
        cfg = {"key": "m", "model": "m", "base_url": "http://localhost:11434/v1",
               "context_window": 10, "max_output_tokens": 5}
        assert submit(c, model="custom", profile_json=json.dumps(cfg), api_key="").status_code == 303


def test_failed_run_reports_message(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError(f"provider said no to {KEY}")
    monkeypatch.setattr(jobs, "pipeline_run", boom)
    token = token_of(submit(client))
    status = wait_done(client, token)
    assert status["status"] == "failed"
    assert KEY not in status["error"]
    assert client.get(f"/jobs/{token}/download/xlsx").status_code == 404


def test_purge_keeps_recent_jobs(tmp_path):
    store = jobs.JobStore(tmp_path)
    old, _ = store.create(PDF, "openvas", "deepseek", None, None)
    new, _ = store.create(PDF, "openvas", "deepseek", None, None)
    for job, hours in ((old, 25), (new, 1)):
        job.status = "done"
        job.finished_at = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        store.save(job)
    assert store.purge_older_than(24) == 1
    assert store.get(old.id) is None and not store.job_dir(old.id).exists()
    assert store.get(new.id) is not None


def test_restart_fails_unfinished_jobs_and_shreds_plaintext(tmp_path):
    store = jobs.JobStore(tmp_path)
    job, _ = store.create(PDF, "openvas", "deepseek", None, None)
    (store.job_dir(job.id) / "input.pdf").write_bytes(PDF)   # as if cut mid-run
    store2 = jobs.JobStore(tmp_path)
    store2.load()
    assert store2.get(job.id).status == "failed"
    assert "restarted" in store2.get(job.id).error
    assert not (store.job_dir(job.id) / "input.pdf").exists()
    assert (store.job_dir(job.id) / "input.pdf.enc").exists()


def test_run_dir_becomes_one_archive(client, tmp_path):
    token = token_of(submit(client))
    wait_done(client, token)
    job_dir = tmp_path / "jobs" / jobs.job_id(token)
    assert sorted(p.name for p in job_dir.iterdir()) == ["input.pdf.enc", "job.json", "name.enc", "results.tar.enc"]


def test_plaintext_never_written_to_data_dir(client, tmp_path, monkeypatch):
    seen = []

    def spy_run(config, client=None, run_dir=None, doc=None, progress=None):
        seen.append((config.input_path.resolve(), run_dir.resolve()))
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", spy_run)
    token = token_of(submit(client))
    wait_done(client, token)
    pdf, run_dir = seen[0]
    assert tmp_path.resolve() not in pdf.parents and tmp_path.resolve() not in run_dir.parents
    assert not pdf.exists() and not run_dir.exists()   # the temp dir is gone with the job


def test_jobs_run_one_at_a_time(tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_run(config, client=None, run_dir=None, doc=None, progress=None):
        gate.wait(5)
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", slow_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"], rate_per_hour=1000)) as c:
        first = token_of(submit(c))
        second = token_of(submit(c))
        time.sleep(0.2)
        assert c.get(f"/api/jobs/{first}").json()["status"] == "running"
        s2 = c.get(f"/api/jobs/{second}").json()
        assert s2["status"] == "queued" and s2["queue_position"] == 0
        gate.set()
        assert wait_done(c, second)["status"] == "done"


def test_full_queue_answers_busy(tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_run(config, client=None, run_dir=None, doc=None, progress=None):
        gate.wait(5)
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", slow_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"], max_queue=2, rate_per_hour=1000)) as c:
        assert submit(c).status_code == 303
        assert submit(c).status_code == 303
        r = submit(c)
        assert r.status_code == 503 and "queue is full" in r.text
        gate.set()


def test_rate_limit_per_address(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "pipeline_run", fake_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"], rate_per_hour=2)) as c:
        assert submit(c).status_code == 303
        assert submit(c).status_code == 303
        r = submit(c)
        assert r.status_code == 429 and "Too many submissions" in r.text


def test_batch_creates_one_job_per_pdf_and_zips_them(client, tmp_path):
    import io
    import zipfile
    files = [("report", (f"scan-{i}.pdf", PDF, "application/pdf")) for i in range(3)]
    r = client.post("/jobs", data={"scanner": "openvas", "model": "deepseek", "api_key": KEY},
                    files=files, follow_redirects=False)
    assert r.status_code == 303 and "/batch/" in r.headers["location"]
    tokens = r.headers["location"].rsplit("/", 1)[1]
    assert len(tokens.split(".")) == 3
    for token in tokens.split("."):
        assert wait_done(client, token)["status"] == "done"
    page = client.get(f"/batch/{tokens}")
    assert page.status_code == 200 and "scan-2" in page.text
    r = client.get(f"/batch/{tokens}/download/xlsx")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    names = sorted(zipfile.ZipFile(io.BytesIO(r.content)).namelist())
    assert names == ["openvas-scan-0.xlsx", "openvas-scan-1.xlsx", "openvas-scan-2.xlsx"]
    assert client.get("/batch/nope.nope").status_code == 404


def test_batch_counts_against_the_queue_once_per_pdf(tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_run(config, client=None, run_dir=None, doc=None, progress=None):
        gate.wait(5)
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", slow_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"], max_queue=2, rate_per_hour=1000)) as c:
        files = [("report", (f"s{i}.pdf", PDF, "application/pdf")) for i in range(3)]
        r = c.post("/jobs", data={"scanner": "openvas", "model": "deepseek", "api_key": KEY},
                   files=files, follow_redirects=False)
        assert r.status_code == 503
        gate.set()


def test_pages_render(client):
    assert "Research" in client.get("/").text
    assert "Profile JSON" in client.get("/app").text


def test_security_headers_on_every_response(client):
    for path in ("/", "/app", "/api/health", "/static/style.css"):
        h = client.get(path).headers
        assert h["referrer-policy"] == "no-referrer", path
        assert "frame-ancestors 'none'" in h["content-security-policy"], path
        assert h["x-content-type-options"] == "nosniff", path


def test_language_switch_and_cookie(client):
    r = client.get("/?lang=pt")
    assert "Como funciona" in r.text and r.cookies.get("lang") == "pt"
    assert "Guia" in client.get("/app").text          # the cookie now carries the choice
    client.cookies.clear()
    assert "Cómo funciona" in client.get("/", headers={"accept-language": "es-ES,es;q=0.9"}).text
    r = client.post("/jobs", data={"scanner": "openvas", "model": "custom", "profile_json": "{nope"},
                    files={"report": ("r.pdf", PDF, "application/pdf")},
                    headers={"accept-language": "pt-BR"})
    assert r.status_code == 400 and "Perfil custom" in r.text
