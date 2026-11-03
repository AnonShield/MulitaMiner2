"""Web front end: submit, poll, download; key never persisted; cleanup."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from mulitaminer.models import RunResult
from mulitaminer.web import jobs
from mulitaminer.web.app import create_app

PDF = b"%PDF-1.4 fake"
KEY = "sk-super-secret-key-123"


def fake_run(config, client=None, run_dir=None, doc=None, progress=None):
    """Stand-in for pipeline.run: emits progress and writes every download."""
    assert config.formats == jobs.EXPORTS
    progress.stage("reading")
    progress.segmented(3)
    progress.chunk_done(3, 3)
    run_dir.mkdir(parents=True, exist_ok=True)
    for filename, _ in jobs.DOWNLOADS.values():
        (run_dir / filename).write_bytes(b"x")
    return RunResult(records=[], duration_s=1.5, block_count=3), run_dir


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "pipeline_run", fake_run)
    app = create_app(data_dir=tmp_path, models=["deepseek", "qwen2.5-1.5b"])
    with TestClient(app) as c:
        yield c


def submit(client, **overrides):
    data = {"scanner": "openvas", "model": "deepseek", "api_key": KEY} | overrides
    return client.post("/jobs", data=data, files={"report": ("r.pdf", PDF, "application/pdf")},
                       follow_redirects=False)


def wait_done(client, job_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/jobs/{job_id}").json()
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_submit_poll_download(client, tmp_path):
    r = submit(client)
    assert r.status_code == 303
    job_id = r.headers["location"].rsplit("/", 1)[1]
    status = wait_done(client, job_id)
    assert status["status"] == "done"
    assert status["done_blocks"] == 3 and status["total_blocks"] == 3
    assert client.get(f"/jobs/{job_id}").status_code == 200
    for slug in jobs.DOWNLOADS:
        r = client.get(f"/jobs/{job_id}/download/{slug}")
        assert r.content == b"x", slug
        assert "mulitaminer-openvas-" in r.headers["content-disposition"]
    assert client.get(f"/jobs/{job_id}/download/pdf").status_code == 404


def test_pages_render(client):
    assert "Research" in client.get("/").text
    assert "Profile JSON" in client.get("/app").text


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


def test_key_never_touches_disk_or_logs(client, tmp_path, caplog):
    job_id = submit(client).headers["location"].rsplit("/", 1)[1]
    wait_done(client, job_id)
    for path in (tmp_path / "jobs" / job_id).rglob("*"):
        if path.is_file():
            assert KEY.encode() not in path.read_bytes(), path
    assert KEY not in caplog.text
    assert client.app.state.store.get(job_id).api_key is None


def test_validation_creates_no_job(client, tmp_path):
    assert submit(client, api_key="").status_code == 400
    r = client.post("/jobs", data={"scanner": "openvas", "model": "deepseek", "api_key": KEY},
                    files={"report": ("r.pdf", b"not a pdf", "application/pdf")})
    assert r.status_code == 400
    assert submit(client, scanner="nope").status_code == 400
    assert submit(client, model="haiku").status_code == 400   # not in the allowed list
    assert list((tmp_path / "jobs").iterdir()) == []


def test_local_model_needs_no_key(client):
    r = submit(client, model="qwen2.5-1.5b", api_key="")
    assert r.status_code == 303


def test_custom_profile(client, tmp_path):
    cfg = {"key": "mine", "model": "m", "base_url": "https://x.example/v1",
           "context_window": 1000, "max_output_tokens": 100}
    r = submit(client, model="custom", profile_json=json.dumps(cfg))
    assert r.status_code == 303
    job_id = r.headers["location"].rsplit("/", 1)[1]
    assert wait_done(client, job_id)["status"] == "done"
    meta = json.loads((tmp_path / "jobs" / job_id / "job.json").read_text())
    assert meta["profile_json"] == cfg
    bad = submit(client, model="custom", profile_json=json.dumps(cfg | {"api_key_env": "X"}))
    assert bad.status_code == 400
    assert submit(client, model="custom", profile_json="{nope").status_code == 400


def test_custom_profile_rejects_private_hosts_on_public_site(client, tmp_path, monkeypatch):
    for url in ("http://127.0.0.1:11434/v1", "http://localhost:8000/v1", "http://10.0.0.5/v1",
                "http://169.254.169.254/v1", "ftp://x.example/v1"):
        cfg = {"key": "m", "model": "m", "base_url": url, "context_window": 10, "max_output_tokens": 5}
        r = submit(client, model="custom", profile_json=json.dumps(cfg))
        assert r.status_code == 400, url
    monkeypatch.setattr(jobs, "pipeline_run", fake_run)
    with TestClient(create_app(data_dir=tmp_path / "local", models=["deepseek"], allow_private=True)) as c:
        cfg = {"key": "m", "model": "m", "base_url": "http://localhost:11434/v1",
               "context_window": 10, "max_output_tokens": 5}
        assert submit(c, model="custom", profile_json=json.dumps(cfg), api_key="").status_code == 303


def test_full_queue_answers_busy(tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_run(config, client=None, run_dir=None, doc=None, progress=None):
        gate.wait(5)
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", slow_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"], max_queue=2)) as c:
        assert submit(c).status_code == 303
        assert submit(c).status_code == 303
        r = submit(c)
        assert r.status_code == 503 and "queue is full" in r.text
        gate.set()


def test_failed_run_reports_message(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError(f"provider said no to {KEY}")
    monkeypatch.setattr(jobs, "pipeline_run", boom)
    job_id = submit(client).headers["location"].rsplit("/", 1)[1]
    status = wait_done(client, job_id)
    assert status["status"] == "failed"
    assert KEY not in status["error"]
    assert client.get(f"/jobs/{job_id}/download/xlsx").status_code == 404


def test_purge_keeps_recent_jobs(tmp_path):
    store = jobs.JobStore(tmp_path)
    old = store.create(PDF, "openvas", "deepseek", None, None)
    new = store.create(PDF, "openvas", "deepseek", None, None)
    for job, hours in ((old, 25), (new, 1)):
        job.status = "done"
        job.finished_at = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        store.save(job)
    assert store.purge_older_than(24) == 1
    assert store.get(old.id) is None and not store.job_dir(old.id).exists()
    assert store.get(new.id) is not None


def test_restart_fails_unfinished_jobs(tmp_path):
    store = jobs.JobStore(tmp_path)
    job = store.create(PDF, "openvas", "deepseek", None, None)
    store2 = jobs.JobStore(tmp_path)
    store2.load()
    assert store2.get(job.id).status == "failed"
    assert "restarted" in store2.get(job.id).error


def test_jobs_run_one_at_a_time(tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_run(config, client=None, run_dir=None, doc=None, progress=None):
        gate.wait(5)
        return fake_run(config, client, run_dir, doc, progress)
    monkeypatch.setattr(jobs, "pipeline_run", slow_run)
    with TestClient(create_app(data_dir=tmp_path, models=["deepseek"])) as c:
        first = submit(c).headers["location"].rsplit("/", 1)[1]
        second = submit(c).headers["location"].rsplit("/", 1)[1]
        time.sleep(0.2)
        assert c.get(f"/api/jobs/{first}").json()["status"] == "running"
        s2 = c.get(f"/api/jobs/{second}").json()
        assert s2["status"] == "queued" and s2["queue_position"] == 0
        gate.set()
        assert wait_done(c, second)["status"] == "done"
