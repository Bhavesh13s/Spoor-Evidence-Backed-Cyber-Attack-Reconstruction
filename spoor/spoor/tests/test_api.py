import warnings
warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient
from app.main import app

c = TestClient(app)


def h(sid):
    return {"X-Session": sid}


def test_full_flow():
    r = c.post("/api/generate", json={"seed": 4})
    assert r.status_code == 200
    sid = r.json()["sid"]
    rep = c.post("/api/analyze", headers=h(sid)).json()
    assert rep["stats"]["incidents"] == 1
    ev = c.get("/api/evaluate", headers=h(sid)).json()
    assert ev["merged_into_single_campaign"]
    ids = rep["incidents"][0]["steps"][-1]["event_ids"][:3]
    rows = c.get("/api/events", params={"ids": ",".join(map(str, ids))}, headers=h(sid)).json()
    assert len(rows) == len(ids) and "raw" in rows[0]
    assert c.get("/api/report.json", headers=h(sid)).status_code == 200
    assert c.get("/api/download/logs", headers=h(sid)).headers["content-type"] == "application/zip"


def test_analyze_without_data_is_clear_404():
    r = c.post("/api/analyze")
    assert r.status_code == 404 and "Generate" in r.json()["detail"]


def test_upload_garbage_gives_helpful_422():
    r = c.post("/api/upload", files=[("files", ("x.log", b"hello world\nnothing useful\n"))])
    assert r.status_code == 422 and "No usable events" in r.json()["detail"]


def test_upload_real_syslog_and_analyze():
    log = b"".join(b"Oct  4 02:00:%02d web01 sshd[1]: Failed password for root from 45.1.1.1 port 22 ssh2\n" % i for i in range(30))
    r = c.post("/api/upload", files=[("files", ("auth.log", log))])
    assert r.status_code == 200
    rep = c.post("/api/analyze", headers=h(r.json()["sid"])).json()
    assert rep["stats"]["alerts"] + rep["stats"]["incidents"] >= 1


def test_evaluate_requires_synthetic_data():
    log = b"Oct  4 02:00:00 web01 sshd[1]: Failed password for root from 45.1.1.1 port 22 ssh2\n"
    sid = c.post("/api/upload", files=[("files", ("auth.log", log))]).json()["sid"]
    c.post("/api/analyze", headers=h(sid))
    assert c.get("/api/evaluate", headers=h(sid)).status_code == 409


def test_validation_errors():
    assert c.post("/api/generate", json={"seed": -5}).status_code == 422
    assert c.post("/api/generate", json={"scale": 99}).status_code == 422
    assert c.get("/api/events", params={"ids": "a,b"}, headers=h("nope")).status_code == 404
