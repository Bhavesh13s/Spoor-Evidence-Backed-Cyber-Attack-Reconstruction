from datetime import datetime, timedelta, timezone
from app.context import Context
from app.detectors import run_all
from app.models import Event
from app import correlate

T0 = datetime(2026, 10, 4, 2, 0, tzinfo=timezone.utc)


def ev(i, off, kind, **kw):
    kw.setdefault("host", "web01")
    return Event(id=i, ts=T0 + timedelta(seconds=off), source="auth", kind=kind, file="t", line=i, raw="", **kw)


def fails(n, ip="45.1.1.1", users=("root",), start=0, step=2, base=0):
    return [ev(base + i, start + i * step, "login_fail", ip=ip, user=users[i % len(users)]) for i in range(n)]


def names(evs):
    f, _ = run_all(Context(sorted(evs, key=lambda e: e.ts)))
    return f


def test_bruteforce_threshold_boundary():
    assert not any(f.detector == "ssh_bruteforce" for f in names(fails(7)))
    assert any(f.detector == "ssh_bruteforce" for f in names(fails(8)))


def test_spray_vs_single_account_technique():
    f = [x for x in names(fails(12, users=("a", "b", "c", "d", "e", "f"))) if x.detector == "ssh_bruteforce"][0]
    assert f.technique == "T1110.003"
    f = [x for x in names(fails(12)) if x.detector == "ssh_bruteforce"][0]
    assert f.technique == "T1110.001"


def test_slow_attempts_split_into_separate_bursts():
    evs = fails(5, step=2) + fails(5, start=3600, step=2, base=100)
    assert not any(f.detector == "ssh_bruteforce" for f in names(evs))


def test_internal_source_is_downgraded():
    f = [x for x in names(fails(12, ip="10.0.0.9")) if x.detector == "ssh_bruteforce"][0]
    assert f.adjusted < 0.5 and f.benign


def test_success_after_failures_flagged_but_known_ip_suppressed():
    hist = [ev(1000 + i, -86400 * (i + 1), "login_ok", ip="9.9.9.9", user="priya") for i in range(5)]
    evs = hist + fails(6, ip="9.9.9.9", users=("priya",), start=-60) + [ev(500, 20, "login_ok", ip="9.9.9.9", user="priya")]
    f = [x for x in names(evs) if x.detector == "login_after_failures"][0]
    assert f.adjusted < 0.35, "mistyped password from a known IP must not alert"
    new = fails(30, ip="7.7.7.7", users=("priya",), start=-120) + [ev(501, 20, "login_ok", ip="7.7.7.7", user="priya")]
    f = [x for x in names(hist + new) if x.detector == "login_after_failures"][0]
    assert f.adjusted > 0.8


def test_offhours_known_ip_oncall_suppressed():
    t = datetime(2026, 10, 4, 3, 0, tzinfo=timezone.utc)
    hist = [Event(id=i, ts=t - timedelta(days=d, hours=h), source="auth", kind="login_ok", file="t", line=i, raw="",
                  host="web01", ip="9.9.9.9", user="ravi") for i, (d, h) in enumerate([(1, 0), (2, 0), (3, -8), (4, -8), (5, -9)])]
    now = Event(id=99, ts=t, source="auth", kind="login_ok", file="t", line=99, raw="", host="web01", ip="9.9.9.9", user="ravi")
    f = [x for x in names(hist + [now]) if x.detector == "offhours_login"]
    assert f and f[0].adjusted < 0.35


def test_cold_start_does_not_flag_first_logins():
    e = ev(1, 0, "login_ok", ip="5.5.5.5", user="newbie")
    assert not [x for x in names([e]) if x.detector == "offhours_login"]


def test_scanner_ua_and_allowlist():
    def web(n, ip, ua):
        return [Event(id=i, ts=T0 + timedelta(seconds=i), source="web", kind="http", file="t", line=i, raw="", host="web01",
                      ip=ip, path="/x%d" % i, status=404, ua=ua) for i in range(n)]
    ext = [f for f in names(web(8, "45.2.2.2", "Nikto/2.5")) if f.detector == "web_recon"]
    assert ext and ext[0].adjusted >= 0.6
    internal = [f for f in names(web(60, "10.0.9.9", "Nessus SOAP")) if f.detector == "web_recon"]
    assert internal and internal[0].adjusted < 0.35


def test_googlebot_style_200s_not_flagged():
    evs = [Event(id=i, ts=T0 + timedelta(seconds=i), source="web", kind="http", file="t", line=i, raw="", host="web01",
                 ip="66.249.1.1", path="/p?id=%d" % i, status=200, ua="Googlebot/2.1") for i in range(80)]
    assert not [f for f in names(evs) if f.detector == "web_recon"]


def test_sudo_shadow_read_flagged_and_routine_ignored():
    evs = [ev(1, 0, "sudo", user="x", target_user="root", cmd="/bin/cat /etc/shadow"),
           ev(2, 5, "sudo", user="x", target_user="root", cmd="/bin/systemctl restart nginx")]
    f = [x for x in names(evs) if x.detector.startswith("sudo_")]
    assert len(f) == 1 and f[0].technique == "T1003.008"


def test_exfil_internal_recurring_suppressed_external_flagged():
    def flow(i, off, dst, mb):
        return Event(id=i, ts=T0 + timedelta(seconds=off), source="net", kind="flow", file="t", line=i, raw="", host="web01",
                     ip="10.0.1.10", dst_ip=dst, dst_port=443, bytes_out=mb * 1024 * 1024)
    evs = [flow(i, -86400 * d + 60 * i, "10.0.5.20", 100) for d in (0, 1, 2) for i in range(6)]
    f = [x for x in names(evs) if x.detector == "exfil_volume"]
    assert f and all(x.adjusted < 0.35 for x in f)
    evs = [flow(100 + i, 60 * i, "8.8.4.4", 150) for i in range(4)]
    f = [x for x in names(evs) if x.detector == "exfil_volume"]
    assert f and f[0].adjusted >= 0.75


def test_small_transfers_ignored():
    evs = [Event(id=i, ts=T0 + timedelta(seconds=i), source="net", kind="flow", file="t", line=i, raw="", host="web01",
                 ip="10.0.1.10", dst_ip="8.8.8.8", bytes_out=1000) for i in range(100)]
    assert not [f for f in names(evs) if f.detector == "exfil_volume"]


def test_single_stage_noise_is_alert_not_incident():
    inc, alerts, sup = correlate.correlate(names(fails(12)))
    assert not inc and alerts
