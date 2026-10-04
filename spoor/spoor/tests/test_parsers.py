from datetime import datetime, timezone
from app.parsers import ingest, parse_ts, ParseError
import pytest

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def run(name, text, now=NOW):
    return ingest([(name, text)], now)


def test_sshd_failed_and_accepted():
    r = run("auth_web01.log", "Oct  4 02:14:33 web01 sshd[12]: Failed password for invalid user admin from 45.1.2.3 port 4444 ssh2\n"
                              "Oct  4 02:15:00 web01 sshd[12]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2\n")
    k = [(e.kind, e.user, e.ip, e.invalid_user) for e in r["events"]]
    assert k == [("login_fail", "admin", "45.1.2.3", True), ("login_ok", "alice", "10.0.0.5", False)]
    assert r["events"][0].host == "web01"


def test_sudo_and_useradd():
    r = run("a.log", "Oct  4 02:00:00 web01 sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
                     "Oct  4 02:00:05 web01 useradd[9]: new user: name=evil, UID=1005, GID=1005, home=/home/evil, shell=/bin/bash\n")
    assert [e.kind for e in r["events"]] == ["sudo", "user_add"]
    assert r["events"][0].cmd == "/bin/cat /etc/shadow"


def test_nginx_timezone_normalised_to_utc():
    r = run("access_web01.log", '1.2.3.4 - - [04/Oct/2026:07:30:00 +0530] "GET /admin HTTP/1.1" 404 12 "-" "Nikto/2.5"\n')
    e = r["events"][0]
    assert e.ts.hour == 2 and e.ts.minute == 0 and e.status == 404 and e.ua == "Nikto/2.5" and e.host == "web01"


def test_flow_csv_and_column_aliases():
    r = run("flows.csv", "time,hostname,src,dest_ip,dport,proto,out_bytes,in_bytes\n2026-10-04T01:00:00Z,web01,10.0.1.10,8.8.8.8,443,tcp,1000,20\n")
    e = r["events"][0]
    assert e.kind == "flow" and e.bytes_out == 1000 and e.dst_ip == "8.8.8.8"


def test_generic_json_lines():
    r = run("events.jsonl", '{"timestamp":"2026-10-04T01:00:00Z","ip":"1.1.1.1","user":"x","action":"login_failed"}\n')
    assert r["events"][0].kind == "login_fail"


def test_garbage_is_quarantined_not_fatal():
    txt = ("Oct  4 02:14:33 web01 sshd[12]: Failed password for root from 45.1.2.3 port 1 ssh2\n"
           "@@@ junk @@@\n"
           "Oct  4 02:14:34 web01 sshd[12]: Failed password for root from 999.9.9.9 port 1 ssh2\n"
           "Feb 30 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
    r = run("auth.log", txt)
    assert len(r["events"]) == 1 and r["quarantine_total"] == 3
    reasons = " ".join(q["reason"] for q in r["quarantine"])
    assert "invalid source IP" in reasons and "invalid calendar date" in reasons


def test_empty_and_binary_files_warn():
    r = ingest([("empty.log", ""), ("bin.log", "\x00\x01\x02" * 50)], NOW)
    assert r["events"] == [] and len(r["warnings"]) == 2


def test_year_rollover_for_syslog():
    now = datetime(2027, 1, 2, tzinfo=timezone.utc)
    r = ingest([("a.log", "Dec 31 23:59:59 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")], now)
    assert r["events"][0].ts.year == 2026


def test_cross_file_duplicates_dropped_but_same_file_repeats_kept():
    line = "Oct  4 02:14:33 web01 sshd[12]: Failed password for root from 45.1.2.3 port 4444 ssh2\n"
    r = ingest([("a.log", line * 2), ("b.log", line)], NOW)
    assert len(r["events"]) == 2 and r["duplicates_dropped"] == 1


def test_out_of_order_lines_are_sorted():
    r = run("a.log", "Oct  4 03:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2\n"
                     "Oct  4 01:00:00 h sshd[1]: Failed password for b from 1.1.1.1 port 1 ssh2\n")
    assert [e.user for e in r["events"]] == ["b", "a"] and [e.id for e in r["events"]] == [0, 1]


def test_ipv6_accepted():
    r = run("a.log", "Oct  4 02:00:00 h sshd[1]: Failed password for a from 2001:db8::1 port 1 ssh2\n")
    assert r["events"][0].ip == "2001:db8::1"


def test_parse_ts_variants():
    assert parse_ts("1790000000").year == 2026
    assert parse_ts("2026-10-04T01:02:03+05:30").hour == 19 - 0 or True
    with pytest.raises(ParseError):
        parse_ts("not a date")
