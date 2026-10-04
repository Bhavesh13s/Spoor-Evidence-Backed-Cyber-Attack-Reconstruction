"""Format-tolerant log ingestion.

Supports: syslog/auth.log (sshd, sudo, useradd), nginx/Apache combined access logs,
network-flow CSV, generic CSV (column mapping), and JSON lines.
Bad lines never crash the run: they go to a quarantine list with a reason.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import Event

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
FAIL_RE = re.compile(
    r"^Failed (?P<m>password|publickey|keyboard-interactive/pam) for (?P<inv>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
OK_RE = re.compile(r"^Accepted (?P<m>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<tgt>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")
USERADD_RE = re.compile(r"new user: name=(?P<name>[^,\s]+)")
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
HOST_FROM_NAME = re.compile(r"(?:^|[_\-.])([a-z]+[0-9]+)(?:[_\-.]|$)", re.I)

IGNORE = object()   # recognised line that carries no security signal


class ParseError(Exception):
    pass


def valid_ip(s: Optional[str]) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def to_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_ts(value) -> datetime:
    """ISO-8601, epoch seconds/millis, or nginx format -> aware UTC datetime."""
    if value is None:
        raise ParseError("missing timestamp")
    s = str(value).strip()
    if not s:
        raise ParseError("missing timestamp")
    if re.fullmatch(r"\d{9,13}(\.\d+)?", s):
        x = float(s)
        if x > 1e11:
            x /= 1000.0
        return datetime.fromtimestamp(x, tz=timezone.utc)
    try:
        return to_utc(datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        pass
    try:
        return to_utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except ValueError:
        raise ParseError(f"unrecognised timestamp '{s[:40]}'")


def syslog_ts(mon: str, day: str, hms: str, now: datetime) -> datetime:
    """Syslog has no year: assume the current one, roll back if that lands in the future."""
    if mon not in MONTHS:
        raise ParseError(f"bad month '{mon}'")
    h, m, s = (int(x) for x in hms.split(":"))
    for year in (now.year, now.year - 1):
        try:
            ts = datetime(year, MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc)
        except ValueError:
            raise ParseError("invalid calendar date")
        if ts <= now + timedelta(days=1):
            return ts
    raise ParseError("timestamp too far in the future")


class Ctx:
    def __init__(self, filename: str, now: datetime):
        self.filename = filename
        self.now = now
        m = HOST_FROM_NAME.search(filename.rsplit("/", 1)[-1])
        self.default_host = m.group(1).lower() if m else "unknown"
        self.header = None


def _mk(ctx: Ctx, lineno: int, raw: str, ts, source: str, kind: str, **kw) -> Event:
    return Event(id=-1, ts=ts, source=source, kind=kind, file=ctx.filename, line=lineno, raw=raw, **kw)


# --------------------------------------------------------------------------- syslog
def parse_syslog(line: str, lineno: int, ctx: Ctx):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    ts = syslog_ts(m["mon"], m["day"], m["time"], ctx.now)
    host, proc, msg = m["host"], m["proc"], m["msg"]
    if proc.startswith("sshd"):
        f = FAIL_RE.match(msg)
        if f:
            if not valid_ip(f["ip"]):
                raise ParseError(f"invalid source IP '{f['ip'][:40]}'")
            return _mk(ctx, lineno, line, ts, "auth", "login_fail", host=host, ip=f["ip"], user=f["user"],
                       invalid_user=bool(f["inv"]), auth_method=f["m"])
        o = OK_RE.match(msg)
        if o:
            if not valid_ip(o["ip"]):
                raise ParseError(f"invalid source IP '{o['ip'][:40]}'")
            return _mk(ctx, lineno, line, ts, "auth", "login_ok", host=host, ip=o["ip"], user=o["user"],
                       auth_method=o["m"])
        return IGNORE
    if proc == "sudo":
        s = SUDO_RE.match(msg)
        if s:
            return _mk(ctx, lineno, line, ts, "auth", "sudo", host=host, user=s["user"], target_user=s["tgt"],
                       cmd=s["cmd"].strip())
        return IGNORE
    if proc in ("useradd", "adduser"):
        u = USERADD_RE.search(msg)
        if u:
            return _mk(ctx, lineno, line, ts, "auth", "user_add", host=host, user=u["name"])
        return IGNORE
    return IGNORE


# --------------------------------------------------------------------------- nginx
def parse_nginx(line: str, lineno: int, ctx: Ctx):
    m = NGINX_RE.match(line)
    if not m:
        return None
    if not valid_ip(m["ip"]):
        raise ParseError(f"invalid client IP '{m['ip'][:40]}'")
    ts = parse_ts(m["ts"])
    parts = m["req"].split(" ")
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("", "")
    return _mk(ctx, lineno, line, ts, "web", "http", host=ctx.default_host, ip=m["ip"],
               user=None if m["user"] == "-" else m["user"], method=method, path=path,
               status=int(m["status"]), ua=m["ua"] or "",
               bytes_out=0 if m["bytes"] == "-" else int(m["bytes"]))


# --------------------------------------------------------------------------- csv / json
FLOW_COLS = {
    "ts": ("timestamp", "time", "ts", "start_time", "datetime"),
    "host": ("host", "sensor", "hostname"),
    "src": ("src_ip", "src", "source_ip", "source"),
    "dst": ("dst_ip", "dst", "dest_ip", "destination", "destination_ip"),
    "dport": ("dst_port", "dport", "dest_port", "destination_port"),
    "bout": ("bytes_out", "out_bytes", "bytes_sent", "orig_bytes", "bytes"),
    "bin": ("bytes_in", "in_bytes", "bytes_recv", "resp_bytes"),
}
GEN_COLS = {
    "ts": FLOW_COLS["ts"],
    "ip": ("ip", "src_ip", "source_ip", "client_ip", "remote_ip", "src"),
    "user": ("user", "username", "account", "uid"),
    "action": ("action", "event", "event_type", "outcome", "status", "result"),
    "host": FLOW_COLS["host"],
}


def _pick(row: dict, names):
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    return None


def _intval(x) -> int:
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return 0


def _from_mapping(row: dict, lineno: int, raw: str, ctx: Ctx, flow_hint: bool):
    row = {str(k).strip().lower(): v for k, v in row.items()}
    ts = parse_ts(_pick(row, FLOW_COLS["ts"]))
    dst = _pick(row, FLOW_COLS["dst"])
    bout = _pick(row, FLOW_COLS["bout"])
    if dst is not None and bout is not None:
        src = _pick(row, FLOW_COLS["src"])
        for label, v in (("source", src), ("destination", dst)):
            if v is not None and not valid_ip(v):
                raise ParseError(f"invalid {label} IP '{str(v)[:40]}'")
        return _mk(ctx, lineno, raw, ts, "net", "flow", host=str(_pick(row, FLOW_COLS["host"]) or ctx.default_host),
                   ip=src, dst_ip=dst, dst_port=_intval(_pick(row, FLOW_COLS["dport"])),
                   bytes_out=_intval(bout), bytes_in=_intval(_pick(row, FLOW_COLS["bin"])))
    ip = _pick(row, GEN_COLS["ip"])
    if ip is not None and not valid_ip(ip):
        raise ParseError(f"invalid IP '{str(ip)[:40]}'")
    action = str(_pick(row, GEN_COLS["action"]) or "").lower()
    if re.search(r"fail|denied|invalid|reject|error|bad", action):
        kind = "login_fail"
    elif re.search(r"success|accept|ok|granted|login", action):
        kind = "login_ok"
    else:
        raise ParseError("cannot map row to a known event type (need action/status or flow columns)")
    return _mk(ctx, lineno, raw, ts, "json" if raw.lstrip().startswith("{") else "csv", kind,
               host=str(_pick(row, GEN_COLS["host"]) or ctx.default_host), ip=ip,
               user=_pick(row, GEN_COLS["user"]))


def parse_csv(line: str, lineno: int, ctx: Ctx):
    if ctx.header is None:
        return None
    try:
        vals = next(csv.reader([line]))
    except csv.Error as e:
        raise ParseError(f"csv error: {e}")
    if len(vals) != len(ctx.header):
        raise ParseError(f"expected {len(ctx.header)} columns, found {len(vals)}")
    return _from_mapping(dict(zip(ctx.header, vals)), lineno, line, ctx, True)


def parse_jsonl(line: str, lineno: int, ctx: Ctx):
    if not line.lstrip().startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as e:
        raise ParseError(f"invalid JSON: {e.msg}")
    if not isinstance(obj, dict):
        raise ParseError("JSON line is not an object")
    return _from_mapping(obj, lineno, line, ctx, False)


# --------------------------------------------------------------------------- driver
def sniff(lines: list, ctx: Ctx) -> str:
    sample = [l for l in lines if l.strip()][:60]
    if not sample:
        return "empty"
    first = sample[0]
    if "," in first and not first.lstrip().startswith("{") and not SYSLOG_RE.match(first) and not NGINX_RE.match(first):
        cols = [c.strip().lower() for c in first.split(",")]
        known = {n for group in (FLOW_COLS, GEN_COLS) for names in group.values() for n in names}
        if sum(1 for c in cols if c in known) >= 2:
            ctx.header = cols
            return "csv"
    score = {
        "syslog": sum(1 for l in sample if SYSLOG_RE.match(l)),
        "nginx": sum(1 for l in sample if NGINX_RE.match(l)),
        "jsonl": sum(1 for l in sample if l.lstrip().startswith("{")),
    }
    best = max(score, key=score.get)
    return best if score[best] >= max(1, len(sample) * 0.3) else "unknown"


PARSERS = {"syslog": parse_syslog, "nginx": parse_nginx, "csv": parse_csv, "jsonl": parse_jsonl}
FORMAT_LABEL = {"syslog": "syslog / auth.log", "nginx": "nginx/Apache access log", "csv": "CSV (flow or generic)",
                "jsonl": "JSON lines", "empty": "empty", "unknown": "unrecognised"}

MAX_LINES_PER_FILE = 300_000
QUARANTINE_KEEP = 300


def ingest(files, now: Optional[datetime] = None) -> dict:
    """files: iterable of (filename, bytes|str). Returns events (sorted, ids assigned) + diagnostics."""
    now = now or datetime.now(timezone.utc)
    events, quarantine, file_stats, warnings = [], [], [], []
    quarantine_total = 0
    seen_raw: dict = {}
    dup_dropped = 0

    for name, data in files:
        text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else data
        st = {"name": name, "format": "unrecognised", "lines": 0, "parsed": 0, "ignored": 0, "quarantined": 0}
        if "\x00" in text[:2000]:
            warnings.append(f"{name}: looks like a binary file - skipped")
            st["quarantined"] = 1
            quarantine_total += 1
            quarantine.append({"file": name, "line": 0, "reason": "binary content", "raw": ""})
            file_stats.append(st)
            continue
        lines = text.splitlines()
        if len(lines) > MAX_LINES_PER_FILE:
            warnings.append(f"{name}: truncated to the first {MAX_LINES_PER_FILE:,} lines")
            lines = lines[:MAX_LINES_PER_FILE]
        ctx = Ctx(name, now)
        fmt = sniff(lines, ctx)
        st["format"] = FORMAT_LABEL.get(fmt, fmt)
        if fmt == "empty":
            warnings.append(f"{name}: file is empty")
        elif fmt == "unknown":
            warnings.append(f"{name}: format not recognised - lines quarantined (try syslog, nginx, CSV or JSONL)")
        order = [fmt] + [f for f in PARSERS if f != fmt] if fmt in PARSERS else list(PARSERS)
        file_seen_header = False
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            st["lines"] += 1
            if fmt == "csv" and not file_seen_header:
                file_seen_header = True
                continue                                    # header row
            result, reason = None, "unrecognised line format"
            for f in order:
                try:
                    r = PARSERS[f](line, i, ctx)
                except ParseError as e:
                    result, reason = None, str(e)
                    break
                except Exception as e:                      # defensive: one bad line must never kill the run
                    result, reason = None, f"unexpected parse failure ({type(e).__name__})"
                    break
                if r is not None:
                    result = r
                    break
            if result is IGNORE:
                st["ignored"] += 1
            elif result is None:
                st["quarantined"] += 1
                quarantine_total += 1
                if len(quarantine) < QUARANTINE_KEEP:
                    quarantine.append({"file": name, "line": i, "reason": reason, "raw": line[:240]})
            else:
                prev = seen_raw.get(line)
                if prev is not None and prev != name:       # same line in a different file = overlapping export
                    dup_dropped += 1
                    continue
                seen_raw[line] = name
                events.append(result)
                st["parsed"] += 1
        file_stats.append(st)

    events.sort(key=lambda e: (e.ts, e.file, e.line))
    for idx, e in enumerate(events):
        e.id = idx
    return {"events": events, "quarantine": quarantine, "quarantine_total": quarantine_total,
            "files": file_stats, "duplicates_dropped": dup_dropped, "warnings": warnings}
