"""Detectors. Each returns Findings with evidence event ids, a base confidence, positive signals,
the benign explanations that apply (with deductions) and the benign explanations that were checked and ruled out."""
from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict

from . import config as C
from .context import Context, is_internal, is_offhours
from .models import Finding


def _fmt_t(ts):
    return ts.strftime("%H:%M:%S")


def _bursts(evs, gap):
    cur = []
    for e in evs:
        if cur and (e.ts - cur[-1].ts).total_seconds() > gap:
            yield cur
            cur = []
        cur.append(e)
    if cur:
        yield cur


def _mc(values, default=""):
    c = Counter(v for v in values if v)
    return c.most_common(1)[0][0] if c else default


def _ip_benign(f: Finding, ip, weight=0.3):
    if ip in C.KNOWN_SCANNERS:
        f.benign.append((f"{ip} is an allow-listed vulnerability scanner", 0.6))
    if is_internal(ip):
        f.benign.append((f"{ip} is an internal (RFC1918) address", weight))
    else:
        f.checks.append(f"{ip} is an external address (not internal, not an allow-listed scanner)")


# ----------------------------------------------------------------------------- SSH brute force / spray
def d_bruteforce(ctx: Context):
    out = []
    for ip, evs in ctx.fails.items():
        for b in _bursts(evs, C.BRUTE_GAP_SEC):
            n = len(b)
            if n < C.BRUTE_MIN_FAILS:
                continue
            users = Counter(e.user for e in b)
            spray = len(users) >= C.SPRAY_MIN_USERS
            invalid = sum(1 for e in b if e.invalid_user)
            host = _mc(e.host for e in b)
            dur = max(1, int((b[-1].ts - b[0].ts).total_seconds()))
            top = ", ".join(u for u, _ in users.most_common(4))
            f = Finding(
                id="", detector="ssh_bruteforce", stage="Credential Access",
                technique="T1110.003" if spray else "T1110.001",
                title=(f"Password spraying / account enumeration from {ip}" if spray
                       else f"SSH password guessing against '{b[0].user}' from {ip}"),
                detail=(f"{n} failed SSH logins from {ip} in {dur}s against {len(users)} account(s) "
                        f"({top}) on {host}; {round(100 * invalid / n)}% targeted accounts that do not exist."),
                start=b[0].ts, end=b[-1].ts, host=host, event_ids=[e.id for e in b],
                confidence=min(0.8, 0.45 + 0.17 * math.log10(n)), ips=[ip], users=list(users),
                meta={"fails": n, "accounts": len(users), "rate_per_min": round(n * 60 / dur, 1)},
            )
            _ip_benign(f, ip, 0.25)
            out.append(f)
    return out


# ----------------------------------------------------------------------------- web recon / scanning
def d_web_recon(ctx: Context):
    out = []
    for ip, evs in ctx.web.items():
        for b in _bursts(evs, C.WEB_BURST_GAP_SEC):
            n = len(b)
            c4 = sum(1 for e in b if 400 <= e.status < 500)
            sens = sum(1 for e in b if C.SENSITIVE_PATH.search(e.path))
            scan_ua = [e.ua for e in b if C.SCANNER_UA.search(e.ua or "")]
            volume = n >= C.WEB_MIN_REQS and c4 / n >= C.WEB_MIN_4XX_RATIO
            scanner = len(scan_ua) >= C.SCANNER_MIN_REQS
            sensitive = sens >= C.SENSITIVE_HITS
            if not (volume or scanner or sensitive):
                continue
            ua = _mc(scan_ua) or _mc(e.ua for e in b)
            paths = len({e.path.split("?")[0] for e in b})
            host = _mc(e.host for e in b)
            dur = max(1, int((b[-1].ts - b[0].ts).total_seconds()))
            conf = 0.7 if scanner else 0.6
            if sensitive:
                conf += 0.1
            f = Finding(
                id="", detector="web_recon", stage="Reconnaissance",
                technique="T1595.002" if scanner else "T1595.003",
                title=f"Web scanning from {ip}" + (f" ({ua.split('/')[0]})" if scanner else ""),
                detail=(f"{n} HTTP requests from {ip} in {dur}s probing {paths} distinct paths on {host}; "
                        f"{round(100 * c4 / n)}% returned 4xx, {sens} touched sensitive paths"
                        + (f", user-agent '{ua}'." if scanner else ".")),
                start=b[0].ts, end=b[-1].ts, host=host, event_ids=[e.id for e in b], confidence=min(conf, 0.85),
                ips=[ip], ua=ua if scanner else "", meta={"requests": n, "paths": paths, "ratio_4xx": round(c4 / n, 2)},
            )
            if not scanner:
                f.checks.append("traffic is not a known search-engine crawler pattern (mostly 4xx, not 200s)")
            _ip_benign(f, ip, 0.3)
            out.append(f)
    return out


# ----------------------------------------------------------------------------- web exploit payloads
def d_web_exploit(ctx: Context):
    out = []
    for ip, evs in ctx.web.items():
        hits = [e for e in evs if C.PAYLOAD.search(e.path)]
        for b in _bursts(hits, 600):
            host = _mc(e.host for e in b)
            kind = "SQL injection" if any(re.search(r"union|or(\s|\+|%20)+1|'--|sleep|information_schema", e.path, re.I)
                                          for e in b) else "injection / traversal"
            f = Finding(
                id="", detector="web_exploit", stage="Initial Access", technique="T1190",
                title=f"{kind[0].upper() + kind[1:]} payloads from {ip}",
                detail=f"{len(b)} request(s) from {ip} carried {kind} payloads against {host}, e.g. {b[0].method} {b[0].path[:90]}.",
                start=b[0].ts, end=b[-1].ts, host=host, event_ids=[e.id for e in b],
                confidence=0.65 + (0.1 if len(b) >= 3 else 0), ips=[ip], meta={"payload_requests": len(b)},
            )
            _ip_benign(f, ip, 0.3)
            out.append(f)
    return out


# ----------------------------------------------------------------------------- suspicious logins
def d_logins(ctx: Context):
    out = []
    for e in ctx.events:
        if e.kind != "login_ok" or not (e.ip and e.user):
            continue
        prior = ctx.prior_logins(e.user, e.ts)
        known = ctx.known_ip_logins(e.user, e.ip, e.ts)
        same_ip_fails = ctx.recent_fails(e.ip, e.ts)
        user_fails = [x for x in ctx.recent_fails_for_user(e.user, e.ts) if x.ip != e.ip]
        off = is_offhours(e.ts)
        created = ctx.created.get(e.user)
        new_account = created is not None and created[0] <= e.ts and (e.ts - created[0]).total_seconds() < 48 * 3600 \
            and not prior
        method = e.auth_method or "password"
        base = dict(host=e.host, users=[e.user], ips=[e.ip], session_ip=e.ip, start=e.ts, end=e.ts)

        if len(same_ip_fails) >= C.FAILS_BEFORE_SUCCESS:
            n = len(same_ip_fails)
            f = Finding(
                id="", detector="login_after_failures", stage="Initial Access", technique="T1078",
                title=f"'{e.user}' logged in from {e.ip} after {n} failed attempts",
                detail=(f"{e.ip} failed {n} times, then {_fmt_t(e.ts)} succeeded as '{e.user}' ({method}) on {e.host}. "
                        f"A password that was guessed is the most likely explanation."),
                event_ids=[x.id for x in same_ip_fails] + [e.id], confidence=0.85,
                meta={"fails_before": n, "login_ip": e.ip}, **base)
            if known >= C.KNOWN_IP_LOGINS:
                f.benign.append((f"{e.ip} has {known} earlier successful logins for '{e.user}'", 0.5))
            else:
                f.checks.append(f"{e.ip} was never seen for '{e.user}' before ({known} prior logins)")
            if not off:
                if len(prior) >= C.BASELINE_MIN_LOGINS and known:
                    f.benign.append(("login happened in normal working hours", 0.15))
            else:
                f.positive.append("login happened off-hours")
            if n < 10:
                f.benign.append((f"only {n} failures - consistent with a mistyped password", 0.1))
            out.append(f)
            continue

        if len(user_fails) >= C.FAILS_BEFORE_SUCCESS and known == 0:
            src = Counter(x.ip for x in user_fails).most_common(1)[0][0]
            f = Finding(
                id="", detector="credential_handoff", stage="Initial Access", technique="T1078",
                title=f"'{e.user}' logged in from new IP {e.ip} while {src} was guessing its password",
                detail=(f"{len(user_fails)} failures against '{e.user}' came from {src}; shortly after, {e.ip} (never seen "
                        f"for this user) logged in successfully at {_fmt_t(e.ts)}."),
                event_ids=[x.id for x in user_fails] + [e.id], confidence=0.8,
                meta={"login_ip": e.ip, "guess_ip": src}, **base)
            out.append(f)
            continue

        if new_account:
            f = Finding(
                id="", detector="login_new_account", stage="Persistence", technique="T1078.003",
                title=f"First-ever login to account '{e.user}' created {int((e.ts - created[0]).total_seconds() // 60)} min earlier",
                detail=(f"Account '{e.user}' was created at {_fmt_t(created[0])} and logged in from {e.ip} at {_fmt_t(e.ts)} "
                        f"({method}). It has no earlier history."),
                event_ids=[e.id], confidence=0.75, meta={"new_account": e.user, "login_ip": e.ip}, **base)
            if not is_internal(e.ip):
                f.positive.append("login came from an external address")
            out.append(f)
            continue

        if off and len(prior) >= C.BASELINE_MIN_LOGINS:
            f = Finding(
                id="", detector="offhours_login", stage="Initial Access", technique="T1078",
                title=f"Off-hours login for '{e.user}' at {_fmt_t(e.ts)}",
                detail=f"'{e.user}' logged in from {e.ip} at {_fmt_t(e.ts)}, outside normal hours.",
                event_ids=[e.id], confidence=0.45, meta={"login_ip": e.ip}, **base)
            if known >= C.KNOWN_IP_LOGINS:
                f.benign.append((f"{e.ip} was used for {known} earlier logins by '{e.user}'", 0.3))
            else:
                f.positive.append(f"{e.ip} is a new address for this user")
            oh = ctx.prior_offhours_logins(e.user, e.ts)
            if oh >= 2:
                f.benign.append((f"'{e.user}' has logged in off-hours {oh} times before (on-call pattern)", 0.2))
            out.append(f)
    return out


# ----------------------------------------------------------------------------- post-compromise commands
SUDO_RULES = [
    ("cred_dump", re.compile(r"/etc/shadow|/etc/sudoers|id_rsa|\.aws/credentials"), "Privilege Escalation", "T1003.008",
     "read credential material"),
    ("setuid", re.compile(r"chmod\s+(u\+s|[ug]\+s|4[0-7]{3}|2[0-7]{3})\b"), "Privilege Escalation", "T1548.001",
     "set the setuid bit on a binary"),
    ("account", re.compile(r"\b(useradd|adduser)\b"), "Persistence", "T1136.001", "create a local account"),
    ("ssh_key", re.compile(r"authorized_keys"), "Persistence", "T1098.004", "modify SSH authorized keys"),
    ("download_exec", re.compile(r"(wget|curl)\b.*(\|\s*(sh|bash)|-o\s*/tmp)|\bnc\b.*\s-e\b|bash\s+-i"), "Privilege Escalation",
     "T1059", "download and execute code"),
]


def d_postcompromise(ctx: Context):
    out = []
    used_adds = set()
    for e in ctx.sudo:
        for name, rx, stage, tech, verb in SUDO_RULES:
            if not rx.search(e.cmd):
                continue
            session = ctx.last_login_before(e.user, e.ts)
            ids = [e.id]
            extra = ""
            if name == "account":
                near = [u for u in ctx.user_adds if u.host == e.host and abs((u.ts - e.ts).total_seconds()) <= 15]
                for u in near:
                    ids.append(u.id)
                    used_adds.add(u.id)
                    extra = f" Account '{u.user}' now exists."
            f = Finding(
                id="", detector=f"sudo_{name}", stage=stage, technique=tech,
                title=f"'{e.user}' used sudo to {verb}",
                detail=f"At {_fmt_t(e.ts)} '{e.user}' ran `{e.cmd[:110]}` as {e.target_user} on {e.host}.{extra}",
                start=e.ts, end=e.ts, host=e.host, event_ids=ids, confidence=0.6, users=[e.user],
                session_ip=session[1] if session else None,
                meta={"cmd": e.cmd[:160], "rule": name})
            if name == "account":
                m = re.search(r"([A-Za-z_][\w\-]*)\s*$", e.cmd)
                f.meta["new_account"] = next((u.user for u in ctx.user_adds if u.id in ids and u.kind == "user_add"),
                                             m.group(1) if m else "")
            if session:
                s_ts, s_ip = session
                k = ctx.known_ip_logins(e.user, s_ip, s_ts)
                if k >= C.KNOWN_IP_LOGINS and not is_offhours(s_ts):
                    f.benign.append((f"session came from {s_ip}, a known address for '{e.user}' in working hours", 0.35))
                elif not is_internal(s_ip):
                    f.positive.append(f"the session originated from external IP {s_ip}")
            out.append(f)
            break
    for u in ctx.user_adds:           # account creation logged without a matching sudo line
        if u.id in used_adds:
            continue
        out.append(Finding(
            id="", detector="useradd", stage="Persistence", technique="T1136.001",
            title=f"New local account '{u.user}' created", detail=f"At {_fmt_t(u.ts)} account '{u.user}' was created on {u.host}.",
            start=u.ts, end=u.ts, host=u.host, event_ids=[u.id], confidence=0.55, users=[u.user],
            meta={"new_account": u.user}))
    return out


# ----------------------------------------------------------------------------- exfiltration
def d_exfil(ctx: Context):
    out = []
    groups = defaultdict(list)
    for e in ctx.flows:
        if e.dst_ip and e.bytes_out > 0:
            groups[(e.host, e.ip, e.dst_ip)].append(e)
    hourly = list(ctx.hourly_out().values())
    mu = statistics.mean(hourly) if hourly else 0
    sd = statistics.pstdev(hourly) if len(hourly) > 1 else 0
    for (host, src, dst), evs in groups.items():
        windows, cur = [], []
        for e in evs:
            if cur and ((e.ts - cur[-1].ts).total_seconds() > C.EXFIL_WINDOW_GAP_SEC
                        or (e.ts - cur[0].ts).total_seconds() > C.EXFIL_WINDOW_MAX_SEC):
                windows.append(cur)
                cur = []
            cur.append(e)
        if cur:
            windows.append(cur)
        for w in windows:
            total = sum(e.bytes_out for e in w)
            if total < C.EXFIL_MIN_BYTES:
                continue
            gb = total / 1024 ** 3
            size = f"{gb:.2f} GB" if gb >= 1 else f"{total / 1024 ** 2:.0f} MB"
            earlier = [x for x in evs if x.ts < w[0].ts]
            f = Finding(
                id="", detector="exfil_volume", stage="Exfiltration", technique="T1041",
                title=f"{size} sent from {host} to {dst}",
                detail=(f"{host} ({src}) sent {size} to {dst}:{w[0].dst_port} in {len(w)} flows between "
                        f"{_fmt_t(w[0].ts)} and {_fmt_t(w[-1].ts)}."),
                start=w[0].ts, end=w[-1].ts, host=host, event_ids=[e.id for e in w], confidence=0.75,
                dst_ip=dst, meta={"bytes": total, "dst": dst, "port": w[0].dst_port, "flows": len(w)})
            hour_total = ctx.hourly_out().get((host, w[0].ts.replace(minute=0, second=0, microsecond=0)), total)
            if sd > 0:
                z = (hour_total - mu) / sd
                f.meta["zscore"] = round(z, 1)
                if z >= 4:
                    f.positive.append(f"hourly outbound volume is {z:.0f} standard deviations above this fleet's norm")
            if is_internal(dst):
                f.benign.append((f"{dst} is an internal address (bulk copy inside the network is not exfiltration)", 0.5))
            else:
                f.checks.append(f"{dst} is an external address")
                if not earlier:
                    f.positive.append(f"{host} has never sent data to {dst} before")
            same_hour_days = {x.ts.date() for x in earlier if abs(x.ts.hour - w[0].ts.hour) <= 1}
            if len(same_hour_days) >= 2:
                f.benign.append((f"same transfer pattern occurred on {len(same_hour_days)} earlier days at this hour (scheduled job)", 0.5))
            else:
                f.checks.append("no recurring schedule for this destination (not a nightly backup)")
            out.append(f)
    return out


DETECTORS = [d_bruteforce, d_web_recon, d_web_exploit, d_logins, d_postcompromise, d_exfil]


def run_all(ctx: Context):
    findings = []
    per_detector = {}
    for d in DETECTORS:
        got = d(ctx)
        per_detector[d.__name__[2:]] = len(got)
        findings.extend(got)
    findings.sort(key=lambda f: (f.start, f.detector))
    for i, f in enumerate(findings, 1):
        f.id = f"F{i:03d}"
    return findings, per_detector
