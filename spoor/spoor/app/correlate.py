"""Turn findings into incidents: link findings that belong to one attacker campaign, order them on the kill chain,
and score the result with an explicit, explainable formula."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from . import config as C
from .context import is_internal

EARLY = {"Reconnaissance", "Credential Access"}
MID = {"Initial Access", "Privilege Escalation", "Persistence"}


class UF:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _secs(a, b):
    return (b - a).total_seconds()


def build_links(active):
    """Return a list of {a, b, rule, reason}. Each rule is a documented, testable heuristic."""
    links = []

    def link(a, b, rule, reason):
        if a.id != b.id:
            links.append({"a": a.id, "b": b.id, "rule": rule, "reason": reason})

    by_ip = defaultdict(list)
    by_ua = defaultdict(list)
    for f in active:
        if f.ips:
            by_ip[f.ips[0]].append(f)
        if f.ua:
            by_ua[f.ua].append(f)

    # R1 same source IP
    for ip, fs in by_ip.items():
        for x in fs[1:]:
            link(fs[0], x, "same_ip", f"same source IP {ip}")
    # R2 same attacker toolkit fingerprint
    for ua, fs in by_ua.items():
        if len({f.ips[0] for f in fs if f.ips}) > 1:
            for x in fs[1:]:
                link(fs[0], x, "same_toolkit", f"same scanner fingerprint '{ua}' from different IPs")

    ordered = sorted(active, key=lambda f: f.start)
    # R3 IP rotation / handoff: B starts attacking the same host right after A goes quiet
    for a in ordered:
        for b in ordered:
            if a is b or not a.ips or not b.ips or a.ips[0] == b.ips[0]:
                continue
            if is_internal(a.ips[0]) or is_internal(b.ips[0]):
                continue
            if a.stage in EARLY and b.stage in EARLY and a.host == b.host:
                gap = _secs(a.end, b.start)
                if 0 <= gap <= C.HANDOFF_SEC:
                    link(a, b, "ip_rotation", f"{b.ips[0]} began {int(gap)}s after {a.ips[0]} went quiet on {a.host} (IP rotation)")
    # R4 credential reuse: failures on user U from IP1, then U logs in from IP2
    logins = [f for f in active if f.detector in ("login_after_failures", "credential_handoff", "login_new_account", "offhours_login")]
    guessers = [f for f in active if f.detector == "ssh_bruteforce"]
    for lg in logins:
        for g in guessers:
            u = lg.users[0] if lg.users else None
            if u in g.users and g.ips[0] != lg.session_ip and 0 <= _secs(g.end, lg.start) <= 7200:
                link(g, lg, "credential_reuse", f"'{u}' was being guessed from {g.ips[0]} before {lg.session_ip} logged in as it")
    # R5 compromised credentials re-used from a second new IP shortly afterwards
    logins.sort(key=lambda f: f.start)
    for i, a in enumerate(logins):
        for b in logins[i + 1:]:
            if a.users and b.users and a.users[0] == b.users[0] and a.session_ip != b.session_ip \
                    and 0 <= _secs(a.start, b.start) <= 6 * 3600 and not is_internal(b.session_ip):
                link(a, b, "credential_reuse", f"'{b.users[0]}' re-used from second new IP {b.session_ip}")
    # R6 login to an account that the incident itself created
    for lg in active:
        if lg.detector == "login_new_account":
            for mk in active:
                if mk.meta.get("new_account") == lg.users[0] and mk.stage == "Persistence" and mk.start <= lg.start:
                    link(mk, lg, "created_account", f"'{lg.users[0]}' was created during the incident, then used to log in")
    # R7 post-compromise commands belong to the login that opened the session
    for f in active:
        if f.detector.startswith("sudo_") or f.detector == "useradd":
            cands = [x for x in active if x.detector in ("login_after_failures", "credential_handoff", "offhours_login", "login_new_account")
                     and x.users and f.users and x.users[0] == f.users[0] and x.start <= f.start
                     and _secs(x.start, f.start) <= 12 * 3600 and (f.session_ip is None or x.session_ip == f.session_ip)]
            if cands:
                link(max(cands, key=lambda x: x.start), f, "session", f"command ran inside the session opened from {cands[-1].session_ip}")
    # R8 exfiltration follows a compromise on the same host
    for f in active:
        if f.stage == "Exfiltration":
            prev = [x for x in active if x.stage in MID and x.host == f.host and 0 <= _secs(x.end, f.start) <= 12 * 3600]
            if prev:
                p = max(prev, key=lambda x: x.end)
                link(p, f, "exfil_after_access", f"data left {f.host} {int(_secs(p.end, f.start) // 60)} min after the compromise")
    return links


def stage_order_score(findings):
    first = {}
    for f in findings:
        if f.stage not in first or f.start < first[f.stage]:
            first[f.stage] = f.start
    present = [s for s in C.STAGES if s in first]
    if len(present) < 2:
        return 1.0, present
    ok = sum(1 for a, b in zip(present, present[1:]) if _secs(first[a], first[b]) >= -C.ORDER_TOLERANCE_SEC)
    return ok / (len(present) - 1), present


def score_incident(findings, order, stages):
    """Transparent formula: noisy-OR of finding confidences + kill-chain bonuses, each listed for the UI."""
    parts = []
    miss = 1.0
    for f in sorted(findings, key=lambda x: -x.adjusted)[:8]:
        miss *= 1 - f.adjusted * 0.9
        parts.append({"label": f.title[:70], "value": round(f.adjusted, 2), "kind": "finding"})
    base = 1 - miss
    bonus = 0.0
    if len(stages) >= 2:
        b = min(0.12, 0.03 * (len(stages) - 1))
        bonus += b
        parts.append({"label": f"attack spans {len(stages)} of {len(C.STAGES)} kill-chain stages", "value": round(b, 2), "kind": "bonus"})
    if order >= 0.8 and len(stages) >= 3:
        bonus += 0.03
        parts.append({"label": "stages occur in kill-chain order", "value": 0.03, "kind": "bonus"})
    return min(0.99, base + bonus), parts


def severity(score):
    return "critical" if score >= 0.9 else "high" if score >= 0.75 else "medium" if score >= 0.55 else "low"


def correlate(findings):
    active = [f for f in findings if f.adjusted >= C.SUPPRESS_BELOW]
    suppressed = [f for f in findings if f.adjusted < C.SUPPRESS_BELOW]
    links = build_links(active)
    uf = UF([f.id for f in active])
    for l in links:
        uf.union(l["a"], l["b"])
    groups = defaultdict(list)
    for f in active:
        groups[uf.find(f.id)].append(f)
    by_id = {f.id: f for f in active}

    incidents, alerts = [], []
    for g in groups.values():
        g.sort(key=lambda f: f.start)
        stages = {f.stage for f in g}
        if len(stages) >= C.INCIDENT_MIN_STAGES or max(f.adjusted for f in g) >= C.INCIDENT_SOLO_CONF:
            order, present = stage_order_score(g)
            score, parts = score_incident(g, order, stages)
            ids = {f.id for f in g}
            incidents.append({
                "findings": g, "stages": present, "order": order, "score": score, "parts": parts,
                "links": [l for l in links if l["a"] in ids and l["b"] in ids],
            })
        else:
            alerts.extend(g)
    incidents.sort(key=lambda i: (-i["score"], i["findings"][0].start))
    for n, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{n:02d}"
        inc["severity"] = severity(inc["score"])
    alerts.sort(key=lambda f: -f.adjusted)
    return incidents, alerts, suppressed
