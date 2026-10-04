"""ingest -> context -> detect -> correlate -> narrate -> report (plain JSON-serialisable dict)."""
from __future__ import annotations

import time
from collections import defaultdict

from . import config as C
from . import correlate as corr
from . import narrate
from .context import Context, is_internal
from .detectors import run_all
from .models import Finding


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def finding_dict(f: Finding, step=None):
    d = {
        "id": f.id, "detector": f.detector, "stage": f.stage, "technique": f.technique,
        "technique_name": C.TECHNIQUES.get(f.technique, ""), "title": f.title, "detail": f.detail,
        "start": _iso(f.start), "end": _iso(f.end), "host": f.host, "ips": f.ips, "users": f.users,
        "dst_ip": f.dst_ip, "confidence": round(f.adjusted, 2), "base_confidence": round(f.confidence, 2),
        "positive": f.positive, "benign": [{"reason": r, "deduction": d} for r, d in f.benign],
        "checks": f.checks, "evidence_count": len(f.event_ids), "event_ids": f.event_ids[:400],
    }
    if step is not None:
        d["step"] = step
    return d


def _graph(inc):
    nodes, edges = {}, {}

    def node(kind, key, step):
        nid = f"{kind}:{key}"
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": kind, "label": key, "step": step}
        return nid

    def edge(a, b, label, step, dashed=False):
        k = (a, b, label)
        if k not in edges:
            edges[k] = {"from": a, "to": b, "label": label, "step": step, "dashed": dashed}

    for i, f in enumerate(inc["findings"]):
        ip = f.ips[0] if f.ips else None
        if f.stage == "Exfiltration" and f.dst_ip:
            h = node("host", f.host, i)
            d = node("dst", f.dst_ip, i)
            edge(h, d, f"exfil {f.meta.get('bytes', 0) // (1024 * 1024)} MB", i)
            continue
        if ip:
            a = node("ip", ip, i)
            h = node("host", f.host, i)
            if f.detector.startswith("login") or f.detector in ("credential_handoff", "offhours_login"):
                u = node("user", f.users[0], i)
                edge(a, u, "logged in", i)
                edge(u, h, "session", i)
            else:
                edge(a, h, {"Reconnaissance": "scan", "Credential Access": "brute force"}.get(f.stage, "attack"), i)
        elif f.users:
            u = node("user", f.users[0], i)
            h = node("host", f.host, i)
            edge(u, h, f.title.split(" used sudo to ")[-1][:28] if "sudo" in f.title else "account created", i)
    fmap = {f.id: f for f in inc["findings"]}
    for l in inc["links"]:
        if l["rule"] in ("ip_rotation", "same_toolkit", "credential_reuse"):
            fa, fb = fmap[l["a"]], fmap[l["b"]]
            ia = fa.ips[0] if fa.ips else fa.session_ip
            ib = fb.ips[0] if fb.ips else fb.session_ip
            if ia and ib and ia != ib:
                edge(f"ip:{ia}", f"ip:{ib}", "same campaign", max(inc["findings"].index(fa), inc["findings"].index(fb)), True)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def incident_dict(inc):
    fs = inc["findings"]
    ips = list(dict.fromkeys(i for f in fs for i in ([f.ips[0]] if f.ips else []) + ([f.session_ip] if f.session_ip and not is_internal(f.session_ip) else [])))
    inc["ips"] = ips
    inc["hosts"] = list(dict.fromkeys(f.host for f in fs))
    inc["users"] = list(dict.fromkeys(u for f in fs for u in f.users))
    inc["rotation"] = any(l["rule"] in ("ip_rotation", "same_toolkit") for l in inc["links"]) or len(ips) > 1
    applied, ruled_out = narrate.benign_review(inc)
    all_ids = {i for f in fs for i in f.event_ids}
    title = narrate.headline(inc)
    return {
        "id": inc["id"], "severity": inc["severity"], "score": round(inc["score"] * 100), "title": title,
        "start": _iso(fs[0].start), "end": _iso(max(f.end for f in fs)),
        "duration_min": round((max(f.end for f in fs) - fs[0].start).total_seconds() / 60, 1),
        "ips": ips, "users": inc["users"], "hosts": inc["hosts"],
        "dst_ips": list(dict.fromkeys(f.dst_ip for f in fs if f.dst_ip)),
        "stages": inc["stages"], "all_stages": C.STAGES, "order_score": round(inc["order"], 2),
        "story": narrate.story(inc), "actions": narrate.actions(inc),
        "steps": [finding_dict(f, i) for i, f in enumerate(fs)],
        "links": [{"a": l["a"], "b": l["b"], "rule": l["rule"], "reason": l["reason"]} for l in inc["links"]],
        "link_summary": list(dict.fromkeys(l["reason"] for l in inc["links"] if l["rule"] not in ("same_ip", "session")))[:8],
        "score_breakdown": inc["parts"], "benign_applied": applied, "ruled_out": ruled_out,
        "graph": _graph(inc), "evidence_total": len(all_ids), "evidence_ids": sorted(all_ids),
    }


def _entities(incidents, alerts):
    ents = {}

    def bump(kind, key, risk, tag, inc_id):
        e = ents.setdefault((kind, key), {"type": kind, "id": key, "risk": 0, "tags": [], "incident": None, "findings": 0})
        e["risk"] = max(e["risk"], round(risk * 100))
        e["findings"] += 1
        if tag and tag not in e["tags"]:
            e["tags"].append(tag)
        if inc_id and not e["incident"]:
            e["incident"] = inc_id

    groups = [(i["id"], i["findings"]) for i in incidents] + [(None, alerts)]
    role = {"web_recon": "scanner", "ssh_bruteforce": "brute-forcer", "web_exploit": "exploit attempts",
            "login_after_failures": "session origin", "credential_handoff": "session origin", "login_new_account": "session origin",
            "offhours_login": "off-hours login"}
    for inc_id, fs in groups:
        for f in fs:
            for ip in f.ips[:1]:
                bump("ip", ip, f.adjusted, role.get(f.detector), inc_id)
            if f.session_ip and f.session_ip not in f.ips and not is_internal(f.session_ip):
                bump("ip", f.session_ip, f.adjusted, "session origin", inc_id)
            for u in f.users:
                tag = ("compromised" if f.detector in ("login_after_failures", "credential_handoff") else
                       "attacker-created" if f.detector == "login_new_account" else
                       "targeted" if f.detector == "ssh_bruteforce" else None)
                if f.detector == "ssh_bruteforce" and len(f.users) > 5:
                    continue
                bump("user", u, f.adjusted, tag, inc_id)
            if f.stage == "Exfiltration":
                bump("host", f.host, f.adjusted, "data left host", inc_id)
                if f.dst_ip:
                    bump("ip", f.dst_ip, f.adjusted, "exfil destination", inc_id)
            elif f.host and f.host != "unknown" and f.adjusted >= 0.6:
                bump("host", f.host, f.adjusted, "target", inc_id)
    return sorted(ents.values(), key=lambda e: (-e["risk"], e["type"], e["id"]))[:80]


def analyze(parsed: dict) -> dict:
    t0 = time.perf_counter()
    events = parsed["events"]
    ctx = Context(events)
    findings, per_det = run_all(ctx)
    incidents, alerts, suppressed = corr.correlate(findings)
    inc_dicts = [incident_dict(i) for i in incidents]
    t_ms = round((time.perf_counter() - t0) * 1000)
    return {
        "stats": {
            "events": len(events), "files": len(parsed["files"]), "quarantined": parsed["quarantine_total"],
            "duplicates_dropped": parsed["duplicates_dropped"], "findings": len(findings),
            "incidents": len(inc_dicts), "alerts": len(alerts), "suppressed": len(suppressed),
            "ignored": sum(f["ignored"] for f in parsed["files"]), "analysis_ms": t_ms,
            "span_start": _iso(events[0].ts) if events else None, "span_end": _iso(events[-1].ts) if events else None,
        },
        "files": parsed["files"], "warnings": parsed["warnings"], "detectors": per_det,
        "incidents": inc_dicts,
        "alerts": [finding_dict(f) for f in alerts],
        "suppressed": [finding_dict(f) for f in suppressed],
        "entities": _entities(incidents, alerts),
        "quarantine": parsed["quarantine"],
    }
