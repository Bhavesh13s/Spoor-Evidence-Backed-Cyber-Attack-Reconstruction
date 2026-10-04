"""Deterministic narrative generation: the story, the benign-explanation review and recommended actions.
Templates only - no model call - so the output is reproducible and cannot hallucinate evidence."""
from __future__ import annotations

from . import config as C


def _hhmm(ts):
    return ts.strftime("%H:%M")


def _join(items, limit=3):
    items = list(dict.fromkeys(items))
    if len(items) <= limit:
        return ", ".join(items[:-1]) + (" and " if len(items) > 1 else "") + items[-1] if items else ""
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def headline(inc):
    fs = inc["findings"]
    ips = inc["ips"]
    host = inc["hosts"][0] if inc["hosts"] else "the environment"
    if len(inc["stages"]) >= 3:
        return f"Multi-stage intrusion on {host}: {len(inc['stages'])} kill-chain stages, {len(ips)} attacker IP(s)"
    if len(inc["stages"]) == 2:
        return f"Two-stage attack on {host} from {_join(ips, 2)}"
    return fs[0].title


def story(inc):
    fs = inc["findings"]
    paras = []
    ips = inc["ips"]
    by = lambda d: [f for f in fs if f.detector == d]
    recon, brute = by("web_recon"), by("ssh_bruteforce")
    logins = [f for f in fs if f.detector in ("login_after_failures", "credential_handoff")]
    newlogin = by("login_new_account")
    exfil = by("exfil_volume")
    post = [f for f in fs if f.detector.startswith("sudo_") or f.detector == "useradd"]

    opening = (f"Between {_hhmm(fs[0].start)} and {_hhmm(fs[-1].end)} UTC, Spoor connected {len(fs)} separate findings "
               f"into one campaign involving {len(ips)} external IP(s): {_join(ips)}.")
    if inc["rotation"]:
        opening += " The attacker switched IP addresses mid-attack, which per-IP alerting would have treated as unrelated events."
    paras.append(opening)

    if recon:
        r = recon[0]
        paras.append(f"Reconnaissance: {r.detail}")
    if brute:
        total = sum(b.meta.get("fails", 0) for b in brute)
        who = _join([b.ips[0] for b in brute])
        paras.append(f"Credential access: {total} failed SSH logins from {who} before the attacker found a working password.")
    if logins:
        l = logins[0]
        paras.append(f"Initial access: {l.detail}")
    if post:
        cmds = _join([f.title.replace("'", "").split(" used sudo to ")[-1] for f in post])
        user = post[0].users[0] if post[0].users else "the account"
        paras.append(f"Privilege escalation and persistence: inside that session '{user}' used sudo to {cmds}.")
    if newlogin:
        n = newlogin[0]
        paras.append(f"Return access: {n.detail}")
    if exfil:
        e = exfil[0]
        paras.append(f"Exfiltration: {e.detail} This destination had no prior traffic history.")
    return paras


def benign_review(inc):
    applied, ruled_out = [], []
    for f in inc["findings"]:
        for reason, ded in f.benign:
            applied.append(f"{f.id}: {reason} (confidence -{int(ded * 100)}%)")
        for c in f.checks:
            if c not in ruled_out:
                ruled_out.append(c)
    return applied, ruled_out[:8]


def actions(inc):
    fs = inc["findings"]
    out = []
    ips = inc["ips"]
    out.append(f"Block {_join(ips, 5)} at the firewall and WAF; search other log sources for the same addresses.")
    for u in dict.fromkeys(u for f in fs if f.detector in ("login_after_failures", "credential_handoff") for u in f.users):
        out.append(f"Force a password reset for '{u}', revoke its active sessions and review its recent activity.")
    for f in fs:
        acct = f.meta.get("new_account")
        if acct and f.stage == "Persistence" and f.detector != "login_new_account":
            out.append(f"Disable and investigate account '{acct}' (created during the attack); audit authorized_keys files.")
            break
    if any(f.detector == "sudo_cred_dump" for f in fs):
        out.append("Treat local password hashes as exposed: rotate credentials for every account on the affected host.")
    if any(f.detector == "sudo_setuid" for f in fs):
        out.append("Find and remove setuid binaries created during the incident; compare against a clean baseline.")
    for f in fs:
        if f.stage == "Exfiltration":
            out.append(f"Isolate {f.host}, block {f.dst_ip}, and determine which data was readable by this host before disclosure decisions.")
            break
    if not any(f.stage in ("Initial Access", "Persistence", "Exfiltration") for f in fs):
        out.append("No successful access was observed; add rate limiting / fail2ban for SSH and restrict exposed admin paths.")
    return out
