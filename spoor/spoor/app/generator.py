"""Synthetic log generator with ground truth.

Produces three days of realistic background traffic (SSH auth, nginx access, network flows) and hides a seeded,
multi-stage attack in it: web scan -> SSH enumeration -> IP rotation -> brute force -> login -> credential dump ->
backdoor account -> return from a third IP -> large exfiltration. Four look-alike decoys (an on-call admin, a
mistyped password, an internal vulnerability scanner, a nightly backup) are planted so false positives are measurable.
Every malicious / decoy line is labelled, so detection can be scored. All data is synthetic.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

POOL = [45, 91, 103, 138, 159, 185, 194, 5, 77, 89, 141, 176, 193, 62, 109, 37]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
]
ATTACK_UAS = ["Nikto/2.5.0", "gobuster/3.6", "sqlmap/1.7.2#stable", "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)"]
SENSITIVE = ["/admin", "/administrator", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
             "/config.php", "/server-status", "/actuator/health", "/.aws/credentials", "/wp-admin/", "/backup/db.sql"]
WORDS = ("login test dev stage old new api v1 v2 uploads files images tmp cgi-bin shell console manager portal user users "
         "account debug info status health metrics docs swagger graphql jenkins solr hudson struts tomcat cpanel webmail "
         "mail owa remote vpn setup install db database sql dump logs log private secret keys key cert ssl").split()
PAGES = ["/", "/products", "/about", "/contact", "/cart", "/login", "/static/app.js", "/static/style.css", "/pricing",
         "/api/items?page=%d", "/products?id=%d", "/search?q=%s", "/blog/%d"]
HOUR_W = [1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 11, 11, 10, 10, 11, 11, 10, 9, 8, 7, 6, 4, 3, 2]
STAGES_TRUTH = ["Reconnaissance", "Credential Access", "Initial Access", "Privilege Escalation", "Persistence", "Exfiltration"]


def _ip(r, used):
    while True:
        ip = f"{r.choice(POOL)}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
        if ip not in used:
            used.add(ip)
            return ip


class Gen:
    def __init__(self, seed, now, scale):
        self.r = random.Random(seed)
        self.end = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
        self.start = self.end - timedelta(hours=72)
        self.scale = scale
        self.rows = {"auth_web01.log": [], "auth_db01.log": [], "access_web01.log": [], "flows_web01.csv": []}
        self.used = set()
        self.truth_keys = {"attack": set(), "decoy": set()}
        self._pending = []   # (file, ts, text, label)

    # ---- line formatters
    def _sys(self, ts, host, proc, msg, pid=None):
        pid = pid or self.r.randint(900, 32000)
        return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {proc}[{pid}]: {msg}"

    def add(self, fname, ts, text, label=None):
        self._pending.append((fname, ts, text, label))

    def fail(self, ts, host, user, ip, invalid=False, label=None):
        f = "auth_web01.log" if host == "web01" else "auth_db01.log"
        self.add(f, ts, self._sys(ts, host, "sshd", f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {self.r.randint(1024, 65000)} ssh2"), label)

    def ok(self, ts, host, user, ip, method="password", label=None):
        f = "auth_web01.log" if host == "web01" else "auth_db01.log"
        self.add(f, ts, self._sys(ts, host, "sshd", f"Accepted {method} for {user} from {ip} port {self.r.randint(1024, 65000)} ssh2"), label)

    def sudo(self, ts, host, user, cmd, label=None):
        f = "auth_web01.log" if host == "web01" else "auth_db01.log"
        self.add(f, ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}", label)

    def web(self, ts, ip, path, status, ua, label=None, method="GET"):
        local = ts + timedelta(hours=5, minutes=30)      # access log is written in IST (+0530); parser must normalise
        line = f'{ip} - - [{local:%d/%b/%Y:%H:%M:%S} +0530] "{method} {path} HTTP/1.1" {status} {self.r.randint(200, 48000)} "-" "{ua}"'
        self.add("access_web01.log", ts, line, label)

    def flow(self, ts, dst, port, bout, bin_=None, label=None, src="10.0.1.10"):
        bin_ = bin_ if bin_ is not None else self.r.randint(500, 40000)
        self.add("flows_web01.csv", ts, f"{ts:%Y-%m-%dT%H:%M:%SZ},web01,{src},{dst},{port},tcp,{bout},{bin_}", label)

    def rt(self, lo, hi):
        return lo + timedelta(seconds=self.r.randint(0, int((hi - lo).total_seconds())))


def generate(seed: int = 1, now: datetime | None = None, scale: float = 1.0) -> dict:
    g = Gen(seed, now, scale)
    r = g.r
    S, E = g.start, g.end

    # ---- cast
    users = {}
    for name in ["alice", "bob", "carol", "dave", "priya", "ravi"]:
        users[name] = {"ip": _ip(r, g.used), "hours": (9, 18)}
    ci_ip = "10.0.4.4"
    victim = r.choice(["deploy", "jenkins"])
    humans = list(users)
    atk_a, atk_b, atk_c, dst = (_ip(r, g.used) for _ in range(4))
    ua_x = r.choice(ATTACK_UAS)
    new_account = r.choice(["sysupdate", "svc-monitor", "dbus-helper", "logrotate2"])
    cust = [_ip(r, g.used) for _ in range(int(260 * max(scale, 0.3)))]
    cust_ua = {ip: r.choice(UAS) for ip in cust}

    # ---- pick the attack night: latest 01:00-02:10 window that ends >= 4h before `end`
    day = E.replace(hour=0)
    t0 = day + timedelta(hours=1, minutes=r.randint(0, 70))
    while t0 > E - timedelta(hours=4):
        t0 -= timedelta(days=1)
    nights = [t0.replace(hour=0, minute=0) - timedelta(days=k) for k in (2, 1, 0)]
    quiet = (t0 - timedelta(hours=1), t0 + timedelta(hours=3))

    # ---- background: human logins, typos, admin sudo
    d = S.replace(hour=0, minute=0)
    while d < E:
        for name in humans:
            for _ in range(r.randint(2, 5)):
                ts = d + timedelta(hours=r.randint(9, 17), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
                if not (S <= ts < E):
                    continue
                host = r.choice(["web01", "db01"])
                if r.random() < 0.15:
                    for k in range(r.randint(1, 2)):
                        g.fail(ts - timedelta(seconds=10 * (k + 1)), host, name, users[name]["ip"])
                g.ok(ts, host, name, users[name]["ip"], r.choice(["publickey", "password"]))
                if name == "ravi" and r.random() < 0.5:
                    g.sudo(ts + timedelta(seconds=40), host, "ravi", r.choice(
                        ["/bin/systemctl restart nginx", "/usr/bin/apt update", "/bin/journalctl -u nginx", "/usr/bin/apt upgrade -y"]))
        if d == S.replace(hour=0, minute=0):          # guarantee every user has some baseline history on day one
            for name in humans:
                for k in range(3):
                    ts = S + timedelta(hours=1 + 5 * k, minutes=r.randint(0, 50))
                    g.ok(ts + timedelta(hours=8), r.choice(["web01", "db01"]), name, users[name]["ip"], "publickey")
        for svc in ("deploy", "jenkins"):
            for _ in range(r.randint(3, 6)):
                ts = d + timedelta(hours=r.randint(9, 17), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
                if S <= ts < E:
                    g.ok(ts, r.choice(["web01", "db01"]), svc, ci_ip, "publickey")
        d += timedelta(days=1)

    # ---- background: internet bots (below threshold) + persistent bots (isolated alerts)
    users_try = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "git", "user", "pi", "guest"]
    for _ in range(int(55 * scale)):
        ip = _ip(r, g.used)
        ts = g.rt(S, E)
        if quiet[0] <= ts <= quiet[1]:
            continue
        for k in range(r.randint(1, 4)):
            u = r.choice(users_try)
            g.fail(ts + timedelta(seconds=3 * k), r.choice(["web01", "db01"]), u, ip, invalid=u != "root")
    for _ in range(3):
        ip = _ip(r, g.used)
        ts = g.rt(S, E)
        while quiet[0] - timedelta(hours=1) <= ts <= quiet[1] + timedelta(hours=1):
            ts = g.rt(S, E)
        for k in range(r.randint(9, 14)):
            u = r.choice(users_try)
            g.fail(ts + timedelta(seconds=11 * k), "db01", u, ip, invalid=u != "root")

    # ---- background: web traffic
    hours = [S + timedelta(hours=h) for h in range(72)]
    weights = [HOUR_W[h.hour] for h in hours]
    for _ in range(int(16000 * scale)):
        h = r.choices(hours, weights)[0]
        ts = h + timedelta(seconds=r.randint(0, 3599))
        ip = r.choice(cust)
        p = r.choice(PAGES)
        if "%d" in p:
            p = p % r.randint(1, 900)
        elif "%s" in p:
            p = p % r.choice(["shoes", "laptop", "gift", "chair"])
        x = r.random()
        st = 200 if x < 0.915 else 304 if x < 0.95 else 404 if x < 0.975 else 301 if x < 0.99 else 500
        g.web(ts, ip, p, st, cust_ua[ip])
    for _ in range(2):  # a search-engine crawler: bursty but clean 200s -> must NOT alert
        ts = g.rt(S, E)
        for k in range(r.randint(60, 80)):
            g.web(ts + timedelta(seconds=k), "66.249.66.%d" % r.randint(1, 90), "/products?id=%d" % r.randint(1, 900), 200,
                  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

    # ---- background: flows
    ts = S
    cdn = [_ip(r, g.used) for _ in range(3)]
    while ts < E:
        g.flow(ts, "10.0.2.10", 3306, r.randint(20_000, 400_000))
        if r.random() < 0.7:
            g.flow(ts + timedelta(seconds=30), r.choice(cdn), 443, r.randint(200_000, 1_800_000))
        ts += timedelta(minutes=10)

    # ---- noise that parsers must ignore / quarantine
    for _ in range(int(60 * scale)):
        ts = g.rt(S, E)
        g.add("auth_web01.log", ts, g._sys(ts, "web01", "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
    garbage = ["@@@@ corrupted entry ####", "Oct", "\x1b[31mnot a log line\x1b[0m",
               "Feb 30 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
               "Oct  3 11:00:00 web01 sshd[2]: Failed password for root from 999.1.1.1 port 22 ssh2",
               '203.0.113.9 - - [bad-date] "GET / HTTP/1.1" 200 12 "-" "curl"', "ts=??? level=warn msg=truncat"]
    for i, junk in enumerate(garbage):
        fname = ["auth_web01.log", "access_web01.log"][i % 2]
        g.add(fname, g.rt(S, E), junk)

    # ---- decoys
    present = {"oncall": False, "backup": False}
    for k, n in enumerate(nights):      # on-call admin: off-hours login from a known IP
        ts = n + timedelta(hours=3, minutes=r.randint(8, 40))
        lab = "decoy" if k == 2 and ts < E else None
        present["oncall"] = present["oncall"] or lab == "decoy"
        g.ok(ts, "web01", "ravi", users["ravi"]["ip"], "publickey", lab)
        g.sudo(ts + timedelta(seconds=45), "web01", "ravi", "/bin/systemctl restart nginx", lab)
    pt = (t0 - timedelta(days=1)).replace(hour=11, minute=r.randint(0, 50))       # priya mistypes her password
    for k in range(6):
        g.fail(pt + timedelta(seconds=11 * k), "web01", "priya", users["priya"]["ip"], label="decoy")
    g.ok(pt + timedelta(seconds=75), "web01", "priya", users["priya"]["ip"], "password", "decoy")
    st_ = (t0 - timedelta(days=1)).replace(hour=14, minute=r.randint(0, 30))      # internal scanner (Nessus)
    for k in range(220):
        p = r.choice(SENSITIVE + ["/" + r.choice(WORDS)])
        g.web(st_ + timedelta(seconds=k // 2), "10.0.9.9", p, 404 if r.random() < 0.9 else 403, "Nessus SOAP", "decoy")
    for k, n in enumerate(nights):      # nightly backup to an internal host
        bt = n + timedelta(hours=2)
        for j in range(6):
            g.flow(bt + timedelta(minutes=2 * j), "10.0.5.20", 873, r.randint(90, 120) * 1024 * 1024,
                   label="decoy" if k == 2 and bt < E else None)
        present["backup"] = present["backup"] or (k == 2 and bt < E)

    # ---- the attack
    A = "attack"
    t = t0
    n_scan = r.randint(170, 300)
    dur = r.randint(100, 150)
    for k in range(n_scan):
        ts = t + timedelta(seconds=dur * k / n_scan)
        p = r.choice(SENSITIVE) if r.random() < 0.35 else "/" + r.choice(WORDS) + r.choice(["", "/", ".php", ".bak"])
        stt = 200 if (p in ("/admin", "/.env") and r.random() < 0.15) else 403 if r.random() < 0.05 else 404
        g.web(ts, atk_a, p, stt, ua_x, A)
    scan_end = t + timedelta(seconds=dur)
    for k in range(r.randint(3, 4)):
        g.web(scan_end - timedelta(seconds=10 - 2 * k), atk_a, "/products?id=1'%20OR%201=1--", 500, ua_x, A)
    ts = scan_end + timedelta(seconds=r.randint(20, 40))
    a_users = ["root", "admin", "ubuntu", "test", "oracle", "git", "postgres"]
    n_enum = r.randint(45, 75)
    sp = r.randint(100, 140)
    for k in range(n_enum):
        u = a_users[k % len(a_users)]
        g.fail(ts + timedelta(seconds=sp * k / n_enum), "web01", u, atk_a, invalid=u != "root", label=A)
    a_end = ts + timedelta(seconds=sp)
    b0 = a_end + timedelta(seconds=r.randint(40, 100))                       # IP rotation
    for k in range(r.randint(6, 9)):
        g.web(b0 + timedelta(seconds=2 * k), atk_b, r.choice(["/login", "/admin", "/wp-login.php"]), 404, ua_x, A)
    ts = b0 + timedelta(seconds=25)
    for k in range(r.randint(28, 45)):
        ts += timedelta(seconds=r.randint(3, 6))
        g.fail(ts, "web01", victim, atk_b, label=A)
    t_login = ts + timedelta(seconds=r.randint(4, 8))
    g.ok(t_login, "web01", victim, atk_b, "password", A)
    ts = t_login + timedelta(seconds=r.randint(90, 180))
    g.sudo(ts, "web01", victim, "/bin/cat /etc/shadow", A)
    ts += timedelta(seconds=r.randint(20, 60))
    g.sudo(ts, "web01", victim, f"/usr/sbin/useradd -m -s /bin/bash {new_account}", A)
    t_acct = ts
    g.add("auth_web01.log", ts + timedelta(seconds=1), g._sys(ts + timedelta(seconds=1), "web01", "useradd",
          f"new user: name={new_account}, UID=1005, GID=1005, home=/home/{new_account}, shell=/bin/bash"), A)
    ts += timedelta(seconds=r.randint(20, 50))
    g.sudo(ts, "web01", victim, f"/usr/bin/tee -a /home/{new_account}/.ssh/authorized_keys", A)
    if r.random() < 0.5:
        ts += timedelta(seconds=r.randint(15, 40))
        g.sudo(ts, "web01", victim, "/bin/chmod u+s /bin/bash", A)
    t_c = t_acct + timedelta(minutes=r.randint(25, 45))
    g.ok(t_c, "web01", new_account, atk_c, "publickey", A)
    ex = t_c + timedelta(minutes=r.randint(4, 12))
    total = 0
    for k in range(r.randint(4, 8)):
        b = r.randint(110, 230) * 1024 * 1024
        total += b
        g.flow(ex + timedelta(minutes=2 * k + r.randint(0, 1)), dst, r.choice([8443, 4444, 443]), b, label=A)

    # ---- materialise files with line numbers + ground truth
    files, attack, decoy = {}, set(), set()
    header = {"flows_web01.csv": "timestamp,host,src_ip,dst_ip,dst_port,proto,bytes_out,bytes_in"}
    for fname in g.rows:
        items = sorted((x for x in g._pending if x[0] == fname), key=lambda x: x[1])
        lines = [header[fname]] if fname in header else []
        for _, ts, text, label in items:
            lines.append(text)
            if label == "attack":
                attack.add((fname, len(lines)))
            elif label == "decoy":
                decoy.add((fname, len(lines)))
        files[fname] = "\n".join(lines) + "\n"
    truth = {
        "attacker_ips": sorted([atk_a, atk_b, atk_c]), "exfil_dst": dst, "victim_user": victim, "new_account": new_account,
        "host": "web01", "stages": STAGES_TRUTH, "t0": t0.isoformat(), "toolkit": ua_x, "exfil_bytes": total,
        "attack_lines": sorted(attack), "decoy_lines": sorted(decoy), "seed": seed,
        "decoys_present": {"on-call admin (off-hours, known IP)": present["oncall"], "mistyped password (known IP)": True,
                           "internal Nessus scanner": True, "nightly backup (internal, recurring)": present["backup"]},
        "decoys": ["ravi: on-call off-hours login from a known IP", "priya: 6 mistyped passwords then success from her usual IP",
                   "10.0.9.9: internal Nessus scan", "web01 -> 10.0.5.20: nightly backup (~600 MB)"],
    }
    return {"files": files, "truth": truth}
