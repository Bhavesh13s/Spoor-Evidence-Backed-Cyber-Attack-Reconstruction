"""Behavioural baselines and lookup indexes shared by the detectors."""
from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left
from collections import defaultdict
from datetime import timedelta

from . import config as C


def is_internal(ip) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except (ValueError, TypeError):
        return False


def is_offhours(ts) -> bool:
    start, end = C.OFFHOURS
    return ts.hour >= start or ts.hour < end


ACCOUNT_CMD = re.compile(r"(?:^|/|\s)(?:useradd|adduser)\b.*?([A-Za-z_][\w\-]*)\s*$")


class Context:
    def __init__(self, events):
        self.events = events
        self.logins = defaultdict(list)       # user -> [(ts, ip)]  accepted logins, time-ordered
        self.fails = defaultdict(list)        # ip -> [event]
        self.fails_by_user = defaultdict(list)
        self.web = defaultdict(list)          # ip -> [event]
        self.sudo = []
        self.user_adds = []
        self.flows = []
        self.created = {}                     # account -> (ts, host)
        for e in events:
            if e.kind == "login_ok" and e.user and e.ip:
                self.logins[e.user].append((e.ts, e.ip))
            elif e.kind == "login_fail" and e.ip:
                self.fails[e.ip].append(e)
                if e.user:
                    self.fails_by_user[e.user].append(e)
            elif e.kind == "http" and e.ip:
                self.web[e.ip].append(e)
            elif e.kind == "sudo":
                self.sudo.append(e)
                m = ACCOUNT_CMD.search(e.cmd)
                if m and re.search(r"\b(useradd|adduser)\b", e.cmd):
                    self.created.setdefault(m.group(1), (e.ts, e.host))
            elif e.kind == "user_add":
                self.user_adds.append(e)
                self.created[e.user] = (e.ts, e.host)
            elif e.kind == "flow":
                self.flows.append(e)
        self._login_ts = {u: [t for t, _ in v] for u, v in self.logins.items()}
        self._hourly = None

    # ---- login baselines (always "before time t" so an attack never pollutes its own baseline)
    def prior_logins(self, user, before):
        v = self.logins.get(user, [])
        return v[: bisect_left(self._login_ts.get(user, []), before)]

    def known_ip_logins(self, user, ip, before) -> int:
        return sum(1 for _, i in self.prior_logins(user, before) if i == ip)

    def prior_offhours_logins(self, user, before) -> int:
        return sum(1 for t, _ in self.prior_logins(user, before) if is_offhours(t))

    def last_login_before(self, user, ts, within_sec=12 * 3600):
        prior = self.prior_logins(user, ts + timedelta(seconds=1))
        if prior and (ts - prior[-1][0]).total_seconds() <= within_sec:
            return prior[-1]
        return None

    # ---- failures
    def recent_fails(self, ip, ts, window=C.FAIL_LOOKBACK_SEC):
        lo = ts - timedelta(seconds=window)
        return [e for e in self.fails.get(ip, []) if lo <= e.ts < ts]

    def recent_fails_for_user(self, user, ts, window=C.FAIL_LOOKBACK_SEC):
        lo = ts - timedelta(seconds=window)
        return [e for e in self.fails_by_user.get(user, []) if lo <= e.ts < ts]

    # ---- traffic baseline: bytes_out per host per hour
    def hourly_out(self):
        if self._hourly is None:
            h = defaultdict(int)
            for e in self.flows:
                h[(e.host, e.ts.replace(minute=0, second=0, microsecond=0))] += e.bytes_out
            self._hourly = h
        return self._hourly
