from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Event:
    id: int
    ts: datetime                 # timezone-aware UTC
    source: str                  # auth | web | net | json | csv
    kind: str                    # login_fail | login_ok | sudo | user_add | http | flow | generic
    file: str
    line: int
    raw: str
    host: str = "unknown"
    ip: Optional[str] = None
    user: Optional[str] = None
    method: str = ""
    path: str = ""
    status: int = 0
    ua: str = ""
    invalid_user: bool = False
    auth_method: str = ""
    cmd: str = ""
    target_user: str = ""
    dst_ip: Optional[str] = None
    dst_port: int = 0
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass
class Finding:
    id: str
    detector: str
    stage: str
    technique: str
    title: str
    detail: str
    start: datetime
    end: datetime
    host: str
    event_ids: list
    confidence: float
    ips: list = field(default_factory=list)       # attacker-side source IPs
    users: list = field(default_factory=list)
    dst_ip: Optional[str] = None
    session_ip: Optional[str] = None
    ua: str = ""
    benign: list = field(default_factory=list)     # (reason, deduction) that APPLY
    checks: list = field(default_factory=list)     # benign explanations tested and ruled out
    positive: list = field(default_factory=list)   # extra reasons that strengthen it
    meta: dict = field(default_factory=dict)

    @property
    def adjusted(self) -> float:
        c = self.confidence + 0.05 * min(len(self.positive), 2) - sum(d for _, d in self.benign)
        return max(0.0, min(0.99, c))
