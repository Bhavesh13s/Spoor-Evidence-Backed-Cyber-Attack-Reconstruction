"""Central configuration: thresholds, allowlists, ATT&CK metadata."""
import re

STAGES = [
    "Reconnaissance",
    "Credential Access",
    "Initial Access",
    "Privilege Escalation",
    "Persistence",
    "Exfiltration",
]

# --- detection thresholds -------------------------------------------------
BRUTE_MIN_FAILS = 8          # failed SSH logins in one burst
BRUTE_GAP_SEC = 300          # gap that splits two bursts from the same IP
SPRAY_MIN_USERS = 5          # distinct usernames in a burst => spraying / enumeration
WEB_BURST_GAP_SEC = 120
WEB_MIN_REQS = 40            # volume rule: requests in a burst ...
WEB_MIN_4XX_RATIO = 0.6      # ... of which this share are 4xx
SCANNER_MIN_REQS = 5         # scanner user-agent rule
SENSITIVE_HITS = 5           # hits on well-known sensitive paths
FAILS_BEFORE_SUCCESS = 5     # failures before an accepted login => suspicious success
FAIL_LOOKBACK_SEC = 3600
OFFHOURS = (22, 6)           # server-clock hours considered off-hours (22:00-06:00)
KNOWN_IP_LOGINS = 3          # prior logins from an IP before it counts as "known"
BASELINE_MIN_LOGINS = 3      # cold-start guard for baseline-based rules
EXFIL_MIN_BYTES = 50 * 1024 * 1024
EXFIL_WINDOW_GAP_SEC = 1800
EXFIL_WINDOW_MAX_SEC = 3600   # periodic traffic must not merge into one endless window
SUPPRESS_BELOW = 0.35        # adjusted confidence under which a finding is not raised
INCIDENT_MIN_STAGES = 2
INCIDENT_SOLO_CONF = 0.85
HANDOFF_SEC = 180            # an IP picks up within this time of another going quiet
ORDER_TOLERANCE_SEC = 300    # attackers interleave stages; tolerate 5 min of overlap

# --- allowlists (would come from an asset inventory in production) --------
KNOWN_SCANNERS = {"10.0.9.9"}

SCANNER_UA = re.compile(
    r"(nikto|sqlmap|nmap|gobuster|dirb|dirbuster|masscan|nessus|wfuzz|zgrab|acunetix|openvas|nuclei|hydra)",
    re.I,
)
SENSITIVE_PATH = re.compile(
    r"(/\.env|/\.git|/wp-login|/wp-admin|/phpmyadmin|/admin|/backup|/config\.(php|json|yml)|/server-status|/etc/passwd|/\.aws|/id_rsa|/actuator)",
    re.I,
)
PAYLOAD = re.compile(
    r"(union(\s|\+|%20)+select|(\s|\+|%20)or(\s|\+|%20)+1(\s|\+|%20)*=(\s|\+|%20)*1|'--|%27--|sleep\(\d|information_schema|\.\./\.\./|%2e%2e%2f|/etc/passwd|<script|;\s*(cat|wget|curl|nc)\s)",
    re.I,
)

# --- ATT&CK mapping -------------------------------------------------------
TECHNIQUES = {
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1190": "Exploit Public-Facing Application",
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1003.008": "OS Credential Dumping: /etc/shadow",
    "T1548.001": "Abuse Elevation Control: Setuid and Setgid",
    "T1136.001": "Create Account: Local Account",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1059": "Command and Scripting Interpreter",
    "T1041": "Exfiltration Over C2 Channel",
}
