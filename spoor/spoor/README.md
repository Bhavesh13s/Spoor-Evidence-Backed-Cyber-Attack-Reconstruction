# Spoor — follow the intruder's trail

**ALGOTHON'26 · Problem statement ALG-CYBER-01 · Find the Intruder**

Spoor reads raw SSH, web-server and network logs, links events across IP addresses and accounts, and rebuilds a
suspected intrusion as one evidence-backed timeline: *how they got in, what they did, what they took.*

> Demo: `<add deployed URL>` · Video/screenshots: `<add links>`

## 1. Problem
Thousands of security events hide an attacker among normal activity. Alert-per-event tools flag isolated lines and
leave the analyst to connect them. The PS asks for log ingestion, anomaly/rule detection, suspicious user/IP
detection, event grouping, an incident timeline and evidence, with the bonus of *explaining the likely attack
sequence instead of flagging isolated events.*

## 2. What Spoor does
| PS requirement | Where it lives | How to see it |
|---|---|---|
| Log ingestion | `app/parsers.py` — syslog/auth.log, nginx/Apache, flow CSV, generic CSV, JSONL; auto-detected per file | **Data quality** tab |
| Anomaly detection / rules | `app/detectors.py` — 6 detectors + per-user baselines | **Data quality → detectors** |
| Suspicious user / IP detection | `app/pipeline.py::_entities` | **Suspects** tab |
| Event grouping | `app/correlate.py` — 8 documented link rules → campaigns | **Why these IPs were treated as one attacker** |
| Incident timeline | `app/pipeline.py`, UI timeline + replay | **Incidents** tab |
| Evidence | every finding keeps its event ids → raw `file:line` | **Show N log lines** button |
| *Bonus: attack sequence* | kill-chain staging, ATT&CK IDs, narrative | **What happened** |

## 3. What makes it different
1. **Campaign merging across identities.** Attackers rotate IPs. Spoor links them by shared scanner fingerprint,
   handoff timing (B starts seconds after A is blocked), credential reuse (A guesses, B logs in) and accounts the attacker
   created. Result: *3 IPs → 1 campaign*.
2. **It shows what it did NOT flag.** A 3 AM on-call admin, a mistyped password, an internal Nessus scan and a nightly
   backup all look suspicious to naive rules. Spoor scores them, subtracts documented benign factors, and lists them
   under *Not flagged* with the reason. Each incident also lists the innocent explanations it tested and ruled out.
3. **Provable, not pre-baked.** *Generate attack scenario* hides a freshly randomised attack (different IPs, accounts,
   timing, tooling) in ~18,000 lines. The *Accuracy check* tab then compares Spoor's answer with the hidden ground truth.
4. **Explainable scoring.** Confidence is a stated formula (noisy-OR of per-finding confidences + kill-chain bonuses),
   expandable in the UI. No black box and no model call.

## 4. Architecture
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (Mermaid diagram + design decisions).

```
Browser (single page) → FastAPI → ingest → context/baselines → detectors → correlate → narrate → JSON report
```

## 5. Tech stack
Python 3.12 · FastAPI · plain HTML/CSS/JS (no build step) · pytest. No database and no AI/LLM at runtime —
state lives in memory per session, which is enough for a stateless analysis tool and removes failure modes
from a live demo.

## 6. Run it
```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
# open http://localhost:8000
```
Docker: `docker build -t spoor . && docker run -p 8000:8000 spoor`

**Deploy (free):** push to GitHub → Render → *New Web Service* → pick the repo (it reads `render.yaml`/`Dockerfile`).
Health check path: `/api/health`. Hugging Face Spaces (Docker SDK) also works; set `app_port: 8000` in the Space README header.
No environment variables or API keys are required.

## 7. Demo (60–120 s)
1. Open the app → **Generate attack scenario** (optionally type a seed).
2. **Analyze logs** → one *critical* incident appears in about a second.
3. Point at the kill-chain strip, read **What happened**, press **Replay the attack**.
4. Open **Not flagged** to show the four look-alikes that were correctly ignored.
5. Click **Show N log lines** on the exfiltration step to show raw evidence.
6. **Accuracy check** tab: precision/recall against the hidden truth.
7. Optional: **Upload logs** with the files in `sample_logs/` or your own.

## 8. Testing
```bash
python -m pytest -q                 # 51 tests: parsers, detectors, correlation, API, end-to-end
python scripts/eval_seeds.py 60     # measured table over 60 random scenarios
```
Latest local run: **51/51 tests pass.** Across 60 randomised scenarios: mean event precision 1.000, recall 1.000,
60/60 merged into a single campaign, 0 false-alarm incidents, 240/240 planted decoys correctly not flagged,
~0.2 s analysis for ~18k events.
**Read this honestly:** the generator and detectors were written together, so these numbers show the pipeline is
correct and robust on this attack family, **not** that it will catch every real-world attack. See Limitations.

## 9. Edge cases handled
| Case | Behaviour |
|---|---|
| Corrupt / truncated / binary lines, impossible dates (Feb 30), invalid IPs (999.x) | quarantined with a reason, shown in *Data quality*; analysis continues |
| Mixed time zones (nginx `+0530`, syslog UTC, ISO `Z`) | normalised to UTC before correlation |
| Syslog lines have no year; year boundary | current year assumed, rolled back if it lands in the future |
| Overlapping exports (same line in two files) | de-duplicated; repeats inside one file are kept |
| Out-of-order lines | sorted by time before analysis |
| Unknown / empty / oversized files | clear warning, or `422` with the supported formats; limits 12 files / 40 MB |
| Crawler bursts (Googlebot, all 200s) | not flagged as scanning |
| Few mistyped passwords | below threshold; 6 typos from a known IP → scored, then suppressed |
| Cold start (user with < 3 prior logins) | baseline rules are skipped instead of guessing |
| Internal scanner / allow-listed IP / scheduled internal backup | suppressed with explanation |
| Analysis run with no data / invalid parameters | `404`/`422` with plain-language messages; no stack traces reach the UI |

## 10. Known limitations
- Detection logic is rule + baseline based. It will not find novel techniques outside the 6 detectors.
- Accuracy numbers are on **synthetic** data from this project's generator (disclosed below). Real logs will be noisier.
- Correlation can merge two unrelated attackers who hit the same host within 3 minutes (rule R3). Evidence for every
  link is shown so an analyst can overrule it.
- Thresholds and the scanner allow-list live in `app/config.py`; production would load an asset inventory.
- State is in memory per session (last 40 sessions); restarting the server clears it.
- Syslog timestamps are assumed to be UTC; nginx offsets are honoured.
- No authentication: do not expose it publicly with real customer logs.

## 11. Future work
Persist incidents; asset inventory and user-directory integration; more sources (Windows events, cloud audit logs,
DNS); sigma-rule import; optional LLM paraphrasing of the (already deterministic) narrative; streaming ingestion.

## 12. AI / API / data disclosure
- **Runtime AI:** none. No external APIs, no network calls, no keys. Every sentence in the narrative is a template filled from evidence.
- **AI-assisted development:** the code, tests and docs were written with an AI assistant (Claude) and reviewed and run by the participant.
- **Data:** all demo data is **synthetic**, produced by `app/generator.py` (documentation-style fictional hosts and random IPs). No real logs or personal data.
- **Frameworks:** FastAPI, Uvicorn, pytest. MITRE ATT&CK® technique IDs are used as labels only.

## 13. Repository map
```
app/        main.py (API) · parsers.py · context.py · detectors.py · correlate.py · narrate.py · pipeline.py · evaluate.py · generator.py · config.py
static/     index.html (the whole UI)
tests/      test_parsers · test_detectors · test_pipeline · test_api
scripts/    eval_seeds.py
sample_logs/ one generated bundle you can upload (seed 2026)
docs/       ARCHITECTURE.md · DEMO_GUIDE.md
```
