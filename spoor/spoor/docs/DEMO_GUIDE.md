# Demo guide, pitch and judge Q&A

## Pitches
**30 s.** Security tools hand analysts thousands of isolated alerts. Spoor reads raw logs and tells the story: how the
attacker got in, what they did, what they took. It links three different IPs into one campaign, shows the log lines
behind every step, and tells you which suspicious-looking things it deliberately did *not* flag.

**60 s.** *(30 s version)* + "To prove it isn't pre-baked, I click Generate: a fresh attack is hidden in 18,000 lines —
different IPs, accounts and timing each time. Spoor finds it in about a second, and the Accuracy tab compares its
answer with the hidden truth."

**2 min technical.** Pipeline: sniff and parse four formats into one event model, quarantining bad lines; build per-user
baselines using only past data; run six detectors, each emitting evidence ids, positive signals and benign deductions;
correlate with eight documented link rules (shared tooling, IP rotation, credential reuse, created accounts, session
ownership, exfil-after-access) using union-find; score with a visible formula; narrate from templates. No ML and no
runtime LLM, so every claim traces to a log line. Tested with 51 tests plus a 60-scenario measured sweep.

## Live demo script (about 90 s)
1. "Here is an empty console." → **Generate attack scenario** → "18k lines, attack hidden, I don't know where."
2. **Analyze logs** → "One critical incident, 3 IPs, 6 kill-chain stages."
3. **Replay the attack** → narrate stages as they light up. Pause on the dashed IP link: "Same campaign, three addresses."
4. Click **Show log lines** on the login step: "Every claim has evidence."
5. **Not flagged** list: "An on-call admin, a typo, an internal scanner, a backup — all look suspicious, all explained."
6. **Accuracy check**: "Measured against the hidden truth." Finish: "Same pipeline accepts your own logs."

Seeds: type a seed to make the same scenario reproducible (e.g. `2026`).

## Three scenarios
- **A – normal:** any seed; full 6-stage chain, one incident.
- **B – difficult:** open *Not flagged* → "ravi 03:xx login", "priya typos", Nessus, backup.
- **C – wow:** generate a **new** scenario in front of the judge (blank seed); optionally ask them to pick the seed.

## Fallbacks if something breaks
Network down → run locally (`uvicorn app.main:app`). UI glitch → refresh; session is restored by regenerating.
Upload demo → `sample_logs/` (4 files, select all).

## Predicted judge questions
1. **Is the attack hard-coded?** No. `app/generator.py` randomises IPs, users, tools, timing and size per seed; the Accuracy tab scores against truth withheld from detection. Tests run 12 seeds + a 60-seed sweep.
2. **Why no ML?** Few labelled attacks exist for a given site; rules + baselines are explainable and testable. An anomaly model could be added as another detector feeding the same correlation layer.
3. **How does it connect events?** Eight link rules (README/ARCHITECTURE). Every link is listed with its reason in the UI.
4. **What about false positives?** Each finding carries benign deductions; below 35% it moves to *Not flagged*, visible with reasons. Four look-alike traps are planted and measured.
5. **Accuracy numbers?** On synthetic data: precision/recall 1.00 across 60 seeds. That's in-distribution; I do not claim that for real traffic.
6. **What could fool it?** Very slow brute force below thresholds, living-off-the-land with no sudo trail, attacker using an already-known IP, split attackers within 3 minutes could be wrongly merged. Listed under Limitations.
7. **Scalability?** ~18k events in ~0.2 s; detectors are near-linear in events. For millions of lines you'd stream ingest and index by IP/user; the design (per-entity bursts) allows that.
8. **Security of the tool itself?** No auth, in-memory, upload size/count limits, HTML-escaped output, no stack traces in responses, no shell or file execution of uploads.
9. **Which log formats?** syslog/auth.log, nginx/Apache combined, flow CSV, generic CSV (column aliases), JSON lines. Unknown formats are rejected with a clear message.
10. **Time zones?** Normalised to UTC; syslog assumed UTC (documented).
11. **Why is the confidence 99%?** It's a stated noisy-OR formula over strong findings plus kill-chain bonuses; expand "How the % was calculated". It's a ranking aid, not a calibrated probability.
12. **Real data?** Demo data is synthetic. Upload works on real logs; behaviour depends on thresholds in `config.py`.
13. **Cost?** Zero: no API calls or paid services.
14. **MITRE mapping?** Technique IDs are labels per finding (e.g. T1110.001); they're mapped by detector, not inferred.
15. **How would you extend it?** New detector = one function returning `Finding`s; new log format = one parser; new link rule = one block in `build_links`.
16. **What did AI do?** Helped write the code and tests; no AI runs inside the product. Disclosed in README.

## Competitor positioning
- *Basic team:* threshold table → we have a timeline, evidence, and correlation.
- *Technically advanced (ML):* anomaly scores without explanation → we explain, and quantify with ground truth.
- *Pretty UI:* weak depth → ours is backed by 51 tests and measurable accuracy.

## Honest checklist before submitting
- [ ] Deployed URL opens and Generate → Analyze works on the deployed site
- [ ] README placeholders (URL, video/screenshots) filled
- [ ] `python -m pytest -q` passes on your machine
- [ ] Repo pushed; add the architecture diagram image (paste the Mermaid into mermaid.live and export PNG)
