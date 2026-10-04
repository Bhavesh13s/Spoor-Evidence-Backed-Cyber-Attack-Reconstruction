"""Run Spoor on many random scenarios and print a measured accuracy table.
Usage: python scripts/eval_seeds.py [n_seeds]"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime, timezone
from app.generator import generate
from app.parsers import ingest
from app.pipeline import analyze
from app.evaluate import evaluate

n = int(sys.argv[1]) if len(sys.argv) > 1 else 25
now = datetime(2026, 10, 4, 15, 0, tzinfo=timezone.utc)
rows = []
print(f"{'seed':>4} {'events':>7} {'prec':>6} {'recall':>6} {'IPs':>4} {'stages':>6} {'1 camp':>6} {'FP inc':>6} {'decoys':>6} {'ms':>5}")
for seed in range(1, n + 1):
    g = generate(seed, now)
    p = ingest(list(g["files"].items()), now)
    rep = analyze(p)
    ev = evaluate(rep, {e.id: e for e in p["events"]}, g["truth"])
    rows.append(ev)
    print(f"{seed:>4} {rep['stats']['events']:>7} {ev['event_precision']:>6.3f} {ev['event_recall']:>6.3f} "
          f"{ev['attacker_ips_recovered']}/{ev['attacker_ips_total']:<2} {ev['stages_found']}/{ev['stages_expected']:<4} "
          f"{'yes' if ev['merged_into_single_campaign'] else 'NO':>6} {ev['false_incidents']:>6} "
          f"{ev['decoys_suppressed_count']}/{ev['decoys_planted']}{'':>2} {rep['stats']['analysis_ms']:>5}")
m = lambda k: sum(r[k] for r in rows) / len(rows)
print("-" * 70)
print(f"mean precision {m('event_precision'):.3f} | mean recall {m('event_recall'):.3f} | "
      f"single-campaign {sum(r['merged_into_single_campaign'] for r in rows)}/{n} | "
      f"false incidents {sum(r['false_incidents'] for r in rows)} | decoy events flagged {sum(r['decoy_events_wrongly_flagged'] for r in rows)} | "
      f"decoys suppressed {sum(r['decoys_suppressed_count'] for r in rows)}/{sum(r['decoys_planted'] for r in rows)}")
