"""Score detection against the generator's ground truth."""
from __future__ import annotations


def evaluate(report: dict, events_by_id: dict, truth: dict) -> dict:
    attack = {tuple(x) for x in truth["attack_lines"]}
    decoy = {tuple(x) for x in truth["decoy_lines"]}
    flagged_ids = set()
    for inc in report["incidents"]:
        flagged_ids.update(inc["evidence_ids"])
    flagged = {(events_by_id[i].file, events_by_id[i].line) for i in flagged_ids if i in events_by_id}
    tp = len(flagged & attack)
    fp_decoy = len(flagged & decoy)
    fp_other = len(flagged - attack - decoy)
    precision = tp / len(flagged) if flagged else 0.0
    recall = tp / len(attack) if attack else 0.0

    found_ips = set()
    stages = set()
    for inc in report["incidents"]:
        found_ips.update(inc["ips"])
        stages.update(inc["stages"])
    truth_ips = set(truth["attacker_ips"])
    attack_incidents = [i for i in report["incidents"] if set(i["ips"]) & truth_ips]
    false_incidents = [i for i in report["incidents"] if not (set(i["ips"]) & truth_ips)]
    exfil_found = any(truth["exfil_dst"] in i["dst_ips"] for i in report["incidents"])

    sup_titles = " ".join(s["title"] for s in report["suppressed"])
    decoys_suppressed = {
        "on-call admin (off-hours, known IP)": "Off-hours login for 'ravi'" in sup_titles,
        "mistyped password (known IP)": "'priya' logged in" in sup_titles,
        "internal Nessus scanner": "10.0.9.9" in sup_titles,
        "nightly backup (internal, recurring)": "10.0.5.20" in sup_titles,
    }
    return {
        "event_precision": round(precision, 3), "event_recall": round(recall, 3),
        "true_positive_events": tp, "attack_events_total": len(attack), "flagged_events": len(flagged),
        "decoy_events_wrongly_flagged": fp_decoy, "other_false_positive_events": fp_other,
        "attacker_ips_total": len(truth_ips), "attacker_ips_recovered": len(truth_ips & found_ips),
        "attack_incidents": len(attack_incidents), "false_incidents": len(false_incidents),
        "merged_into_single_campaign": len(attack_incidents) == 1 and truth_ips <= found_ips,
        "stages_expected": len(truth["stages"]), "stages_found": len(set(truth["stages"]) & stages),
        "exfil_destination_found": exfil_found, "decoys_suppressed": decoys_suppressed,
        "decoys_suppressed_count": sum(1 for k, v in decoys_suppressed.items() if v and truth["decoys_present"].get(k)),
        "decoys_planted": sum(1 for v in truth["decoys_present"].values() if v),
    }
