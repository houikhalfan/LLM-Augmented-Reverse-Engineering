"""
scorer.py  —  Recall & Precision against ground truth
Sujet 2.2 : LLM-Augmented Reverse Engineering

Usage:
    python scorer.py <samples_dir> <ground_truth_dir>
"""

import os
import json
import sys
from pathlib import Path
from extractor import extract


def score_sample(predicted: dict, truth: dict) -> dict:
    scores = {}
    for ioc_type in ["ips", "domains", "registry_keys"]:
        pred  = set(predicted.get(ioc_type, []))
        gt    = set(truth.get("iocs", {}).get(ioc_type, []))

        tp = len(pred & gt)
        fp = len(pred - gt)
        fn = len(gt  - pred)

        recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

        scores[ioc_type] = {
            "recall":    round(recall,    3),
            "precision": round(precision, 3),
            "TP": tp, "FP": fp, "FN": fn,
            "expected":  sorted(gt),
            "found":     sorted(pred),
            "missed":    sorted(gt - pred),
            "false_pos": sorted(pred - gt),
        }
    return scores


def run(samples_dir: str, gt_dir: str):
    samples_dir = Path(samples_dir)
    gt_dir      = Path(gt_dir)

    c_files = sorted(samples_dir.glob("*.c"))
    if not c_files:
        print(f"No .c files found in {samples_dir}")
        return

    all_results = []
    total_tp = total_fp = total_fn = 0

    print(f"\n{'='*70}")
    print(f"  IoC EXTRACTOR — SCORING REPORT")
    print(f"{'='*70}\n")

    for c_file in c_files:
        gt_file = gt_dir / (c_file.stem + ".json")
        if not gt_file.exists():
            print(f"  [SKIP] No ground truth for {c_file.name}")
            continue

        predicted = extract(str(c_file))
        with open(gt_file) as f:
            truth = json.load(f)

        scores = score_sample(predicted, truth)
        obfuscation = truth.get("obfuscation", "unknown")

        print(f"  ── {c_file.name}  [{obfuscation}]")
        for ioc_type, s in scores.items():
            status = "✅" if s["recall"] == 1.0 else "❌"
            print(f"     {status} {ioc_type:<15} "
                  f"recall={s['recall']:.0%}  precision={s['precision']:.0%}  "
                  f"TP={s['TP']} FP={s['FP']} FN={s['FN']}")
            if s["missed"]:
                print(f"        MISSED    : {s['missed']}")
            if s["false_pos"]:
                print(f"        FALSE POS : {s['false_pos']}")

        # accumulate totals
        for s in scores.values():
            total_tp += s["TP"]
            total_fp += s["FP"]
            total_fn += s["FN"]

        all_results.append({"file": c_file.name, "obfuscation": obfuscation, "scores": scores})
        print()

    # ── global summary ────────────────────────────────────────────────────────
    g_recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    g_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0

    print(f"{'─'*70}")
    print(f"  GLOBAL  recall={g_recall:.1%}   precision={g_precision:.1%}   "
          f"(TP={total_tp}  FP={total_fp}  FN={total_fn})")
    print(f"{'='*70}\n")

    # save full report
    report = {
        "global": {"recall": round(g_recall,3), "precision": round(g_precision,3),
                   "TP": total_tp, "FP": total_fp, "FN": total_fn},
        "samples": all_results
    }
    out = Path("scoring_report.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"  Full report saved → {out}\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scorer.py <samples_dir> <ground_truth_dir>")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2])
