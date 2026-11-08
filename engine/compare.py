"""Models ka muqabla: NB (purana) vs logistic regression, word vs char n-grams.

  python -m engine.compare --data data/ --save engine/artifacts/model.joblib

Usool: model ka intikhab sirf VALIDATION par hota hai. Test set is script mein kabhi nahi chhuta
jata (warna test par "behtar nikalne wala" model usi test ke liye chuna gaya hota aur uska number
jhoota hota). --save ke baad winner ko train+val par dobara train karke save karta hai; test ka
natija phir `python -m engine.eval_real` se aata hai."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from engine.corpus import load_split
from engine.eval_real import build_report, recall_at_fpr, score_records
from engine.ml import VARIANTS, PhishingModel


def compare(train, val, variants=VARIANTS, fpr_target: float = 0.01) -> list[dict]:
    rows = []
    for v in variants:
        t0 = time.time()
        groups = [r.group for r in train] if all(r.group for r in train) else None
        model = PhishingModel.train([r.text for r in train], [r.label for r in train],
                                    "compare", groups=groups, variant=v)
        y, p = score_records(model, val)
        rep = build_report(y, p, ci=False)
        rec = recall_at_fpr(y, p, fpr_target)
        rows.append({
            "variant": v, "roc_auc": rep["roc_auc"], "average_precision": rep["average_precision"],
            "brier": rep["brier"], f"recall_at_fpr_{fpr_target:.1%}": rec["recall"] or 0.0,
            "threshold_for_that": rec["threshold"], "train_seconds": round(time.time() - t0, 1),
        })
    return rows


def pick_winner(rows: list[dict], fpr_target: float = 0.01) -> dict:
    """Sab se ooncha recall@FPR; barabari par average precision, phir sasta (kam features) model."""
    key = f"recall_at_fpr_{fpr_target:.1%}"
    return max(rows, key=lambda r: (r[key], r["average_precision"], -r["train_seconds"]))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--variants", nargs="+", default=list(VARIANTS), choices=VARIANTS)
    ap.add_argument("--fpr-target", type=float, default=0.01)
    ap.add_argument("--save", help="winner ko train+val par dobara train karke yahan save karo")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    split = load_split(args.data)
    if len(split.val) < 50:
        print(f"WARNING: val mein sirf {len(split.val)} emails hain; muqabla bharosemand nahi")
    rows = compare(split.train, split.val, args.variants, args.fpr_target)
    winner = pick_winner(rows, args.fpr_target)
    key = f"recall_at_fpr_{args.fpr_target:.1%}"
    print(f"{'variant':14}{'AUC':>8}{'AP':>8}{'Brier':>8}{key:>22}{'sec':>7}")
    for r in rows:
        mark = " <- winner" if r is winner else ""
        print(f"{r['variant']:14}{r['roc_auc']:>8}{r['average_precision']:>8}{r['brier']:>8}{r[key]:>22}"
              f"{r['train_seconds']:>7}{mark}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"rows": rows, "winner": winner["variant"]}, indent=2))
    if args.save:
        full = split.train + split.val
        groups = [r.group for r in full] if all(r.group for r in full) else None
        model = PhishingModel.train([r.text for r in full], [r.label for r in full],
                                    f"corpus:{args.data}", groups=groups, variant=winner["variant"])
        digest = model.save(args.save)
        print(f"\n{winner['variant']} (train+val, n={len(full)}) -> {args.save}\nsha256 {digest}")
        print("Ab test par naapo:  python -m engine.eval_real --data", args.data, "--model", args.save,
              "--write-metrics")


if __name__ == "__main__":
    main()
