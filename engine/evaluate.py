"""python -m engine.evaluate : bundled ML + heuristics ko hand-written samples par chalao."""
from __future__ import annotations

from engine.analyzer import Engine
from engine.eval_samples import SAMPLES
from engine.models import Verdict


def run(engine: Engine | None = None, verbose: bool = True) -> dict:
    engine = engine or Engine.default()
    tp = fp = tn = fn = 0
    sus_legit = 0
    rows = []
    for label, name, email in SAMPLES:
        r = engine.analyze(email)
        flagged = r.verdict is Verdict.PHISHING  # sirf PHISHING = auto-quarantine wali category
        tp += flagged and label == 1
        fn += (not flagged) and label == 1
        fp += flagged and label == 0
        tn += (not flagged) and label == 0
        sus_legit += r.verdict is Verdict.SUSPICIOUS and label == 0
        ok = flagged == bool(label)
        rows.append((ok, label, name, r.verdict.value, r.score, r.layer_scores))
    if verbose:
        print(f"{'':3}{'expected':9}{'sample':32}{'verdict':11}{'score':>5}  ml / heuristics")
        for ok, label, name, verdict, score, ls in rows:
            mark = "OK" if ok else "!!"
            ml = "-" if ls["ml"] is None else f"{ls['ml']:.0f}"
            print(f"{mark:3}{'phish' if label else 'legit':9}{name:32}{verdict:11}{score:>5}  "
                  f"{ml} / {ls['heuristics']:.0f}")
    n = len(SAMPLES)
    summary = {
        "n": n, "accuracy": round((tp + tn) / n, 3), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
        "legit_marked_suspicious": sus_legit,
    }
    if verbose:
        print("\n", summary)
        print("(Note: sirf 18 haath se likhe samples: sanity check hai, asli accuracy nahi)")
    return summary


if __name__ == "__main__":
    run()
