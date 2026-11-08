"""Asli data par evaluation: precision / recall / false-positive rate, har threshold ka curve,
aur asli inbox ke prior (1-2% phishing) ke hisaab se adjust ki hui precision.

  python -m engine.eval_real --data data/ --model engine/artifacts/model.joblib
  python -m engine.eval_real --data data/ --model ... --prevalence 0.02 --write-metrics

Test set ko sirf yahi script chhooti hai (training/selection val par hoti hai). --write-metrics
engine/METRICS.md ka `REAL-METRICS` hissa dobara likhta hai; sirf synthetic data par ye mana hai."""
from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

from engine.corpus import Record, load_split
from engine.ml import DEFAULT_MODEL_PATH, PhishingModel

METRICS_MD = Path(__file__).with_name("METRICS.md")
BEGIN = "<!-- BEGIN REAL-METRICS (auto: python -m engine.eval_real --write-metrics) -->"
END = "<!-- END REAL-METRICS -->"
DEFAULT_THRESHOLDS = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99)
FPR_TARGETS = (0.05, 0.02, 0.01, 0.005, 0.001)


# ------------------------------------------------------------------ metrics
def confusion(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = p >= threshold
    tp = int(np.sum(pred & (y == 1)))
    fp = int(np.sum(pred & (y == 0)))
    tn = int(np.sum(~pred & (y == 0)))
    fn = int(np.sum(~pred & (y == 1)))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "false_positive_rate": round(fpr, 4)}


def prior_adjusted_precision(recall: float, fpr: float, prevalence: float) -> float:
    """Precision agar asli inbox mein phishing ka hissa `prevalence` hota (Bayes). Test set 50/50 ya
    kuch aur ho, recall (TPR) aur FPR badalte nahi: sirf precision badalti hai.
    Misal: recall 0.95, FPR 2%, prevalence 1%  ->  precision sirf ~32%."""
    tp, fp = recall * prevalence, fpr * (1 - prevalence)
    return tp / (tp + fp) if tp + fp else 0.0


def recall_at_fpr(y: np.ndarray, p: np.ndarray, target_fpr: float) -> dict:
    """Sab se ooncha recall jo FPR <= target par mile (aur wo threshold)."""
    neg = p[y == 0]
    pos = p[y == 1]
    if len(neg) == 0 or len(pos) == 0:
        return {"target_fpr": target_fpr, "recall": None, "threshold": None, "achieved_fpr": None}
    best = {"target_fpr": target_fpr, "recall": 0.0, "threshold": 1.0, "achieved_fpr": 0.0}
    for t in sorted(set(p.tolist())):
        fpr = float(np.mean(neg >= t))
        if fpr <= target_fpr:
            rec = float(np.mean(pos >= t))
            if rec > best["recall"]:
                best = {"target_fpr": target_fpr, "recall": round(rec, 4),
                        "threshold": round(t, 4), "achieved_fpr": round(fpr, 4)}
    return best


def calibration_bins(y: np.ndarray, p: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0, 1, bins + 1)
    out = []
    for lo, hi in zip(edges[:-1], edges[1:], strict=True):
        mask = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if mask.any():
            out.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(mask.sum()),
                        "mean_predicted": round(float(p[mask].mean()), 3),
                        "actual_phishing": round(float(y[mask].mean()), 3)})
    return out


def bootstrap_ci(y: np.ndarray, p: np.ndarray, fn, n: int = 300, seed: int = 0) -> tuple[float, float]:
    """95% interval (records par bootstrap). Chhote test set par ye interval aksar bohat chora nikalta hai:
    asal sabaq wohi hai, point estimate par zyada bharosa mat karo."""
    rng = random.Random(seed)  # noqa: S311
    idx = list(range(len(y)))
    vals = []
    for _ in range(n):
        s = [rng.choice(idx) for _ in idx]
        ys, ps = y[s], p[s]
        if ys.min() == ys.max():
            continue
        vals.append(fn(ys, ps))
    if not vals:
        return (float("nan"), float("nan"))
    return (round(float(np.percentile(vals, 2.5)), 4), round(float(np.percentile(vals, 97.5)), 4))


def build_report(y: np.ndarray, p: np.ndarray, prevalence: float | None = None,
                 thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS, ci: bool = True) -> dict:
    if len(y) == 0 or y.min() == y.max():
        raise ValueError("test set mein dono classes (phishing aur legit) chahiye")
    rows = []
    for t in thresholds:
        row = confusion(y, p, t)
        if prevalence is not None:
            row["precision_at_prevalence"] = round(
                prior_adjusted_precision(row["recall"], row["false_positive_rate"], prevalence), 4)
        rows.append(row)
    report = {
        "n": int(len(y)), "phishing": int(y.sum()), "legit": int((y == 0).sum()),
        "test_phishing_share": round(float(y.mean()), 4), "prevalence_assumed": prevalence,
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "average_precision": round(float(average_precision_score(y, p)), 4),
        "brier": round(float(brier_score_loss(y, p)), 4),
        "thresholds": rows,
        "recall_at_fpr": [recall_at_fpr(y, p, f) for f in FPR_TARGETS],
        "calibration": calibration_bins(y, p),
    }
    if ci:
        report["roc_auc_ci95"] = bootstrap_ci(y, p, roc_auc_score)
    return report


def score_records(model: PhishingModel, records: list[Record]) -> tuple[np.ndarray, np.ndarray]:
    y = np.array([r.label for r in records])
    p = np.array([model.predict_proba(r.text) for r in records])
    return y, p


# ------------------------------------------------------------------ full engine (ML + heuristics)
def engine_report(model: PhishingModel | None, records: list[Record], config=None) -> dict:
    """Poora engine (ML + heuristics) bina network. CSV mein sirf text hota hai: headers, SPF/DKIM/DMARC aur
    attachments nahi, isliye heuristics ki kai strong signals (auth fail, reply-to mismatch) yahan nahi chalte.
    Engine ki asli accuracy is se behtar ya mukhtalif ho sakti hai: raw .eml par evaluate karna ideal hai."""
    from engine.analyzer import Engine
    from engine.config import EngineConfig
    from engine.models import EmailInput, Verdict

    eng = Engine(config=config or EngineConfig(), model=model)
    counts = {"phish_as_phishing": 0, "phish_as_suspicious": 0, "phish_as_safe": 0,
              "legit_as_phishing": 0, "legit_as_suspicious": 0, "legit_as_safe": 0}
    for r in records:
        subject, _, body = r.text.partition("\n")
        v = eng.analyze(EmailInput(subject=subject, text_body=body or subject)).verdict
        key = {Verdict.PHISHING: "phishing", Verdict.SUSPICIOUS: "suspicious", Verdict.SAFE: "safe"}[v]
        counts[f"{'phish' if r.label else 'legit'}_as_{key}"] += 1
    ph = counts["phish_as_phishing"] + counts["phish_as_suspicious"] + counts["phish_as_safe"]
    lg = counts["legit_as_phishing"] + counts["legit_as_suspicious"] + counts["legit_as_safe"]
    counts.update(
        n=len(records),
        recall_phishing_verdict=round(counts["phish_as_phishing"] / ph, 4) if ph else None,
        recall_suspicious_or_above=round((ph - counts["phish_as_safe"]) / ph, 4) if ph else None,
        fpr_phishing_verdict=round(counts["legit_as_phishing"] / lg, 4) if lg else None,
        fpr_suspicious_or_above=round((lg - counts["legit_as_safe"]) / lg, 4) if lg else None,
    )
    return counts


# ------------------------------------------------------------------ METRICS.md
def render_markdown(report: dict, *, model_version: str, model_variant: str, data_note: str,
                    engine: dict | None = None, when: datetime | None = None) -> str:
    when = when or datetime.now(UTC)
    lines = [
        f"## ASLI DATA metrics (auto-generated {when:%Y-%m-%d %H:%M} UTC)",
        "",
        f"Model: `{model_version}` ({model_variant}). Data: {data_note}.",
        f"Test set: n={report['n']} ({report['phishing']} phishing, {report['legit']} legit; "
        f"phishing share {report['test_phishing_share']:.1%}). "
        f"ROC AUC {report['roc_auc']}" + (f" (95% CI {report['roc_auc_ci95'][0]}-{report['roc_auc_ci95'][1]})"
                                         if "roc_auc_ci95" in report else "")
        + f", average precision {report['average_precision']}, Brier {report['brier']}.",
        "",
        "### Threshold curve (sirf ML layer)",
    ]
    prev = report.get("prevalence_assumed")
    head = "| Threshold | Precision | Recall | False-positive rate | TP | FP | TN | FN |"
    sep = "|---|---|---|---|---|---|---|---|"
    if prev is not None:
        head += f" Precision @ {prev:.0%} phishing |"
        sep += "---|"
    lines += [head, sep]
    for r in report["thresholds"]:
        row = (f"| {r['threshold']} | {r['precision']} | {r['recall']} | {r['false_positive_rate']} | "
               f"{r['tp']} | {r['fp']} | {r['tn']} | {r['fn']} |")
        if prev is not None:
            row += f" {r['precision_at_prevalence']} |"
        lines.append(row)
    lines += ["", "### Recall jab false-positive rate ek hadd se neeche rakhna ho",
              "| FPR hadd | Recall | Threshold | Asal FPR |", "|---|---|---|---|"]
    for r in report["recall_at_fpr"]:
        lines.append(f"| {r['target_fpr']:.1%} | {r['recall']} | {r['threshold']} | {r['achieved_fpr']} |")
    lines += ["", "### Calibration (predicted bhi asli kitni phishing nikli)",
              "| Bin | n | Mean predicted | Asli phishing share |", "|---|---|---|---|"]
    for b in report["calibration"]:
        lines.append(f"| {b['bin']} | {b['n']} | {b['mean_predicted']} | {b['actual_phishing']} |")
    if engine:
        lines += ["", "### Poora engine (ML + heuristics, bina network/headers)",
                  f"n={engine['n']}. Phishing mails: PHISHING {engine['phish_as_phishing']}, "
                  f"SUSPICIOUS {engine['phish_as_suspicious']}, SAFE {engine['phish_as_safe']}. "
                  f"Legit mails: PHISHING {engine['legit_as_phishing']}, SUSPICIOUS {engine['legit_as_suspicious']}, "
                  f"SAFE {engine['legit_as_safe']}.",
                  f"Recall (PHISHING verdict) {engine['recall_phishing_verdict']}, "
                  f"FPR (PHISHING verdict) {engine['fpr_phishing_verdict']}, "
                  f"FPR (SUSPICIOUS ya upar) {engine['fpr_suspicious_or_above']}."]
    lines += ["", "> Ye numbers sirf is test set ke hain. Naye campaigns/templates aane par accuracy gir sakti hai; "
                  "isliye source-level split (`--test-source`) bhi chalao."]
    return "\n".join(lines)


def update_metrics_md(section: str, path: str | Path = METRICS_MD) -> None:
    """BEGIN/END markers ke beech wala hissa badalta hai (pehli baar markers khud lagata hai).
    Baqi file (synthetic wali purani notes) jas ki tas rehti hai."""
    path = Path(path)
    text = path.read_text() if path.exists() else "# Engine metrics\n"
    block = f"{BEGIN}\n{section}\n{END}"
    if BEGIN in text and END in text:
        head, rest = text.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        text = head + block + tail
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    path.write_text(text)


# ------------------------------------------------------------------ CLI
def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="corpus build ka output folder (train/val/test.csv + manifest)")
    ap.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    ap.add_argument("--split", choices=["test", "val"], default="test")
    ap.add_argument("--prevalence", type=float, default=0.02,
                    help="asli inbox mein phishing ka hissa (default 0.02); 0 do to adjustment band")
    ap.add_argument("--engine", action="store_true", help="poora engine (ML + heuristics) bhi naapo")
    ap.add_argument("--write-metrics", action="store_true", help="engine/METRICS.md ka REAL-METRICS hissa update karo")
    ap.add_argument("--metrics-md", default=str(METRICS_MD))
    ap.add_argument("--json-out")
    ap.add_argument("--allow-synthetic", action="store_true")
    args = ap.parse_args(argv)

    split = load_split(args.data)
    records = getattr(split, args.split)
    sources = sorted({r.source for r in records})
    if args.write_metrics and not args.allow_synthetic and any("synthetic" in s.lower() for s in sources):
        raise SystemExit("test mein synthetic data hai: asli metrics ke taur par METRICS.md mein nahi likhunga "
                         "(--allow-synthetic sirf smoke test ke liye)")
    model = PhishingModel.load(args.model)
    y, p = score_records(model, records)
    prevalence = args.prevalence or None
    report = build_report(y, p, prevalence)
    engine = engine_report(model, records) if args.engine else None
    print(json.dumps({"report": report, "engine": engine}, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"report": report, "engine": engine}, indent=2))
    if args.write_metrics:
        note = f"{args.split} split of {args.data}, sources: {', '.join(sources)}"
        update_metrics_md(render_markdown(report, model_version=model.version,
                                          model_variant=model.meta.variant, data_note=note, engine=engine),
                          args.metrics_md)
        print(f"\n{args.metrics_md} update ho gayi")


if __name__ == "__main__":
    main()
