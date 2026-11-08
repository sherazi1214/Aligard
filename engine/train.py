"""Training script.
  python -m engine.train                       # synthetic demo data
  python -m engine.train --csv data.csv        # asli data: columns text,label (1/phishing, 0/legit)
Metrics (precision/recall/F1/false-positive-rate) print + JSON mein save hote hain."""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from engine.dataset import generate
from engine.ml import DEFAULT_MODEL_PATH, PhishingModel


def evaluate(model: PhishingModel, texts: list[str], labels: list[int], threshold: float = 0.5) -> dict:
    tp = fp = tn = fn = 0
    for t, y in zip(texts, labels, strict=True):
        pred = model.predict_proba(t) >= threshold
        tp += pred and y == 1
        fp += pred and y == 0
        tn += (not pred) and y == 0
        fn += (not pred) and y == 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(labels), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "threshold": threshold,
    }


def _load_csv(path: str) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            lab = str(row["label"]).strip().lower()
            labels.append(1 if lab in ("1", "phishing", "phish", "spam") else 0)
            texts.append(row["text"])
    return texts, labels


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--out", default=str(DEFAULT_MODEL_PATH))
    ap.add_argument("--metrics", default=str(Path(DEFAULT_MODEL_PATH).with_name("metrics.json")))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    report: dict = {}
    if args.csv:
        texts, labels = _load_csv(args.csv)
        idx = list(range(len(texts)))
        random.Random(args.seed).shuffle(idx)  # noqa: S311
        cut = int(len(idx) * 0.8)
        tr, te = idx[:cut], idx[cut:]
        model = PhishingModel.train([texts[i] for i in tr], [labels[i] for i in tr], f"csv:{args.csv}")
        report["holdout_20pct"] = evaluate(model, [texts[i] for i in te], [labels[i] for i in te])
        report["data_source"] = f"REAL csv: {args.csv}"
    else:
        ds = generate(args.seed)
        model = PhishingModel.train(
            [s.text for s in ds.train], [s.label for s in ds.train],
            "synthetic-templates-v1", groups=[s.group for s in ds.train],
        )
        for name, part in (("unseen_phrasing", ds.test_unseen_phrasing),
                           ("unseen_families", ds.test_unseen_families)):
            report[name] = evaluate(model, [s.text for s in part], [s.label for s in part])
        report["data_source"] = "SYNTHETIC templates: numbers asli duniya ki accuracy NAHI hain"
    digest = model.save(args.out)
    report.update(model_version=model.version, sha256=digest, n_train=model.meta.n_train)
    Path(args.metrics).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
