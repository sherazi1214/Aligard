"""ML vs heuristics ka wazan (wohi 40/60 wala sawal) aur thresholds andaze se nahi, data se chunna.

  python -m engine.tune_weights --data data/ --model engine/artifacts/model.joblib \\
      --max-fpr 0.005 --max-suspicious-fpr 0.05 --prevalence 0.02

Kya tune hota hai (sab bina network, bilkul offline):
  ml_weight, phishing_threshold, suspicious_threshold, ml_cap_without_corroboration,
  ml_corroboration_heuristic.
Kya tune NAHI hota: reputation / sandbox / domain-age / LLM. Wo network par chalte hain aur unke
outputs CSV mein nahi hote. Unka wazan tab chun sakte hain jab worker asli mails par har layer ka
score log kare (agla qadam); tab tak unke points (config.py) sakht aur ehtiyaat wale rakhne chahiye.

Intikhab VALIDATION par, uska natija TEST par sirf aik baar (tuned config vs maujooda config).
Shart: legit -> PHISHING (auto-quarantine) ka FPR hadd ke andar, phir recall sab se zyada."""
from __future__ import annotations

import argparse
import itertools
import json
from dataclasses import asdict, replace
from pathlib import Path

import numpy as np

from engine.analyzer import blend_base
from engine.config import EngineConfig
from engine.corpus import Record, load_split
from engine.eval_real import prior_adjusted_precision
from engine.heuristics import score_heuristics
from engine.ml import DEFAULT_MODEL_PATH, PhishingModel
from engine.models import EmailInput
from engine.parsing import build_content

GRID = {
    "ml_weight": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 1.0],
    "phishing_threshold": [50, 55, 60, 65, 70, 75, 80, 85, 90],
    "suspicious_threshold": [20, 25, 30, 35, 40, 45, 50],
    "ml_cap_without_corroboration": [40, 55, 69],
    "ml_corroboration_heuristic": [10, 20, 30],
}
TUNED_FIELDS = tuple(GRID)


def layer_scores(records: list[Record], model: PhishingModel | None,
                 cfg: EngineConfig | None = None) -> tuple[np.ndarray, np.ndarray | None, np.ndarray]:
    """(heuristics 0-100, ml 0-100 ya None, labels). Har email par sirf aik baar (grid ke liye cache)."""
    cfg = cfg or EngineConfig()
    h, m, y = [], [], []
    for r in records:
        subject, _, body = r.text.partition("\n")
        email = EmailInput(subject=subject, text_body=body or subject)
        content = build_content(email, cfg.max_body_chars)
        h_score, _signals, _auth = score_heuristics(email, content, cfg)
        h.append(h_score)
        if model:
            m.append(round(model.predict_proba(f"{email.subject}\n{content.text}") * 100, 1))
        y.append(r.label)
    return np.array(h, float), (np.array(m, float) if model else None), np.array(y)


def blend_vec(h: np.ndarray, m: np.ndarray | None, cfg: EngineConfig) -> np.ndarray:
    """blend_base ka numpy version (grid tez karne ke liye). tests/test_tune_weights.py check karta hai
    ke ye blend_base se hamesha barabar hai, taake formula do jagah alag na ho jaye."""
    if m is None:
        return h.copy()
    base = (1 - cfg.ml_weight) * h + cfg.ml_weight * m
    base = np.where(h >= cfg.heuristic_strong, np.maximum(base, h), base)
    return np.where(h < cfg.ml_corroboration_heuristic, np.minimum(base, float(cfg.ml_cap_without_corroboration)), base)


def evaluate_config(h: np.ndarray, m: np.ndarray | None, y: np.ndarray, cfg: EngineConfig) -> dict:
    score = np.clip(np.rint(blend_vec(h, m, cfg)), 0, 100)
    phish = score >= cfg.phishing_threshold
    sus_up = score >= cfg.suspicious_threshold
    pos, neg = y == 1, y == 0
    n_pos, n_neg = max(int(pos.sum()), 1), max(int(neg.sum()), 1)
    return {
        "recall_phishing": float((phish & pos).sum() / n_pos),
        "recall_suspicious_up": float((sus_up & pos).sum() / n_pos),
        "fpr_phishing": float((phish & neg).sum() / n_neg),
        "fpr_suspicious_up": float((sus_up & neg).sum() / n_neg),
        "tp": int((phish & pos).sum()), "fp": int((phish & neg).sum()),
        "n_pos": n_pos, "n_neg": n_neg,
    }


def search(h: np.ndarray, m: np.ndarray | None, y: np.ndarray, base_cfg: EngineConfig,
           max_fpr: float, max_sus_fpr: float) -> tuple[EngineConfig, dict, bool]:
    """(best config, uske val metrics, feasible). feasible=False ho to koi config hadd mein nahi aayi
    aur sab se kam FPR wali di gayi hai."""
    grid = dict(GRID)
    if m is None:  # ML nahi to ml_* parameters ka koi asar nahi
        grid = {k: v for k, v in grid.items() if not k.startswith("ml_")}
    names = list(grid)
    best = best_infeasible = None
    for combo in itertools.product(*(grid[n] for n in names)):
        kw = dict(zip(names, combo, strict=True))
        if kw["suspicious_threshold"] >= kw["phishing_threshold"]:
            continue
        cfg = replace(base_cfg, **kw)
        res = evaluate_config(h, m, y, cfg)
        # tie-break: kam badlav (maujooda config ke qareeb) ko tarjeeh
        changes = sum(getattr(cfg, k) != getattr(base_cfg, k) for k in names)
        if res["fpr_phishing"] <= max_fpr and res["fpr_suspicious_up"] <= max_sus_fpr:
            key = (res["recall_phishing"], res["recall_suspicious_up"], -changes)
            if best is None or key > best[0]:
                best = (key, cfg, res)
        else:
            key = (-res["fpr_phishing"], -res["fpr_suspicious_up"], res["recall_phishing"])
            if best_infeasible is None or key > best_infeasible[0]:
                best_infeasible = (key, cfg, res)
    if best is not None:
        return best[1], best[2], True
    return best_infeasible[1], best_infeasible[2], False


def describe(res: dict, prevalence: float | None) -> str:
    s = (f"recall(PHISHING) {res['recall_phishing']:.3f}, recall(SUSPICIOUS+) {res['recall_suspicious_up']:.3f}, "
         f"FPR(PHISHING) {res['fpr_phishing']:.4f} ({res['fp']}/{res['n_neg']}), "
         f"FPR(SUSPICIOUS+) {res['fpr_suspicious_up']:.4f}")
    if prevalence:
        s += (f", precision @ {prevalence:.0%} phishing "
              f"{prior_adjusted_precision(res['recall_phishing'], res['fpr_phishing'], prevalence):.3f}")
    return s


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    ap.add_argument("--no-ml", action="store_true", help="ML ke baghair (sirf heuristics) tune karo")
    ap.add_argument("--max-fpr", type=float, default=0.005, help="legit -> PHISHING ki hadd (default 0.5%%)")
    ap.add_argument("--max-suspicious-fpr", type=float, default=0.05, help="legit -> SUSPICIOUS+ ki hadd (default 5%%)")
    ap.add_argument("--prevalence", type=float, default=0.02)
    ap.add_argument("--json-out", help="chuni hui config yahan JSON mein likho")
    args = ap.parse_args(argv)

    split = load_split(args.data)
    model = None if args.no_ml else PhishingModel.load(args.model)
    base_cfg = EngineConfig()
    hv, mv, yv = layer_scores(split.val, model, base_cfg)
    cfg, val_res, feasible = search(hv, mv, yv, base_cfg, args.max_fpr, args.max_suspicious_fpr)
    if not feasible:
        limits = f"{args.max_fpr:.2%}/{args.max_suspicious_fpr:.2%}"
        print(f"WARNING: val par koi config FPR hadd ({limits}) mein nahi aayi; "
              "sab se kam FPR wali dikha raha hoon. Model/data behtar karo ya hadd dheeli karo.\n")
    ht, mt, yt = layer_scores(split.test, model, base_cfg)
    cur_test = evaluate_config(ht, mt, yt, base_cfg)
    new_test = evaluate_config(ht, mt, yt, cfg)

    print("NOTE: corpus CSV mein sirf text hota hai (headers, SPF/DKIM/DMARC, reply-to, HTML anchors nahi), is liye "
          "heuristics ke kai strong signals yahan chalte hi nahi aur tuning ML ki taraf jhuk sakti hai. Behtar: apni "
          "reported phishing/legit mails ko raw .eml se naapo (engine.parsing.from_raw_email) "
          "aur nateeja usi se parkho.\n")
    changed = {k: getattr(cfg, k) for k in TUNED_FIELDS if hasattr(cfg, k) and (model or not k.startswith("ml_"))}
    print("Chuni hui config (val par):", json.dumps(changed))
    print("\nVAL  (intikhab yahan hua)")
    print("  maujooda:", describe(evaluate_config(hv, mv, yv, base_cfg), args.prevalence))
    print("  tuned   :", describe(val_res, args.prevalence))
    print("\nTEST (aik baar, intikhab mein shamil nahi)")
    print("  maujooda:", describe(cur_test, args.prevalence))
    print("  tuned   :", describe(new_test, args.prevalence))
    if new_test["fpr_phishing"] > args.max_fpr:
        print(f"\nNOTE: test par tuned FPR(PHISHING) {new_test['fpr_phishing']:.4f} hadd {args.max_fpr} se oopar hai: "
              "val par fit hone ka asar, ya test chhota hai. Config ko is par bharosa karke mat lagao.")
    print("\nengine/config.py mein lagane ke liye:")
    for k, v in changed.items():
        print(f"    {k}: {type(getattr(base_cfg, k)).__name__} = {v!r}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"config": changed, "val": val_res, "test": new_test, "test_current": cur_test,
             "feasible_on_val": feasible, "base_config": {k: v for k, v in asdict(base_cfg).items()
                                                          if k in TUNED_FIELDS}}, indent=2))


if __name__ == "__main__":
    main()
