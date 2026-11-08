import random

import numpy as np

from engine.analyzer import blend_base, decide
from engine.compare import pick_winner
from engine.config import EngineConfig
from engine.models import Verdict
from engine.tune_weights import blend_vec, evaluate_config, search


def test_blend_vec_matches_blend_base_everywhere():
    rng = random.Random(0)
    for _ in range(300):
        cfg = EngineConfig(ml_weight=rng.choice([0.0, 0.3, 0.5, 0.8, 1.0]),
                           ml_corroboration_heuristic=rng.choice([10, 20, 30]),
                           ml_cap_without_corroboration=rng.choice([40, 55, 69]))
        h, m = float(rng.randint(0, 100)), round(rng.uniform(0, 100), 1)
        assert abs(float(blend_vec(np.array([h]), np.array([m]), cfg)[0]) - blend_base(h, m, cfg)) < 1e-9
    assert blend_base(42.0, None, EngineConfig()) == 42.0


def test_ml_alone_never_reaches_phishing():
    cfg = EngineConfig()
    assert decide(blend_base(0, 100.0, cfg), cfg) is Verdict.SUSPICIOUS  # corroboration chahiye


def _toy():
    rng = np.random.default_rng(3)
    n = 400
    y = (rng.random(n) < 0.4).astype(int)
    h = np.where(y == 1, rng.normal(55, 15, n), rng.normal(10, 8, n)).clip(0, 100)
    m = np.where(y == 1, rng.normal(85, 10, n), rng.normal(20, 15, n)).clip(0, 100)
    return h.round(), m.round(1), y


def test_search_respects_fpr_limit_and_beats_nothing_worse():
    h, m, y = _toy()
    base = EngineConfig()
    cfg, res, feasible = search(h, m, y, base, max_fpr=0.01, max_sus_fpr=0.1)
    assert feasible and res["fpr_phishing"] <= 0.01 and res["fpr_suspicious_up"] <= 0.1
    cur = evaluate_config(h, m, y, base)
    if cur["fpr_phishing"] <= 0.01:
        assert res["recall_phishing"] >= cur["recall_phishing"]
    assert cfg.suspicious_threshold < cfg.phishing_threshold


def test_search_reports_infeasible_when_limit_impossible():
    rng = np.random.default_rng(1)
    y = np.array([0, 1] * 100)
    h = rng.integers(0, 100, 200).astype(float)
    m = rng.uniform(0, 100, 200).round(1)  # signal bilkul random: 0% FPR aur achha recall mumkin nahi
    _, res, feasible = search(h, m, y, EngineConfig(), max_fpr=0.0, max_sus_fpr=0.0)
    assert (not feasible) or res["recall_phishing"] < 0.3


def test_search_without_ml_only_tunes_thresholds():
    h, _, y = _toy()
    cfg, _, _ = search(h, None, y, EngineConfig(), max_fpr=0.02, max_sus_fpr=0.2)
    assert cfg.ml_weight == EngineConfig().ml_weight


def test_pick_winner_prefers_recall_then_ap():
    rows = [
        {"variant": "a", "recall_at_fpr_1.0%": 0.7, "average_precision": 0.9, "train_seconds": 1.0},
        {"variant": "b", "recall_at_fpr_1.0%": 0.8, "average_precision": 0.8, "train_seconds": 5.0},
        {"variant": "c", "recall_at_fpr_1.0%": 0.8, "average_precision": 0.85, "train_seconds": 9.0},
    ]
    assert pick_winner(rows)["variant"] == "c"
