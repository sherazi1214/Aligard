import numpy as np
import pytest

from engine import eval_real as ev


def _toy():
    y = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0])
    p = np.array([0.95, 0.9, 0.8, 0.4, 0.6, 0.2, 0.1, 0.1, 0.05, 0.01])
    return y, p


def test_confusion_known_values():
    y, p = _toy()
    c = ev.confusion(y, p, 0.5)
    assert (c["tp"], c["fp"], c["tn"], c["fn"]) == (3, 1, 5, 1)
    assert c["precision"] == 0.75 and c["recall"] == 0.75
    assert c["false_positive_rate"] == round(1 / 6, 4)


def test_prior_adjusted_precision_known_value():
    # recall 0.95, FPR 2%, prevalence 1%  -> 0.0095 / (0.0095 + 0.0198)
    assert ev.prior_adjusted_precision(0.95, 0.02, 0.01) == pytest.approx(0.0095 / 0.0293, rel=1e-6)
    assert ev.prior_adjusted_precision(1.0, 0.0, 0.01) == 1.0
    assert ev.prior_adjusted_precision(0.0, 0.0, 0.01) == 0.0


def test_precision_at_balanced_prevalence_matches_plain_precision():
    y, p = _toy()
    c = ev.confusion(y, p, 0.5)
    balanced = ev.prior_adjusted_precision(c["recall"], c["false_positive_rate"], 0.5)
    assert balanced == pytest.approx(c["tp"] / (c["tp"] + c["fp"] * (c["tp"] + c["fn"]) / (c["fp"] + c["tn"])), rel=1e-3)


def test_recall_at_fpr_respects_limit():
    y, p = _toy()
    r = ev.recall_at_fpr(y, p, 0.0)
    assert r["achieved_fpr"] == 0.0 and r["threshold"] > 0.6 and r["recall"] == 0.75
    r2 = ev.recall_at_fpr(y, p, 0.2)
    assert r2["achieved_fpr"] <= 0.2 and r2["recall"] >= r["recall"]


def test_build_report_shape_and_prevalence_column():
    y, p = _toy()
    rep = ev.build_report(y, p, prevalence=0.02, ci=False)
    assert rep["n"] == 10 and rep["phishing"] == 4 and 0 <= rep["roc_auc"] <= 1
    assert all("precision_at_prevalence" in r for r in rep["thresholds"])
    assert rep["calibration"] and sum(b["n"] for b in rep["calibration"]) == 10


def test_build_report_rejects_single_class():
    with pytest.raises(ValueError):
        ev.build_report(np.array([1, 1, 1]), np.array([0.9, 0.8, 0.7]))


def test_render_and_update_metrics_md(tmp_path):
    y, p = _toy()
    rep = ev.build_report(y, p, prevalence=0.02, ci=False)
    md = ev.render_markdown(rep, model_version="v1", model_variant="lr-word", data_note="test")
    assert "Threshold curve" in md and "Precision @ 2% phishing" in md and "Calibration" in md
    path = tmp_path / "METRICS.md"
    path.write_text("# Engine metrics\n\nPurani synthetic notes.\n")
    ev.update_metrics_md(md, path)
    first = path.read_text()
    assert "Purani synthetic notes." in first and ev.BEGIN in first and "model version" not in first
    ev.update_metrics_md(md.replace("v1", "v2"), path)
    second = path.read_text()
    assert second.count(ev.BEGIN) == 1 and "`v2`" in second and "`v1`" not in second
    assert "Purani synthetic notes." in second
