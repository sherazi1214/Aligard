import json
from pathlib import Path

import joblib
import pytest

from engine.dataset import FAMILIES, HOLDOUT, generate
from engine.ml import ModelLoadError, PhishingModel, prepare_text
from engine.train import evaluate


@pytest.fixture(scope="module")
def small():
    ds = generate(seed=1, per_template=15, per_test_template=5)
    model = PhishingModel.train([s.text for s in ds.train], [s.label for s in ds.train],
                                "test", groups=[s.group for s in ds.train])
    return ds, model


def test_dataset_holdout_families_never_in_train(small):
    ds, _ = small
    train_groups = {s.group.split(":")[0] for s in ds.train}
    assert train_groups == set(FAMILIES)
    assert not train_groups & set(HOLDOUT)
    assert {s.label for s in ds.test_unseen_phrasing} == {0, 1}


def test_dataset_is_deterministic():
    a, b = generate(seed=3, per_template=3), generate(seed=3, per_template=3)
    assert [s.text for s in a.train] == [s.text for s in b.train]


def test_predict_proba_range_and_direction(small):
    _, m = small
    phish = m.predict_proba("Urgent: your account is suspended, verify your PIN and CNIC http://x.xyz/a")
    legit = m.predict_proba("Hi team, meeting tomorrow at 3pm in the conference room")
    assert 0 <= legit < phish <= 1


def test_prepare_text_tokenizes_urls_and_numbers():
    out = prepare_text("Visit HTTP://Evil.com/a?x=1 code 1234567")
    assert "urltoken" in out and "evil" not in out and "longnumtoken" in out


def test_evaluate_metrics_shape(small):
    ds, m = small
    r = evaluate(m, [s.text for s in ds.test_unseen_families], [s.label for s in ds.test_unseen_families])
    assert r["tp"] + r["fp"] + r["tn"] + r["fn"] == r["n"]
    assert 0 <= r["false_positive_rate"] <= 1


def test_save_load_roundtrip(small, tmp_path):
    _, m = small
    path = tmp_path / "m.joblib"
    m.save(path)
    loaded = PhishingModel.load(path)
    assert loaded.version == m.version
    assert loaded.predict_proba("verify your pin now") == m.predict_proba("verify your pin now")


def test_tampered_model_is_rejected_before_loading(small, tmp_path):
    _, m = small
    path = tmp_path / "m.joblib"
    m.save(path)
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(ModelLoadError):
        PhishingModel.load(path)


def test_wrong_expected_hash_and_missing_file(small, tmp_path):
    _, m = small
    path = tmp_path / "m.joblib"
    m.save(path)
    with pytest.raises(ModelLoadError):
        PhishingModel.load(path, expected_sha256="0" * 64)
    with pytest.raises(ModelLoadError):
        PhishingModel.load(tmp_path / "nope.joblib")


def test_sklearn_version_mismatch_rejected(small, tmp_path):
    _, m = small
    path = tmp_path / "m.joblib"
    m.save(path)
    blob = joblib.load(path)
    blob["meta"]["sklearn_version"] = "0.0.1"
    joblib.dump(blob, path)
    Path(str(path) + ".sha256").unlink()
    with pytest.raises(ModelLoadError, match="dobara train"):
        PhishingModel.load(path)


def test_shipped_model_loads_and_has_metrics():
    base = Path(__file__).parent.parent / "engine" / "artifacts"
    m = PhishingModel.load(base / "model.joblib")
    assert m.meta.dataset.startswith("synthetic")
    assert "SYNTHETIC" in json.loads((base / "metrics.json").read_text())["data_source"]
