import joblib
import pytest

from engine.dataset import generate
from engine.ml import VARIANTS, ModelLoadError, PhishingModel, build_variant

_DS = generate(seed=2, per_template=12, per_test_template=4)
_X = [s.text for s in _DS.train]
_Y = [s.label for s in _DS.train]
_G = [s.group for s in _DS.train]
PHISH = "Urgent: your account is suspended, verify your PIN and CNIC http://x.xyz/a"
LEGIT = "Hi team, meeting tomorrow at 3pm in the conference room, bring your updates"


def test_every_variant_trains_and_ranks():
    for v in VARIANTS:
        m = PhishingModel.train(_X, _Y, "t", groups=_G, variant=v)
        assert m.meta.variant == v and m.version.startswith(v)
        assert 0 <= m.predict_proba(LEGIT) < m.predict_proba(PHISH) <= 1, v


def test_default_variant_is_the_old_nb_model():
    m = PhishingModel.train(_X, _Y, "t", groups=_G)
    assert m.meta.variant == "nb-word"


def test_unknown_variant_rejected():
    with pytest.raises(ValueError):
        build_variant("random-forest")


def test_char_variant_survives_roman_urdu_spelling_change():
    m = PhishingModel.train(_X, _Y, "t", groups=_G, variant="lr-char")
    a = m.predict_proba("Aapka JazzCash account block ho gaya, foran apna PIN aur CNIC dein")
    b = m.predict_proba("Aapka JazzCash account block ho gya, fori apna PIN aur CNIC dain")
    assert a > 0.5 and b > 0.5


def test_save_load_roundtrip_lr_word_char(tmp_path):
    m = PhishingModel.train(_X, _Y, "t", groups=_G, variant="lr-word-char")
    path = tmp_path / "m.joblib"
    m.save(path)
    loaded = PhishingModel.load(path)
    assert loaded.meta.variant == "lr-word-char"
    assert loaded.predict_proba(PHISH) == m.predict_proba(PHISH)


def test_old_blob_without_variant_key_still_loads(tmp_path):
    m = PhishingModel.train(_X, _Y, "t", groups=_G)
    path = tmp_path / "old.joblib"
    m.save(path)
    blob = joblib.load(path)
    del blob["meta"]["variant"]  # purane artifacts (bundled model.joblib) mein ye key hoti hi nahi
    joblib.dump(blob, path)
    (tmp_path / "old.joblib.sha256").unlink()
    assert PhishingModel.load(path).meta.variant == "nb-word"


def test_tampered_model_rejected(tmp_path):
    m = PhishingModel.train(_X, _Y, "t", groups=_G)
    path = tmp_path / "m.joblib"
    m.save(path)
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(ModelLoadError):
        PhishingModel.load(path)
