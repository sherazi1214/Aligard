"""Layer 1: TF-IDF + Naive Bayes (calibrated probabilities). joblib se save/load, hash verify."""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion

from engine.urls import URL_RE

log = logging.getLogger("engine.ml")
DEFAULT_MODEL_PATH = Path(__file__).parent / "artifacts" / "model.joblib"
_NUM_RE = re.compile(r"\d{4,}")


class ModelLoadError(Exception):
    pass


def prepare_text(text: str) -> str:
    """URLs aur lambe numbers ko tokens se badal do, taake model alfaz seekhe, specific links nahi."""
    text = URL_RE.sub(" urltoken ", (text or "")[:20_000].lower())
    return " ".join(_NUM_RE.sub(" longnumtoken ", text).split())


@dataclass
class ModelMeta:
    version: str
    trained_at: str
    dataset: str
    n_train: int
    sklearn_version: str
    variant: str = "nb-word"  # purane model.joblib mein ye key nahi hoti, default se load chalta rahega


VARIANTS = ("nb-word", "lr-word", "lr-char", "lr-word-char")


def build_variant(variant: str):
    """(vectorizer, base_classifier). char_wb n-grams Roman Urdu ki spelling ke farq
    (\"foran\"/\"fori\", \"inaam\"/\"inam\") ko behtar sambhalte hain kyunke wo lafz ke tukron par chalte hain."""
    def word():
        return TfidfVectorizer(max_features=20000, ngram_range=(1, 2), sublinear_tf=True, min_df=2)

    def char():
        return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True,
                               min_df=3, max_features=60000)

    def lr():
        # class_weight=balanced: asli data mein phishing kam hoti hai, model sirf majority na seekhe
        return LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")

    if variant == "nb-word":  # purana (bundled) model: 5000 features, NB
        return (TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True, min_df=2),
                MultinomialNB(alpha=0.5))
    if variant == "lr-word":
        return word(), lr()
    if variant == "lr-char":
        return char(), lr()
    if variant == "lr-word-char":
        return FeatureUnion([("word", word()), ("char", char())]), lr()
    raise ValueError(f"unknown variant {variant!r}; choose from {VARIANTS}")


class PhishingModel:
    def __init__(self, vectorizer, classifier, meta: ModelMeta) -> None:
        self._vec, self._clf, self.meta = vectorizer, classifier, meta

    @property
    def version(self) -> str:
        return self.meta.version

    def predict_proba(self, text: str) -> float:
        """Probability ke message phishing hai (0-1)."""
        x = self._vec.transform([prepare_text(text)])
        return float(self._clf.predict_proba(x)[0][1])

    @classmethod
    def train(cls, texts: list[str], labels: list[int], dataset: str,
              groups: list[str] | None = None, variant: str = "nb-word") -> PhishingModel:
        """variant: VARIANTS mein se koi. Default 'nb-word' purana behaviour hai (bundled model wohi)."""
        prepared = [prepare_text(t) for t in texts]
        vec, base = build_variant(variant)
        x = vec.fit_transform(prepared)
        # groups mile (template families / near-duplicate clusters) to calibration unhi par group-wise
        # hoti hai, warna wohi template train aur calibration dono mein aa kar overconfidence deta hai.
        cv = list(GroupKFold(n_splits=3).split(x, labels, groups)) if groups else 3
        clf = CalibratedClassifierCV(base, method="sigmoid", cv=cv)
        clf.fit(x, labels)
        now = datetime.now(UTC)
        meta = ModelMeta(
            version=f"{variant}-{now:%Y%m%d%H%M}", trained_at=now.isoformat(), dataset=dataset,
            n_train=len(texts), sklearn_version=sklearn.__version__, variant=variant,
        )
        return cls(vec, clf, meta)

    def save(self, path: str | Path) -> str:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"vectorizer": self._vec, "classifier": self._clf,
                     "meta": asdict(self.meta)}, path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        Path(str(path) + ".sha256").write_text(digest + "\n")
        return digest

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH,
             expected_sha256: str | None = None) -> PhishingModel:
        """joblib/pickle load code chala sakta hai, isliye pehle hash verify. Production mein
        expected_sha256 config/env se do (sidecar file wahi attacker badal sakta hai jo model)."""
        path = Path(path)
        if not path.exists():
            raise ModelLoadError(f"model file nahi mili: {path}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        sidecar = Path(str(path) + ".sha256")
        expected = expected_sha256 or (sidecar.read_text().strip() if sidecar.exists() else None)
        if expected is None:
            log.warning("Model hash verify nahi hua (koi expected hash nahi)")
        elif actual != expected:
            raise ModelLoadError("model file ka hash match nahi karta, load nahi karenge")
        blob = joblib.load(path)
        meta = ModelMeta(**blob["meta"])
        if meta.sklearn_version != sklearn.__version__:
            raise ModelLoadError(
                f"model sklearn {meta.sklearn_version} se bana, ab {sklearn.__version__} hai: "
                "dobara train karo"
            )
        return cls(blob["vectorizer"], blob["classifier"], meta)
