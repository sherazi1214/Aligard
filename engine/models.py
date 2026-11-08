"""Engine ke data models. Ye FastAPI se independent hain (web, exe, app sab use karenge)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


@dataclass
class EmailInput:
    """Aik email ki saaf shakal. Saari fields attacker-controlled hain, un par bharosa nahi."""

    subject: str = ""
    sender_name: str = ""
    sender_email: str = ""
    reply_to: str = ""
    text_body: str = ""
    html_body: str = ""
    # (naam, value) ki list, original order mein (upar wala header sab se bharosemand)
    headers: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)  # sirf filenames
    # Asli bytes (size-capped). Sirf analysis ke liye, kabhi store nahi hote.
    attachment_files: list[tuple[str, bytes]] = field(default_factory=list)
    image_files: list[tuple[str, bytes]] = field(default_factory=list)  # inline/attached images (QR ke liye)


@dataclass
class Signal:
    code: str
    layer: str  # "heuristics" | "ml" | "reputation" | "llm"
    points: float
    text: str


@dataclass
class AnalysisResult:
    verdict: Verdict
    score: int  # 0-100
    confidence: float  # 0-1
    reasons: list[str]
    layer_scores: dict[str, float | None]
    signals: list[Signal]
    urls: list[str]
    defanged_urls: list[str]
    degraded: bool = False  # koi layer fail hui (network, rate limit...)
    notes: list[str] = field(default_factory=list)
    model_version: str | None = None
    sandbox_reports: list[dict] = field(default_factory=list)  # RAW (andruni use); API/DB ko postmortem do
    postmortem: dict = field(default_factory=dict)  # defanged, store-safe khulasa

    def to_dict(self) -> dict:
        """JSON-safe dict. UI ko reasons/urls HTML-escape karke hi dikhane hain."""
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "reasons": self.reasons,
            "layer_scores": self.layer_scores,
            "signals": [vars(s) for s in self.signals],
            "urls": self.urls,
            "defanged_urls": self.defanged_urls,
            "degraded": self.degraded,
            "notes": self.notes,
            "model_version": self.model_version,
            "postmortem": self.postmortem,
        }
