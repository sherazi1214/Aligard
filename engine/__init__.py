"""AliGuard detection engine.

    from engine import analyze, EmailInput
    result = analyze(EmailInput(subject="...", text_body="..."))
    result.verdict, result.score, result.reasons

Raw email se: engine.parsing.from_raw_email(bytes). Poora control: engine.analyzer.Engine.
"""
from __future__ import annotations

from engine.analyzer import Engine
from engine.models import AnalysisResult, EmailInput, Verdict

__version__ = "0.1.0"
__all__ = ["AnalysisResult", "EmailInput", "Engine", "Verdict", "analyze"]

_default: Engine | None = None


def analyze(email: EmailInput) -> AnalysisResult:
    """Convenience: bundled ML model + heuristics. Reputation/LLM ke liye Engine(...) banao."""
    global _default
    if _default is None:
        _default = Engine.default()
    return _default.analyze(email)
