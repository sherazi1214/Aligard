"""Security-sensitive pure worker decisions stay deterministic and easy to test."""
from backend.app.worker.decision import (
    LABEL,
    NONE,
    QUARANTINE,
    clean_text,
    decide_action,
    sender_domain,
    whitelist_hit,
)


def test_quarantine_requires_verdict_score_and_confidence():
    kwargs = {"suspicious_threshold": 35, "phishing_threshold": 70, "min_confidence": 0.7}
    assert decide_action("SAFE", 99, 1.0, **kwargs) == NONE
    assert decide_action("PHISHING", 90, 0.69, **kwargs) == LABEL
    assert decide_action("PHISHING", 69, 0.99, **kwargs) == LABEL
    assert decide_action("PHISHING", 70, 0.7, **kwargs) == QUARANTINE
    assert decide_action("SUSPICIOUS", 80, 0.99, **kwargs) == LABEL
    assert decide_action("SUSPICIOUS", 34, 0.99, **kwargs) == NONE


def test_whitelist_domain_boundary_and_exact_sender():
    entries = [("domain", "example.com"), ("sender", "trusted@example.net")]
    assert whitelist_hit(entries, "alerts@mail.example.com")
    assert whitelist_hit(entries, "trusted@example.net")
    assert not whitelist_hit(entries, "alerts@evil-example.com")
    assert not whitelist_hit(entries, "trusted@notexample.net")
    assert sender_domain("name@example.com") == "example.com"


def test_clean_text_removes_controls_and_bidi_and_caps_length():
    text = clean_text("hello\nworld\u202e<script>", 12)
    assert "\n" not in text and "\u202e" not in text
    assert len(text) <= 12
