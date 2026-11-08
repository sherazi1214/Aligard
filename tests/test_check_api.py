"""POST /api/check : login, CSRF, rate limit, size limit, validation."""
import pytest
from sqlalchemy import select

from backend.app.config import get_settings
from backend.app.models import Scan


def _login(api, email="user@example.com"):
    api.signup_verify(email, gmail=True)
    assert api.login(email).status_code == 200


def test_check_requires_login_and_csrf(api):
    body = {"kind": "link", "url": "http://example.com"}
    assert api.post("/api/check", body).status_code == 401
    _login(api)
    assert api.post("/api/check", body, csrf=False).status_code == 403


def test_link_check_returns_defanged_only(api):
    _login(api)
    r = api.post("/api/check", {"kind": "link", "url": "http://paypa1-secure-login.example.com/verify-account"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verdict"] in {"SAFE", "SUSPICIOUS", "PHISHING"} and 0 <= d["score"] <= 100
    assert "urls" not in d  # raw URL bahar nahi
    assert all(not u.lower().startswith("http") for u in d["defanged_urls"])
    assert {"reasons", "layer_scores", "confidence", "degraded"} <= set(d)


def test_link_without_scheme_is_accepted(api):
    _login(api)
    assert api.post("/api/check", {"kind": "link", "url": "evil.example/login"}).status_code == 200


def test_message_check(api):
    _login(api)
    r = api.post("/api/check", {
        "kind": "message", "sender": "PayPal Support <support@paypa1-alerts.example>",
        "subject": "URGENT: account suspended",
        "text": "Verify your password immediately at http://paypa1-alerts.example/login or lose access.",
    })
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] in {"SUSPICIOUS", "PHISHING", "SAFE"}


def test_check_results_are_not_stored(api, db):
    _login(api)
    api.post("/api/check", {"kind": "message", "text": "hello there"})
    assert db.scalars(select(Scan)).all() == []


@pytest.mark.parametrize("body", [
    {"kind": "evil", "url": "http://x.example"},
    {"kind": "link"},
    {"kind": "link", "url": "   "},
    {"kind": "message"},
    {"kind": "message", "text": "  ", "subject": ""},
    {"kind": "link", "url": "http://x.example", "extra": 1},
    {"url": "http://x.example"},
])
def test_invalid_bodies_rejected(api, body):
    _login(api)
    assert api.post("/api/check", body).status_code == 422


def test_validation_error_does_not_echo_input(api):
    _login(api)
    r = api.post("/api/check", {"kind": "link", "url": "SECRETMARKER" + "x" * 3000})
    assert r.status_code == 422 and "SECRETMARKER" not in r.text
    bad = api.c.post("/api/check", content=b"{not json SECRETMARKER", headers={
        "X-CSRF-Token": api.c.cookies.get("aliguard_csrf", ""), "Content-Type": "application/json"})
    assert bad.status_code == 422 and "SECRETMARKER" not in bad.text


def test_oversized_body_rejected_with_413(api):
    _login(api)
    r = api.post("/api/check", {"kind": "message", "text": "a" * 150_000})
    assert r.status_code == 413
    # hadd ke andar lekin field limit se bara text: 422
    r = api.post("/api/check", {"kind": "message", "text": "a" * 60_000})
    assert r.status_code == 422


def test_per_user_rate_limit(api, api2, monkeypatch):
    monkeypatch.setattr(get_settings(), "check_user_limit", 2)
    _login(api, "a@example.com")
    _login(api2, "b@example.com")
    body = {"kind": "message", "text": "hello"}
    assert [api.post("/api/check", body).status_code for _ in range(3)] == [200, 200, 429]
    assert api2.post("/api/check", body).status_code == 200  # doosre user par asar nahi
