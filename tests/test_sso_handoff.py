"""Phase 5: aliguard-portal se /api/auth/sso handoff (login bridge + entitlement)."""
import base64
import hashlib
import hmac
import json
import time

from sqlalchemy import select

from backend.app.config import get_settings
from backend.app.models import AuditLog, Entitlement, User

SECRET = "test-sso-shared-secret-at-least-32-chars-long"  # noqa: S105


def _make_token(email: str, service: str = "", exp_in: int = 120, nonce: str = "nonce-0001", verified: bool = True) -> str:
    """Portal ke make_sso_token() jaisa hi encoding, taake test asli handoff reproduce kare."""
    payload = json.dumps(
        {"email": email, "service": service, "verified": verified, "nonce": nonce, "exp": int(time.time()) + exp_in},
        separators=(",", ":"),
    ).encode()
    body_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    sig = hmac.new(SECRET.encode(), body_b64.encode(), hashlib.sha256).hexdigest()
    return f"{body_b64}.{sig}"


def test_sso_creates_user_logs_in_and_grants_entitlement(api, db, monkeypatch):
    monkeypatch.setenv("SSO_SHARED_SECRET", SECRET)
    get_settings.cache_clear()

    token = _make_token("new.portal.user@example.com", service="gmail", nonce="nonce-aaa-0001")
    r = api.get(f"/api/auth/sso?token={token}", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].endswith("/dashboard?connect=gmail")  # gmail plan -> seedha Connect Gmail
    assert "aliguard_session" in r.cookies

    user = db.scalar(select(User).where(User.email == "new.portal.user@example.com"))
    assert user is not None and user.is_verified is True
    ent = db.scalar(select(Entitlement).where(Entitlement.user_id == user.id))
    assert ent is not None and ent.service == "gmail"
    assert "sso_login" in {e for (e,) in db.execute(select(AuditLog.event))}

    get_settings.cache_clear()


def test_sso_token_cannot_be_replayed(api, monkeypatch):
    monkeypatch.setenv("SSO_SHARED_SECRET", SECRET)
    get_settings.cache_clear()
    token = _make_token("replay@example.com", nonce="nonce-bbb-0001")
    first = api.get(f"/api/auth/sso?token={token}", follow_redirects=False)
    assert first.status_code == 302
    second = api.get(f"/api/auth/sso?token={token}", follow_redirects=False)
    assert second.status_code == 400
    get_settings.cache_clear()


def test_sso_rejects_expired_or_badly_signed_token(api, monkeypatch):
    monkeypatch.setenv("SSO_SHARED_SECRET", SECRET)
    get_settings.cache_clear()
    expired = _make_token("late@example.com", exp_in=-10, nonce="nonce-ccc-0001")
    assert api.get(f"/api/auth/sso?token={expired}", follow_redirects=False).status_code == 400
    tampered = _make_token("x@example.com", nonce="nonce-ddd-0001")[:-2] + "00"
    assert api.get(f"/api/auth/sso?token={tampered}", follow_redirects=False).status_code == 400
    get_settings.cache_clear()


def test_sso_disabled_without_shared_secret(api, monkeypatch):
    monkeypatch.delenv("SSO_SHARED_SECRET", raising=False)
    get_settings.cache_clear()
    token = _make_token("nobody@example.com", nonce="nonce-eee")
    assert api.get(f"/api/auth/sso?token={token}", follow_redirects=False).status_code == 404
    get_settings.cache_clear()


def test_sso_rejects_unverified_portal_email(api, db, monkeypatch):
    """Portal ne email verify nahi ki => victim ke email par account takeover nahi ho sakta."""
    monkeypatch.setenv("SSO_SHARED_SECRET", SECRET)
    get_settings.cache_clear()
    token = _make_token("victim@example.com", service="gmail", nonce="nonce-unv1", verified=False)
    r = api.get(f"/api/auth/sso?token={token}", follow_redirects=False)
    assert r.status_code == 400
    assert db.scalar(select(User).where(User.email == "victim@example.com")) is None
    get_settings.cache_clear()


def test_sso_does_not_bypass_2fa(api, db, monkeypatch):
    monkeypatch.setenv("SSO_SHARED_SECRET", SECRET)
    get_settings.cache_clear()
    api.get(f"/api/auth/sso?token={_make_token('twofa@example.com', nonce='nonce-2fa1')}", follow_redirects=False)
    user = db.scalar(select(User).where(User.email == "twofa@example.com"))
    user.totp_enabled = True
    db.commit()
    r = api.get(f"/api/auth/sso?token={_make_token('twofa@example.com', nonce='nonce-2fa2')}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("/login")
    assert "aliguard_session" not in r.cookies
    get_settings.cache_clear()
