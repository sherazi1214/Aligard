"""Phase 2: happy path + enumeration + token + lockout + CSRF + rate limit."""
import logging
from datetime import timedelta

import pyotp
from sqlalchemy import select

from backend.app.config import get_settings
from backend.app.models import AuditLog, EmailToken, Session, User, utcnow
from tests.conftest import PW


def test_full_flow_signup_verify_login_2fa_logout_reset(api, db, caplog):
    caplog.set_level(logging.DEBUG)
    api.signup_verify()
    assert api.login().json() == {"status": "ok"}
    assert api.get("/api/auth/me").json()["email"] == "user@example.com"

    # 2FA setup + enable
    setup = api.post("/api/auth/2fa/setup").json()
    assert setup["qr_data_uri"].startswith("data:image/svg+xml;base64,")
    code = pyotp.TOTP(setup["secret"]).now()
    codes = api.post("/api/auth/2fa/enable", {"code": code}).json()["recovery_codes"]
    assert len(codes) == 10

    # logout, phir login -> 2FA lazmi
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/me").status_code == 401
    assert api.login().json() == {"status": "2fa_required"}
    assert api.get("/api/auth/me").status_code == 401  # pending session se kuch nahi
    assert api.post("/api/auth/login/2fa", {"code": codes[0]}).json() == {"status": "ok"}
    assert api.get("/api/auth/me").status_code == 200
    assert api.post("/api/auth/logout").status_code == 200

    # forgot -> reset -> purana password band, naya chalta hai
    assert api.post("/api/auth/forgot-password", {"email": "user@example.com"}).status_code == 202
    tok = api.last_token()
    r = api.post("/api/auth/reset-password", {"token": tok, "password": "brand-new-passphrase-77"})
    assert r.status_code == 200
    assert api.login().status_code == 401
    assert api.login(pw="brand-new-passphrase-77").json() == {"status": "2fa_required"}

    events = {e for (e,) in db.execute(select(AuditLog.event))}
    assert {"signup", "email_verified", "login_success", "2fa_enabled", "login_success_2fa", "logout",
            "password_reset"} <= events
    # Secrets log mein nahi
    for secret in (PW, "brand-new-passphrase-77", tok, setup["secret"]):
        assert secret not in caplog.text


def test_signup_does_not_reveal_existing_email(api, mails):
    a = api.post("/api/auth/signup", {"email": "dup@example.com", "password": PW})
    b = api.post("/api/auth/signup", {"email": "dup@example.com", "password": PW})
    assert a.status_code == b.status_code == 202 and a.json() == b.json()
    assert "token=" in mails[0][2] and "token=" not in mails[1][2]  # doosri mail mein link nahi


def test_weak_and_breached_passwords_rejected(api, monkeypatch):
    from backend.app import passwords

    for bad in ("short1!", "password123", "aaaaaaaaaaaaaaaa", "user-user@x.com"):
        r = api.post("/api/auth/signup", {"email": "user@example.com", "password": bad})
        assert r.status_code == 422, bad
        assert bad not in r.text  # password response mein echo nahi
    monkeypatch.setattr(passwords, "is_breached", lambda pw: True)
    assert api.post("/api/auth/signup", {"email": "u@example.com", "password": PW}).status_code == 422


def test_validation_error_does_not_echo_input(api):
    r = api.post("/api/auth/login", {"email": "not-an-email", "password": "SuperSecret-Value-1"})
    assert r.status_code == 422 and "SuperSecret-Value-1" not in r.text


def test_login_errors_are_generic_and_unverified_blocked(api):
    api.post("/api/auth/signup", {"email": "u@example.com", "password": PW})
    unknown = api.login("nobody@example.com")
    wrong = api.login("u@example.com", "wrong-password-123")
    assert unknown.status_code == wrong.status_code == 401 and unknown.json() == wrong.json()
    # sahi password lekin email verify nahi
    assert api.login("u@example.com").status_code == 403


def test_brute_force_triggers_lockout(api, db):
    api.signup_verify()
    for _ in range(get_settings().lockout_threshold):
        assert api.login(pw="wrong-password-123").status_code == 401
    user = db.scalar(select(User))
    assert user.failed_login_count >= 5 and user.locked_until > utcnow()
    # lock ke dauran sahi password bhi nahi chalta, aur jawab generic hai
    r = api.login()
    assert r.status_code == 401 and r.json()["detail"] == "Email ya password ghalat hai"
    # lock khatam hone ke baad chalta hai
    user.locked_until = utcnow() - timedelta(seconds=1)
    db.commit()
    assert api.login().status_code == 200


def test_lockout_grows_exponentially(api, db):
    api.signup_verify()
    for _ in range(5):
        api.login(pw="wrong-password-123")
    d1 = db.scalar(select(User)).locked_until - utcnow()
    user = db.scalar(select(User))
    user.locked_until = None
    db.commit()
    api.login(pw="wrong-password-123")  # 6th failure
    db.expire_all()
    d2 = db.scalar(select(User)).locked_until - utcnow()
    assert d2 > d1 * 1.5


def test_ip_rate_limit(api, monkeypatch):
    monkeypatch.setenv("LOGIN_IP_LIMIT", "3")
    get_settings.cache_clear()
    try:
        codes = [api.login("n@example.com").status_code for _ in range(5)]
        assert codes[:3] == [401] * 3 and codes[3:] == [429, 429]
    finally:
        monkeypatch.delenv("LOGIN_IP_LIMIT")
        get_settings.cache_clear()


def test_email_rate_limit_applies_even_to_unknown_email(api):
    codes = [api.login("ghost@example.com").status_code for _ in range(12)]
    assert 429 in codes


def test_verify_token_single_use_hashed_and_expiry(api, db):
    api.post("/api/auth/signup", {"email": "u@example.com", "password": PW})
    tok = api.last_token()
    row = db.scalar(select(EmailToken))
    assert row.token_hash != tok and tok not in row.token_hash  # DB mein raw token nahi
    assert api.post("/api/auth/verify-email", {"token": tok}).status_code == 200
    assert api.post("/api/auth/verify-email", {"token": tok}).status_code == 400  # reuse

    api.post("/api/auth/signup", {"email": "e@example.com", "password": PW})
    tok2 = api.last_token("e@example.com")
    row = db.scalar(select(EmailToken).order_by(EmailToken.expires_at.desc()))
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert api.post("/api/auth/verify-email", {"token": tok2}).status_code == 400  # expire
    assert api.post("/api/auth/verify-email", {"token": "x" * 43}).status_code == 400  # ghalat


def test_new_token_invalidates_old(api):
    api.post("/api/auth/signup", {"email": "u@example.com", "password": PW})
    old = api.last_token()
    api.post("/api/auth/resend-verification", {"email": "u@example.com"})
    new = api.last_token()
    assert old != new
    assert api.post("/api/auth/verify-email", {"token": old}).status_code == 400
    assert api.post("/api/auth/verify-email", {"token": new}).status_code == 200


def test_reset_token_single_use_expiry_and_revokes_sessions(api, db):
    api.signup_verify()
    api.login()
    assert api.get("/api/auth/me").status_code == 200
    api.post("/api/auth/forgot-password", {"email": "user@example.com"})
    tok = api.last_token()
    # kamzor password se token zaya nahi hota
    assert api.post("/api/auth/reset-password", {"token": tok, "password": "short"}).status_code == 422
    new_pw = "another-strong-pass-42"
    assert api.post("/api/auth/reset-password", {"token": tok, "password": new_pw}).status_code == 200
    assert api.post("/api/auth/reset-password", {"token": tok, "password": new_pw + "x"}).status_code == 400
    assert api.get("/api/auth/me").status_code == 401  # purani session revoke
    # expiry
    api.post("/api/auth/forgot-password", {"email": "user@example.com"})
    tok2 = api.last_token()
    row = db.scalar(select(EmailToken).where(EmailToken.purpose == "reset", EmailToken.used_at.is_(None)))
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert api.post("/api/auth/reset-password", {"token": tok2, "password": new_pw + "y"}).status_code == 400


def test_forgot_password_no_enumeration(api, mails):
    known_signup = api.post("/api/auth/signup", {"email": "u@example.com", "password": PW})
    assert known_signup.status_code == 202
    mails.clear()
    a = api.post("/api/auth/forgot-password", {"email": "u@example.com"})
    n = len(mails)
    b = api.post("/api/auth/forgot-password", {"email": "ghost@example.com"})
    assert a.status_code == b.status_code == 202 and a.json() == b.json()
    assert n == 1 and len(mails) == 1  # unknown email par mail nahi gayi


def test_csrf_enforced(api):
    body = {"email": "u@example.com", "password": PW}
    assert api.post("/api/auth/signup", body, csrf=False).status_code == 403
    assert api.post("/api/auth/signup", body, headers={"X-CSRF-Token": "forged.value"}).status_code == 403
    cookie = api.c.cookies.get("aliguard_csrf")
    tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
    assert api.post("/api/auth/signup", body, headers={"X-CSRF-Token": tampered}).status_code == 403
    assert api.post("/api/auth/signup", body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert api.post("/api/auth/signup", body).status_code == 202
    api.signup_verify("v@example.com")
    api.login("v@example.com")
    assert api.post("/api/auth/logout", csrf=False).status_code == 403
    assert api.post("/api/auth/change-password", {"current_password": PW, "new_password": "x" * 14},
                    csrf=False).status_code == 403


def test_session_cookie_flags_hash_and_fixation(api, db):
    api.signup_verify()
    attacker_value = "attacker-chosen-session-id-1234567890"
    api.set_session(attacker_value)
    r = api.login()
    set_cookie = r.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=lax" in set_cookie
    new_value = api.session()
    assert new_value != attacker_value  # server hamesha nayi id banata hai
    raw = [s for s in db.scalars(select(Session))]
    assert all(new_value not in s.session_hash for s in raw)  # DB mein hash
    # purani session revoke: dobara login karne par pehli cookie kaam na kare
    first = new_value
    api.login()
    api.set_session(first)
    assert api.get("/api/auth/me").status_code == 401


def test_logout_revokes_server_side_and_logout_all(api):
    api.signup_verify()
    api.login()
    stolen = api.session()
    from tests.conftest import Api
    other = Api(api.mails)
    other.login()
    assert api.post("/api/auth/logout").status_code == 200
    api.set_session(stolen)
    assert api.get("/api/auth/me").status_code == 401  # cookie chori bhi ho to server band kar chuka
    assert other.get("/api/auth/me").status_code == 200
    api.login()
    assert api.post("/api/auth/logout-all").status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_idle_and_absolute_timeouts(api, db):
    api.signup_verify()
    api.login()
    sess = db.scalar(select(Session))
    sess.last_seen_at = utcnow() - timedelta(minutes=get_settings().session_idle_minutes + 1)
    db.commit()
    assert api.get("/api/auth/me").status_code == 401
    api.login()
    sess = db.scalars(select(Session).order_by(Session.created_at.desc())).first()
    sess.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert api.get("/api/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(api):
    api.signup_verify()
    api.login()
    from tests.conftest import Api
    other = Api(api.mails)
    other.login()
    assert api.post("/api/auth/change-password",
                    {"current_password": "nope-nope-nope-1", "new_password": "z" * 14 + "Q1"}).status_code == 400
    r = api.post("/api/auth/change-password", {"current_password": PW, "new_password": "fresh-passphrase-2026"})
    assert r.status_code == 200
    assert api.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_users_cannot_see_each_other_via_me(api):
    api.signup_verify("a@example.com")
    api.signup_verify("b@example.com")
    api.login("a@example.com")
    assert api.get("/api/auth/me").json()["email"] == "a@example.com"
