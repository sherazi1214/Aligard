"""2FA attack tests: replay, brute force, recovery code single-use, secret encrypted at rest."""
import pyotp
from sqlalchemy import select

from backend.app.models import User
from backend.app.security import decrypt_secret
from tests.conftest import PW, Api


def _enable_2fa(api):
    api.signup_verify()
    api.login()
    secret = api.post("/api/auth/2fa/setup").json()["secret"]
    codes = api.post("/api/auth/2fa/enable", {"code": pyotp.TOTP(secret).now()}).json()["recovery_codes"]
    api.post("/api/auth/logout")
    return secret, codes


def test_secret_encrypted_at_rest(api, db):
    secret, _ = _enable_2fa(api)
    stored = db.scalar(select(User)).totp_secret_encrypted
    assert stored and secret not in stored
    assert decrypt_secret(stored) == secret


def test_wrong_code_and_attempt_limit_kills_pending_session(api):
    secret, _ = _enable_2fa(api)
    assert api.login().json() == {"status": "2fa_required"}
    for _ in range(5):
        assert api.post("/api/auth/login/2fa", {"code": "000000"}).status_code == 401
    # ab sahi code bhi pending session par nahi chalta
    r = api.post("/api/auth/login/2fa", {"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 401
    assert api.get("/api/auth/me").status_code == 401


def test_totp_code_cannot_be_replayed(api):
    secret, _ = _enable_2fa(api)
    # setup ke waqt use hua code replay nahi ho sakta
    api.login()
    assert api.post("/api/auth/login/2fa", {"code": pyotp.TOTP(secret).now()}).status_code == 401
    # agle time step ka code ek bar chalta hai, doosri bar nahi
    import time
    nxt = pyotp.TOTP(secret).at(time.time() + 30)
    assert api.post("/api/auth/login/2fa", {"code": nxt}).status_code == 200
    api.post("/api/auth/logout")
    api.login()
    assert api.post("/api/auth/login/2fa", {"code": nxt}).status_code == 401


def test_recovery_code_single_use(api):
    _, codes = _enable_2fa(api)
    api.login()
    assert api.post("/api/auth/login/2fa", {"code": codes[0]}).status_code == 200
    api.post("/api/auth/logout")
    api.login()
    assert api.post("/api/auth/login/2fa", {"code": codes[0]}).status_code == 401
    assert api.post("/api/auth/login/2fa", {"code": codes[1].upper()}).status_code == 200


def test_2fa_login_without_pending_session_rejected(api):
    _enable_2fa(api)
    assert api.post("/api/auth/login/2fa", {"code": "123456"}).status_code == 401


def test_setup_enable_validation_and_disable(api):
    api.signup_verify()
    api.login()
    assert api.post("/api/auth/2fa/enable", {"code": "123456"}).status_code == 400  # setup nahi hua
    secret = api.post("/api/auth/2fa/setup").json()["secret"]
    assert api.post("/api/auth/2fa/enable", {"code": "000000"}).status_code == 400
    codes = api.post("/api/auth/2fa/enable", {"code": pyotp.TOTP(secret).now()}).json()["recovery_codes"]
    assert api.post("/api/auth/2fa/setup").status_code == 409
    assert api.post("/api/auth/2fa/disable", {"password": "wrong-password-12", "code": codes[0]}).status_code == 400
    assert api.post("/api/auth/2fa/disable", {"password": PW, "code": "000000"}).status_code == 400
    assert api.post("/api/auth/2fa/disable", {"password": PW, "code": codes[0]}).status_code == 200
    api.post("/api/auth/logout")
    assert api.login().json() == {"status": "ok"}  # ab 2FA nahi


def test_2fa_endpoints_need_login(api):
    for p in ("/api/auth/2fa/setup", "/api/auth/2fa/enable", "/api/auth/change-password"):
        assert api.post(p, {"code": "123456", "current_password": "a", "new_password": "b"}).status_code == 401
    assert Api  # import use
