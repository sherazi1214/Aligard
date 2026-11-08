"""Gmail connect: OAuth2 + PKCE + state. Google ki calls mock hain (asli Google se test NAHI hua)."""
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import select

from backend.app.auth.deps import get_redis
from backend.app.config import get_settings
from backend.app.gmail import google
from backend.app.gmail.router import STATE_COOKIE, _pkce_challenge, _state_key
from backend.app.main import app
from backend.app.models import AuditLog, GmailAccount
from backend.app.security import decrypt_secret


@pytest.fixture
def fake_google(monkeypatch):
    f = SimpleNamespace(
        email="ali@gmail.com", scope=google.GMAIL_SCOPE, refresh="refresh-1", access="access-1",
        exchange_fails=False, exchanged=[], revoked=[],
    )

    def exchange(code, verifier):
        f.exchanged.append((code, verifier))
        if f.exchange_fails:
            raise google.GoogleError("token_exchange_failed")
        tokens = {"access_token": f.access, "expires_in": 3600, "scope": f.scope}
        if f.refresh:
            tokens["refresh_token"] = f.refresh
        return tokens

    monkeypatch.setattr(google, "exchange_code", exchange)
    monkeypatch.setattr(google, "fetch_profile_email", lambda token: f.email)
    monkeypatch.setattr(google, "revoke", lambda token: f.revoked.append(token) or True)
    return f


def _login(api, email="user@example.com"):
    api.signup_verify(email)
    assert api.login(email).status_code == 200


def _start(api):
    r = api.post("/api/gmail/connect")
    assert r.status_code == 200, r.text
    q = parse_qs(urlparse(r.json()["auth_url"]).query)
    return r, q, q["state"][0]


def _callback(api, state, code="auth-code"):
    return api.get("/api/gmail/callback", params={"code": code, "state": state}, follow_redirects=False)


def _connect(api, fake_google, email=None):
    if email:
        fake_google.email = email
    _, _, state = _start(api)
    r = _callback(api, state)
    assert r.headers["location"] == "/dashboard?gmail=connected", r.headers["location"]


def test_connect_requires_login_and_csrf(api):
    assert api.post("/api/gmail/connect").status_code == 401
    _login(api)
    assert api.post("/api/gmail/connect", csrf=False).status_code == 403


def test_connect_not_configured(api, monkeypatch):
    _login(api)
    monkeypatch.setattr(get_settings(), "google_client_id", "")
    assert api.post("/api/gmail/connect").status_code == 503


def test_connect_url_has_pkce_state_and_minimal_scope(api):
    _login(api)
    r, q, state = _start(api)
    url = urlparse(r.json()["auth_url"])
    assert url.netloc == "accounts.google.com"
    assert q["response_type"] == ["code"] and q["code_challenge_method"] == ["S256"]
    assert q["scope"] == [google.GMAIL_SCOPE]
    assert q["access_type"] == ["offline"] and q["prompt"] == ["select_account consent"]
    assert q["redirect_uri"] == ["http://localhost:8000/api/gmail/callback"]
    assert len(state) >= 40
    # PKCE verifier sirf Redis mein, aur challenge usi se bana
    raw = app.dependency_overrides[get_redis]().get(_state_key(state))
    verifier = json.loads(raw)["v"]
    assert _pkce_challenge(verifier) == q["code_challenge"][0]
    assert verifier not in r.text and "client_secret" not in r.text
    cookie = r.headers["set-cookie"].lower()
    assert STATE_COOKIE in cookie and "httponly" in cookie and "samesite=lax" in cookie


def test_callback_happy_path_encrypts_tokens(api, db, fake_google):
    _login(api)
    _, q, state = _start(api)
    r = _callback(api, state)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard?gmail=connected"
    code, verifier = fake_google.exchanged[0]
    assert code == "auth-code" and _pkce_challenge(verifier) == q["code_challenge"][0]

    db.expire_all()
    acc = db.scalar(select(GmailAccount))
    assert acc.google_email == "ali@gmail.com" and acc.status == "active"
    assert "refresh-1" not in acc.refresh_token_encrypted and "access-1" not in acc.access_token_encrypted
    assert decrypt_secret(acc.refresh_token_encrypted) == "refresh-1"
    assert "gmail_connected" in {e for (e,) in db.execute(select(AuditLog.event))}

    listing = api.get("/api/gmail/accounts")
    assert listing.status_code == 200
    body = listing.json()
    assert body["accounts"][0]["email"] == "ali@gmail.com"
    assert "refresh-1" not in listing.text and "access-1" not in listing.text
    assert not any("token" in k for k in body["accounts"][0])


def test_callback_state_is_single_use(api, fake_google):
    _login(api)
    _, _, state = _start(api)
    assert _callback(api, state).headers["location"].endswith("connected")
    assert _callback(api, state).headers["location"].endswith("error")  # replay
    assert len(fake_google.exchanged) == 1


def test_callback_without_state_cookie_rejected(api, db, fake_google):
    """Login-CSRF: attacker ka link victim ke browser mein, par state cookie victim ke paas nahi."""
    _login(api)
    _, _, state = _start(api)
    api.c.cookies.delete(STATE_COOKIE, path="/api/gmail")
    assert _callback(api, state).headers["location"].endswith("error")
    assert fake_google.exchanged == [] and db.scalar(select(GmailAccount)) is None


def test_callback_state_of_another_user_rejected(api, api2, db, fake_google):
    _login(api, "a@example.com")
    _login(api2, "b@example.com")
    _, _, state_a = _start(api)
    # B ke browser mein A ki state (cookie bhi) pohanchi: phir bhi B ki session se match nahi karegi
    api2.c.cookies.set(STATE_COOKIE, state_a, domain="testserver.local", path="/api/gmail")
    assert _callback(api2, state_a).headers["location"].endswith("error")
    assert fake_google.exchanged == [] and db.scalar(select(GmailAccount)) is None


def test_callback_requires_session(api, fake_google):
    r = api.get("/api/gmail/callback", params={"code": "c", "state": "s"}, follow_redirects=False)
    assert r.headers["location"] == "/dashboard?gmail=session" and fake_google.exchanged == []


def test_callback_user_denied_and_garbage_params(api, fake_google):
    _login(api)
    r = api.get("/api/gmail/callback", params={"error": "access_denied<script>"}, follow_redirects=False)
    assert r.headers["location"] == "/dashboard?gmail=denied"  # error text aage nahi jata
    for params in ({}, {"code": "x" * 5000, "state": "s"}, {"code": "c", "state": "forged"}):
        r = api.get("/api/gmail/callback", params=params, follow_redirects=False)
        assert r.headers["location"] == "/dashboard?gmail=error"
    assert fake_google.exchanged == []


def test_callback_missing_scope_revokes_and_stores_nothing(api, db, fake_google):
    _login(api)
    fake_google.scope = "https://www.googleapis.com/auth/userinfo.email"
    _, _, state = _start(api)
    assert _callback(api, state).headers["location"].endswith("scope")
    assert db.scalar(select(GmailAccount)) is None and fake_google.revoked == ["refresh-1"]


def test_callback_without_refresh_token_fails(api, db, fake_google):
    _login(api)
    fake_google.refresh = None
    _, _, state = _start(api)
    assert _callback(api, state).headers["location"].endswith("error")
    assert db.scalar(select(GmailAccount)) is None and fake_google.revoked == ["access-1"]


def test_callback_google_failure_is_generic(api, db, fake_google):
    _login(api)
    fake_google.exchange_fails = True
    _, _, state = _start(api)
    assert _callback(api, state).headers["location"] == "/dashboard?gmail=error"
    assert db.scalar(select(GmailAccount)) is None


def test_account_limit(api, db, fake_google, make_account, user_id, monkeypatch):
    _login(api)
    uid = user_id("user@example.com")
    for i in range(3):
        make_account(uid, f"acc{i}@gmail.com")
    # Limit ab callback par lagti hai (needs_reauth reconnect ke liye OAuth shuru hona chahiye)
    assert api.post("/api/gmail/connect").status_code == 200
    # callback par bhi hadd (connect ke baad account bhar jaye to)
    monkeypatch.setattr(get_settings(), "gmail_max_accounts_per_user", 4)
    _, _, state = _start(api)
    make_account(uid, "acc3@gmail.com")
    fake_google.email = "new@gmail.com"
    assert _callback(api, state).headers["location"].endswith("limit")
    assert fake_google.revoked == ["refresh-1"]


def test_reconnect_same_email_updates_single_row(api, db, fake_google):
    _login(api)
    _connect(api, fake_google)
    fake_google.refresh = "refresh-2"
    _connect(api, fake_google)
    db.expire_all()
    rows = db.scalars(select(GmailAccount)).all()
    assert len(rows) == 1 and decrypt_secret(rows[0].refresh_token_encrypted) == "refresh-2"


def test_three_accounts_for_one_user(api, fake_google):
    api.signup_verify("user@example.com", plan="pro")  # Pro plan = 3 inbox
    assert api.login("user@example.com").status_code == 200
    for email in ("one@gmail.com", "two@gmail.com", "three@gmail.com"):
        _connect(api, fake_google, email)
    assert len(api.get("/api/gmail/accounts").json()["accounts"]) == 3
    # Chautha naya account callback par reject hota hai
    fake_google.email = "four@gmail.com"
    _, _, state = _start(api)
    assert _callback(api, state).headers["location"].endswith("limit")
    assert len(api.get("/api/gmail/accounts").json()["accounts"]) == 3


def test_disconnect_wipes_tokens_and_revokes(api, db, fake_google):
    _login(api)
    _connect(api, fake_google)
    acc_id = api.get("/api/gmail/accounts").json()["accounts"][0]["id"]
    r = api.post(f"/api/gmail/accounts/{acc_id}/disconnect")
    assert r.status_code == 200 and r.json() == {"status": "disconnected", "revoked": True}
    assert fake_google.revoked == ["refresh-1"]
    db.expire_all()
    acc = db.scalar(select(GmailAccount))
    assert acc.refresh_token_encrypted is None and acc.access_token_encrypted is None
    assert acc.status == "disconnected"


def test_disconnect_wipes_tokens_even_if_revoke_fails(api, db, fake_google, monkeypatch):
    _login(api)
    _connect(api, fake_google)
    monkeypatch.setattr(google, "revoke", lambda token: False)
    acc_id = api.get("/api/gmail/accounts").json()["accounts"][0]["id"]
    assert api.post(f"/api/gmail/accounts/{acc_id}/disconnect").json()["revoked"] is False
    db.expire_all()
    assert db.scalar(select(GmailAccount)).refresh_token_encrypted is None


def test_disconnect_other_users_account_is_404(api, api2, db, fake_google):
    _login(api, "a@example.com")
    _login(api2, "b@example.com")
    _connect(api, fake_google)
    acc_id = api.get("/api/gmail/accounts").json()["accounts"][0]["id"]
    assert api2.post(f"/api/gmail/accounts/{acc_id}/disconnect").status_code == 404
    assert api2.post("/api/gmail/accounts/00000000-0000-4000-8000-000000000000/disconnect").status_code == 404
    assert api2.post("/api/gmail/accounts/not-a-uuid/disconnect").status_code == 422
    assert api2.get("/api/gmail/accounts").json()["accounts"] == []
    db.expire_all()
    assert db.scalar(select(GmailAccount)).status == "active" and fake_google.revoked == []


def test_disconnect_requires_csrf_and_login(api, fake_google):
    path = "/api/gmail/accounts/00000000-0000-4000-8000-000000000000/disconnect"
    assert api.post(path).status_code == 401
    _login(api)
    assert api.post(path, csrf=False).status_code == 403


def test_typed_email_becomes_login_hint_and_must_match(api, fake_google):
    _login(api)
    r = api.post("/api/gmail/connect", json={"email": "Ali@Gmail.com"})
    assert r.status_code == 200
    q = parse_qs(urlparse(r.json()["auth_url"]).query)
    assert q["login_hint"] == ["ali@gmail.com"]
    # Google mein doosre account se login => connect nahi hota
    fake_google.email = "other@gmail.com"
    resp = _callback(api, q["state"][0])
    assert resp.headers["location"] == "/dashboard?gmail=mismatch"
    assert fake_google.revoked


def test_typed_email_dots_and_plus_tag_match(api, fake_google):
    _login(api)
    fake_google.email = "alik@gmail.com"
    r = api.post("/api/gmail/connect", json={"email": "ali.k+test@gmail.com"})
    state = parse_qs(urlparse(r.json()["auth_url"]).query)["state"][0]
    assert _callback(api, state).headers["location"] == "/dashboard?gmail=connected"


def test_invalid_typed_email_rejected(api):
    _login(api)
    assert api.post("/api/gmail/connect", json={"email": "not-an-email"}).status_code == 422
