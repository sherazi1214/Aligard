"""UI pages (XSS/CSP), passwords/HIBP, mailer, rate limiter, config, Alembic."""
import re
import smtplib
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
import redis
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from backend.app import mailer, passwords
from backend.app.config import Settings
from backend.app.db import Base
from backend.app.models import User
from backend.app.ratelimit import allow
from backend.app.security import hash_password
from tests.conftest import PW

ROOT = Path(__file__).resolve().parents[1]


def test_pages_render_with_strict_csp(api):
    for path in ("/signup", "/login", "/login/2fa", "/verify-email", "/forgot-password", "/reset-password"):
        r = api.get(path)
        assert r.status_code == 200, path
        csp = r.headers["content-security-policy"]
        assert "unsafe-inline" not in csp and "script-src 'self'" in csp
        assert r.headers["cache-control"] == "no-store"
    assert "aliguard_csrf" in api.c.cookies


def test_templates_and_js_have_no_inline_script_or_innerhtml():
    for f in (ROOT / "web" / "templates").glob("*.html"):
        html = f.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), f
        assert not re.search(r"\son\w+\s*=", html), f  # onclick= waghera
        assert "style=" not in html, f
    for name in ("app.js", "dashboard.js"):
        js = (ROOT / "web" / "static" / name).read_text()
        assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", js), name


def test_account_requires_login_and_escapes_email(api, db):
    r = api.get("/account", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    # attacker-controlled email jo DB mein kisi tarah aa gayi: HTML escape honi chahiye
    db.add(User(email="<script>alert(1)</script>@example.com", password_hash=hash_password(PW),
                is_verified=True))
    db.commit()
    api.c.cookies.clear()
    api.c.get("/login")
    # sidha session bana kar account page kholte hain
    from backend.app.auth import service
    user = db.query(User).one()
    raw = service.create_session(db, user, "127.0.0.1", "t")
    db.commit()
    api.set_session(raw)
    page = api.get("/account")
    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text


def test_static_served_and_docs_csp_exception(api):
    assert api.get("/static/app.js").status_code == 200
    assert api.get("/static/../../etc/passwd").status_code in (404, 400)


# ---------- passwords / HIBP ----------
class _Resp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_hibp_detects_breach_and_sends_only_prefix(monkeypatch):
    import hashlib
    monkeypatch.setenv("HIBP_ENABLED", "true")
    from backend.app.config import get_settings
    get_settings.cache_clear()
    sha = hashlib.sha1(b"hunter2hunter2", usedforsecurity=False).hexdigest().upper()
    seen = {}

    def fake_get(url, **kw):
        seen["url"] = url
        return _Resp(f"{sha[5:]}:120\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0")

    monkeypatch.setattr(passwords.httpx, "get", fake_get)
    try:
        assert passwords.is_breached("hunter2hunter2") is True
        assert seen["url"].endswith("/" + sha[:5]) and sha[5:] not in seen["url"]
        monkeypatch.setattr(passwords.httpx, "get", lambda url, **kw: _Resp("0000000000000000000000000000000000A:3"))
        assert passwords.is_breached("hunter2hunter2") is False
    finally:
        monkeypatch.delenv("HIBP_ENABLED")
        get_settings.cache_clear()


def test_hibp_network_failure_fails_open(monkeypatch):
    monkeypatch.setenv("HIBP_ENABLED", "true")
    from backend.app.config import get_settings
    get_settings.cache_clear()

    def boom(url, **kw):
        raise httpx.ConnectTimeout("t")

    monkeypatch.setattr(passwords.httpx, "get", boom)
    monkeypatch.setattr(passwords.time, "sleep", lambda s: None)
    try:
        assert passwords.is_breached("whatever-password-1") is False
    finally:
        monkeypatch.delenv("HIBP_ENABLED")
        get_settings.cache_clear()


# ---------- resilience ----------
def test_rate_limiter_fails_open_when_redis_down():
    class Down:
        def pipeline(self):
            raise redis.ConnectionError("down")

    assert allow(Down(), "k", 1, 10) is True


def test_smtp_failure_retries_and_never_raises(monkeypatch):
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")
    from backend.app.config import get_settings
    get_settings.cache_clear()
    calls = []

    class Bad:
        def __init__(self, *a, **k):
            calls.append(1)
            raise smtplib.SMTPConnectError(421, "x")

    monkeypatch.setattr(mailer.smtplib, "SMTP", Bad)
    monkeypatch.setattr(mailer.time, "sleep", lambda s: None)
    try:
        mailer.safe_send("a@example.com", "s", "b")
        assert len(calls) == 3
    finally:
        monkeypatch.delenv("EMAIL_BACKEND")
        get_settings.cache_clear()


# ---------- config ----------
def test_production_requires_encryption_key_smtp_and_secure_cookies():
    base = {"_env_file": None, "app_env": "production", "secret_key": "x" * 40,
            "base_url": "https://aliguard.example.com", "payments_provider": "stripe",
            "stripe_secret_key": "sk_live_" + "a" * 24, "stripe_webhook_secret": "whsec_" + "b" * 16,
            "stripe_price_pro": "price_pro1", "stripe_price_business": "price_biz1"}
    with pytest.raises(ValueError):
        Settings(**base, email_backend="smtp")  # encryption key nahi
    with pytest.raises(ValueError):
        Settings(**base, encryption_key="k")  # console email
    with pytest.raises(ValueError):
        Settings(**base, encryption_key="k", email_backend="smtp", cookie_secure=False)
    assert Settings(**base, encryption_key="k", email_backend="smtp").secure_cookies is True


# ---------- Alembic ----------
def test_alembic_migration_matches_models(tmp_path):
    dburl = f"sqlite:///{tmp_path / 'm.db'}"
    env = {"DATABASE_URL": dburl, "PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)}
    out = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        cwd=ROOT, env={**env, **{k: v for k, v in __import__("os").environ.items() if k == "VIRTUAL_ENV"}},
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert out.returncode == 0, out.stderr
    eng = create_engine(dburl)
    tables = set(inspect(eng).get_table_names())
    assert {"users", "email_tokens", "sessions", "recovery_codes", "audit_log", "alembic_version"} <= tables
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff  # migration aur models mein farq nahi
