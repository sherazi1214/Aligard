"""Phase 4: logging mask, Sentry scrub, budgets, heartbeat, global limit, retention, key rotation,
legal pages aur failure drills (Redis down, DB down, Gmail 429)."""
import json
import logging
from datetime import timedelta

import fakeredis
import httpx
import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app import budget, observability, ratelimit, redis_client
from backend.app.auth.deps import get_redis
from backend.app.config import Settings, get_settings
from backend.app.db import get_db
from backend.app.gmail import api as gmail_api
from backend.app.logging_config import JsonFormatter, mask
from backend.app.main import app
from backend.app.maintenance import purge_expired
from backend.app.models import AuditLog, EmailToken, Feedback, Scan, Session, User, utcnow
from backend.app.rotation import reencrypt_all
from backend.app.security import decrypt_secret, encrypt_secret
from backend.app.worker import health as worker_health
from engine.reputation import ProviderError, VirusTotalProvider


class BrokenRedis:
    """Har call par ConnectionError (Redis down)."""

    def __getattr__(self, name):
        def _fail(*a, **k):
            raise redis.ConnectionError("down")
        return _fail


# ------------------------------------------------------------------ logging
def test_mask_secrets_and_pii_but_keep_uuids():
    text = ("login password=Hunter2xyz user bob@example.com Authorization: Bearer abcdefgh12345678 "
            "redis://:s3cret@redis:6379/0 postgresql+psycopg://u:pw@db/x token=abc123 "
            "key=" + "A" * 40 + " account=8c2f3a1e-1b2c-4d5e-9f00-112233445566")
    out = mask(text)
    for leaked in ("Hunter2xyz", "bob@example.com", "abcdefgh12345678", "s3cret", "pw@db", "abc123", "A" * 40):
        assert leaked not in out
    assert "8c2f3a1e-1b2c-4d5e-9f00-112233445566" in out  # UUID debugging ke liye rehta hai


def test_json_formatter_is_valid_json_and_masks_exception_text():
    try:
        raise ValueError("bad token=SUPERSECRETVALUE for bob@example.com")
    except ValueError:
        import sys
        rec = logging.LogRecord("x", logging.ERROR, "f", 1, "failed for %s", ("bob@example.com",), sys.exc_info())
    rec.path = "/api/x"
    data = json.loads(JsonFormatter().format(rec))
    blob = json.dumps(data)
    assert "SUPERSECRETVALUE" not in blob and "bob@example.com" not in blob
    assert data["level"] == "ERROR" and data["path"] == "/api/x"


def test_access_log_never_contains_query_string(api, caplog):
    caplog.set_level(logging.INFO, logger="aliguard")
    api.get("/verify-email?token=TOPSECRETTOKEN123")
    assert any(r.name == "aliguard" and getattr(r, "path", "") == "/verify-email" for r in caplog.records)
    assert "TOPSECRETTOKEN123" not in " ".join(r.getMessage() + str(r.__dict__) for r in caplog.records)


def test_sentry_scrub_removes_request_data_and_locals():
    event = {
        "request": {"method": "POST", "url": "https://x/api?token=SECRET", "cookies": {"s": "1"},
                    "data": {"password": "pw"}, "headers": {"Cookie": "a"}},
        "user": {"email": "a@b.co"},
        "message": "oops bob@example.com",
        "exception": {"values": [{"value": "token=XYZ", "stacktrace": {"frames": [{"vars": {"pw": "1"}}]}}]},
    }
    out = observability.scrub_event(event)
    assert out["request"] == {"method": "POST", "url": "https://x/api"}
    assert "user" not in out and "bob@example.com" not in out["message"]
    assert "XYZ" not in out["exception"]["values"][0]["value"]
    assert "vars" not in out["exception"]["values"][0]["stacktrace"]["frames"][0]


# ------------------------------------------------------------------ budgets
def test_budget_per_user_and_global_limits_and_single_alarm(caplog):
    r = fakeredis.FakeRedis()
    guard = budget.BudgetGuard(r, "openai", daily_limit=5, user_daily_limit=2)
    caplog.set_level(logging.ERROR, logger="aliguard.budget")
    with budget.budget_user("u1"):
        guard.consume()
        guard.consume()
        with pytest.raises(ProviderError):
            guard.consume()  # u1 ki apni hadd
    with budget.budget_user("u2"):
        guard.consume()
        guard.consume()
    with budget.budget_user("u3"):
        guard.consume()  # global 5 tak
        with pytest.raises(ProviderError):
            guard.consume()  # global hadd khatam
    alarms = [rec for rec in caplog.records if "BUDGET_ALARM" in rec.getMessage()]
    assert len(alarms) == 2  # 80% aur 100%, har ek sirf ek bar


def test_budget_blocked_user_does_not_burn_global_budget():
    r = fakeredis.FakeRedis()
    guard = budget.BudgetGuard(r, "virustotal", daily_limit=100, user_daily_limit=1)
    with budget.budget_user("spammer"):
        guard.consume()
        for _ in range(20):
            with pytest.raises(ProviderError):
                guard.consume()
    keys = [k.decode() for k in r.keys("budget:virustotal:*:global")]
    assert int(r.get(keys[0])) == 1


def test_budget_fails_closed_when_redis_down():
    guard = budget.BudgetGuard(BrokenRedis(), "openai", 10, 10)
    with pytest.raises(ProviderError):
        guard.consume()


def test_virustotal_budget_only_counts_real_network_calls_not_cache_hits():
    calls = {"http": 0, "budget": 0}

    def handler(request):
        calls["http"] += 1
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}})

    def count():
        calls["budget"] += 1

    vt = VirusTotalProvider("k", client=httpx.Client(transport=httpx.MockTransport(handler)), before_request=count)
    vt.lookup("http://a.example/x")
    vt.lookup("http://a.example/x")  # cache
    assert calls == {"http": 1, "budget": 1}

    def deny():
        raise ProviderError("budget")

    vt2 = VirusTotalProvider("k", client=httpx.Client(transport=httpx.MockTransport(handler)), before_request=deny)
    with pytest.raises(ProviderError):
        vt2.lookup("http://b.example/y")
    assert calls["http"] == 1  # budget khatam: network call hui hi nahi


def test_engine_factory_wires_paid_layers_only_with_keys(monkeypatch):
    from backend.app import engine_factory

    s = get_settings()
    engine_factory.get_engine.cache_clear()
    monkeypatch.setattr(s, "vt_api_key", "")
    monkeypatch.setattr(s, "openai_api_key", "")
    eng = engine_factory.get_engine()
    assert eng.llm is None and eng.reputation == []
    engine_factory.get_engine.cache_clear()
    monkeypatch.setattr(s, "vt_api_key", "vt")
    monkeypatch.setattr(s, "openai_api_key", "oa")
    eng = engine_factory.get_engine()
    assert isinstance(eng.llm, budget.BudgetedLLM) and len(eng.reputation) == 1
    engine_factory.get_engine.cache_clear()


# ------------------------------------------------------------------ worker heartbeat
def test_worker_health_states(monkeypatch):
    c = TestClient(app)
    fake = fakeredis.FakeRedis()
    monkeypatch.setattr(redis_client, "redis_client", fake)
    assert c.get("/health/worker").status_code == 503  # heartbeat nahi
    worker_health.beat(fake)
    ok = c.get("/health/worker")
    assert ok.status_code == 200 and ok.json()["status"] == "alive"
    fake.set(worker_health.HEARTBEAT_KEY, str(int(utcnow().timestamp()) - 99999))
    assert c.get("/health/worker").json()["status"] == "stale"
    monkeypatch.setattr(redis_client, "redis_client", BrokenRedis())
    r = c.get("/health/worker")
    assert r.status_code == 503 and r.json() == {"status": "unknown"}


def test_beat_never_raises_when_redis_down():
    worker_health.beat(BrokenRedis())  # exception nahi


# ------------------------------------------------------------------ global rate limit
def test_global_rate_limit_blocks_but_exempts_health(api, monkeypatch):
    monkeypatch.setattr(get_settings(), "global_rate_limit_per_minute", 3)
    codes = [api.get("/login").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
    blocked = api.get("/login")
    assert blocked.headers["retry-after"] == "60" and "detail" in blocked.json()
    assert api.get("/health").status_code == 200  # monitoring kabhi block nahi


def test_global_limiter_fails_open_with_breaker_when_redis_down(monkeypatch):
    monkeypatch.setattr(get_settings(), "global_rate_limit_per_minute", 1)
    broken = BrokenRedis()
    app.dependency_overrides[get_redis] = lambda: broken
    try:
        c = TestClient(app)
        assert [c.get("/login").status_code for _ in range(4)] == [200, 200, 200, 200]
        assert ratelimit._down_until.get(id(broken), 0) > 0  # breaker lag gaya (agli requests Redis ko chhoote nahi)
    finally:
        app.dependency_overrides.clear()


# ------------------------------------------------------------------ config
def test_database_url_normalized_for_render_style_urls():
    for raw in ("postgres://u:p@h:5432/d", "postgresql://u:p@h:5432/d"):
        assert Settings(_env_file=None, database_url=raw).database_url == "postgresql+psycopg://u:p@h:5432/d"
    keep = "postgresql+psycopg://u:p@h/d"
    assert Settings(_env_file=None, database_url=keep).database_url == keep
    assert Settings(_env_file=None, database_url="sqlite+pysqlite://").database_url == "sqlite+pysqlite://"


def test_log_format_defaults_json_in_production_only():
    assert Settings(_env_file=None).effective_log_format == "text"
    prod = Settings(_env_file=None, app_env="production", secret_key="x" * 40, encryption_key="k",
                    email_backend="smtp", base_url="https://a.example", payments_provider="stripe",
                    stripe_secret_key="sk_live_" + "a" * 24, stripe_webhook_secret="whsec_" + "b" * 16,
                    stripe_price_pro="price_pro1", stripe_price_business="price_biz1")
    assert prod.effective_log_format == "json"


# ------------------------------------------------------------------ retention
def test_purge_expired_removes_only_old_data(api, db, user_id, make_account, make_scan):
    api.signup_verify("ret@example.com")
    uid = user_id("ret@example.com")
    acc = make_account(uid)
    old = make_scan(acc, subject="old")
    fresh = make_scan(acc, subject="fresh")
    old.created_at = utcnow() - timedelta(days=100)
    db.add(Feedback(user_id=uid, scan_id=old.id, kind="not_phishing", verdict="PHISHING", score=90))
    db.add_all([
        EmailToken(user_id=uid, token_hash="a" * 64, purpose="verify", expires_at=utcnow() - timedelta(days=9)),
        EmailToken(user_id=uid, token_hash="b" * 64, purpose="verify", expires_at=utcnow() + timedelta(days=1)),
        Session(user_id=uid, session_hash="c" * 64, expires_at=utcnow() - timedelta(days=40)),
        AuditLog(user_id=uid, event="old", created_at=utcnow() - timedelta(days=400)),
        AuditLog(user_id=uid, event="recent", created_at=utcnow()),
    ])
    db.commit()

    counts = purge_expired(db, scan_days=90, audit_days=365)

    db.expire_all()
    assert counts["scans"] == 1 and counts["email_tokens"] == 1 and counts["audit_log"] == 1
    assert [s.subject for s in db.scalars(select(Scan)).all()] == ["fresh"]
    assert db.scalar(select(Scan).where(Scan.id == fresh.id)) is not None
    assert db.scalars(select(Feedback)).all() == []
    hashes = {e.token_hash for e in db.scalars(select(EmailToken)).all()}
    assert "a" * 64 not in hashes and "b" * 64 in hashes  # expired gaya, valid raha
    assert "recent" in {a.event for a in db.scalars(select(AuditLog)).all()}
    assert db.get(User, uid) is not None


# ------------------------------------------------------------------ key rotation
def test_key_rotation_reencrypts_and_old_key_no_longer_needed(monkeypatch, api, db, user_id, make_account):
    from cryptography.fernet import Fernet

    s = get_settings()
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(s, "encryption_key", old_key)
    api.signup_verify("rot@example.com")
    uid = user_id("rot@example.com")
    acc = make_account(uid)
    acc.refresh_token_encrypted = encrypt_secret("refresh-plain")
    acc.access_token_encrypted = encrypt_secret("access-plain")
    user = db.get(User, uid)
    user.totp_secret_encrypted = encrypt_secret("TOTPSECRET")
    db.commit()

    monkeypatch.setattr(s, "encryption_key", new_key)
    monkeypatch.setattr(s, "encryption_keys_old", old_key)
    assert decrypt_secret(acc.refresh_token_encrypted) == "refresh-plain"  # rotation ke dauran dono kaam
    assert reencrypt_all(db, dry_run=True)["rotated"] == 3

    counts = reencrypt_all(db)
    assert counts == {"rotated": 3, "undecryptable": 0}
    monkeypatch.setattr(s, "encryption_keys_old", "")  # ab purani key hata do
    db.expire_all()
    assert decrypt_secret(db.get(GmailAccountModel(), acc.id).refresh_token_encrypted) == "refresh-plain"
    assert decrypt_secret(db.get(User, uid).totp_secret_encrypted) == "TOTPSECRET"


def GmailAccountModel():
    from backend.app.models import GmailAccount
    return GmailAccount


# ------------------------------------------------------------------ legal pages
def test_privacy_and_terms_are_public_and_reflect_enabled_providers(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "operator_name", "Acme Security")
    monkeypatch.setattr(s, "vt_api_key", "")
    monkeypatch.setattr(s, "openai_api_key", "")
    c = TestClient(app)
    r = c.get("/privacy")
    assert r.status_code == 200 and "Acme Security" in r.text
    assert "OpenAI" not in r.text and "No link-reputation" in r.text
    monkeypatch.setattr(s, "openai_api_key", "oa")
    monkeypatch.setattr(s, "vt_api_key", "vt")
    text = c.get("/privacy").text
    assert "OpenAI" in text and "VirusTotal" in text
    assert str(s.scan_retention_days) in text
    assert c.get("/terms").status_code == 200
    assert "/privacy" in c.get("/login").text and "/terms" in c.get("/login").text  # footer links


# ------------------------------------------------------------------ security checklist items
def test_no_debug_or_admin_routes_exist():
    paths = {getattr(r, "path", "") for r in app.routes}
    assert not [p for p in paths if any(w in p.lower() for w in ("debug", "admin", "console", "shell", "metrics"))]


# ------------------------------------------------------------------ failure drills
def test_drill_redis_down_site_keeps_working(api, db, user_id):
    api.signup_verify("drill@example.com", gmail=True)
    app.dependency_overrides[get_redis] = lambda: BrokenRedis()
    assert api.login("drill@example.com").status_code == 200  # sessions DB mein hain, Redis par nahi
    assert api.get("/dashboard").status_code == 200
    assert api.get("/api/scans").status_code == 200
    assert api.get("/health").status_code == 200  # liveness Redis par depend nahi
    assert api.post("/api/gmail/connect").status_code in (200, 429, 503)  # fail-closed ya graceful, crash nahi
    assert api.post("/api/check", {"kind": "link", "url": "http://example.com/a"}).status_code == 200


def test_drill_redis_down_readiness_reports_degraded(monkeypatch):
    monkeypatch.setattr(redis_client, "redis_client", BrokenRedis())
    r = TestClient(app).get("/health/ready")
    assert r.status_code == 503 and r.json()["checks"]["redis"] is False
    assert "down" not in r.text  # error detail bahar nahi


def test_drill_database_down_returns_generic_500_without_leaking(api):
    from sqlalchemy.exc import OperationalError

    def broken_db():
        raise OperationalError("SELECT secret_table", {}, Exception("password authentication failed for user x"))
        yield  # pragma: no cover

    app.dependency_overrides[get_db] = broken_db
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/scans")
    assert r.status_code >= 500
    for leak in ("secret_table", "password authentication", "OperationalError", "Traceback"):
        assert leak not in r.text
    assert c.get("/health").status_code == 200  # liveness phir bhi zinda


def test_drill_gmail_429_is_retried_then_succeeds(monkeypatch):
    monkeypatch.setattr(gmail_api.time, "sleep", lambda *_: None)
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": {"status": "RESOURCE_EXHAUSTED"}})
        return httpx.Response(200, json={"emailAddress": "a@gmail.com", "historyId": "42"})

    client = gmail_api.GmailClient("tok", transport=httpx.MockTransport(handler))
    assert client.profile() == {"email": "a@gmail.com", "history_id": "42"}
    assert attempts["n"] == 3


def test_drill_gmail_429_forever_raises_transient_not_crash(monkeypatch):
    monkeypatch.setattr(gmail_api.time, "sleep", lambda *_: None)
    client = gmail_api.GmailClient("tok", transport=httpx.MockTransport(lambda r: httpx.Response(429, json={})))
    with pytest.raises(gmail_api.GmailTransient):
        client.profile()
