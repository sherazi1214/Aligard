import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app import redis_client
from backend.app.config import Settings
from backend.app.main import app

client = TestClient(app)


def test_liveness():
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_ready_ok(monkeypatch):
    monkeypatch.setattr(redis_client, "check_redis", lambda: True)
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert r.json()["checks"] == {"database": True, "redis": True}


def test_ready_degraded_when_redis_down(monkeypatch):
    monkeypatch.setattr(redis_client, "check_redis", lambda: False)
    r = client.get("/health/ready")
    assert r.status_code == 503 and r.json()["status"] == "degraded"


def test_security_headers_present():
    h = client.get("/health").headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"


def test_cors_blocks_unknown_origin():
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_production_rejects_weak_secret():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", secret_key="short")


_STRIPE = {"payments_provider": "stripe", "stripe_secret_key": "sk_live_" + "a" * 24,
           "stripe_webhook_secret": "whsec_" + "b" * 16, "stripe_price_pro": "price_pro1",
           "stripe_price_business": "price_biz1"}


def test_production_accepts_strong_secret():
    s = Settings(
        _env_file=None, app_env="production", secret_key="x" * 40,
        encryption_key="k", email_backend="smtp",
        base_url="https://aliguard.example.com", **_STRIPE,
    )
    assert s.is_production
