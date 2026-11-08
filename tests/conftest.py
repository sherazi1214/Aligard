import os

# Tests ke liye in-memory SQLite, taake Postgres ke baghair bhi chalein
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("GLOBAL_RATE_LIMIT_PER_MINUTE", "0")  # global limiter ko tests khud on karte hain
os.environ.setdefault("HIBP_ENABLED", "false")  # tests mein asli network call nahi
os.environ.setdefault("GOOGLE_CLIENT_ID", "test-client-id.apps.example")  # Google calls tests mein mock hoti hain
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "test-client-secret")

import re  # noqa: E402
import uuid  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402

import fakeredis  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from backend.app import models, passwords, ratelimit  # noqa: E402, F401
from backend.app.auth import router as auth_router  # noqa: E402
from backend.app.auth.deps import get_redis  # noqa: E402
from backend.app.db import Base, SessionLocal, engine  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import GmailAccount, Scan, Subscription, User  # noqa: E402
from backend.app.security import encrypt_secret  # noqa: E402

PW = "correct-horse-battery-9"


class Api:
    """TestClient wrapper: CSRF header khud lagata hai."""

    def __init__(self, mails):
        self.c = TestClient(app)
        self.mails = mails
        self.c.get("/login")  # csrf cookie

    def post(self, path, json=None, csrf=True, headers=None):
        h = dict(headers or {})
        if csrf:
            h.setdefault("X-CSRF-Token", self.c.cookies.get("aliguard_csrf", ""))
        return self.c.post(path, json=json or {}, headers=h)

    def session(self):
        vals = [c.value for c in self.c.cookies.jar if c.name == "aliguard_session"]
        return vals[-1] if vals else None

    def set_session(self, value):
        """Cookie jar mein ek hi aliguard_session rakhta hai (domain conflict se bachne ke liye)."""
        for c in [c for c in self.c.cookies.jar if c.name == "aliguard_session"]:
            self.c.cookies.jar.clear(c.domain, c.path, c.name)
        self.c.cookies.set("aliguard_session", value, domain="testserver.local", path="/")

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def last_token(self, to=None):
        for m in reversed(self.mails):
            if to is None or m[0] == to:
                found = re.search(r"token=([\w-]+)", m[2])
                if found:
                    return found.group(1)
        return None

    def signup_verify(self, email="user@example.com", pw=PW, plan="business", gmail=False):
        """Signup + verify. plan=None => koi plan nahi (billing tests); warna us plan ki active subscription seed."""
        assert self.post("/api/auth/signup", {"email": email, "password": pw}).status_code == 202
        r = self.post("/api/auth/verify-email", {"token": self.last_token(email)})
        assert r.status_code == 200, r.text
        if plan:
            with SessionLocal() as s:
                uid = s.scalar(select(User.id).where(User.email == email))
                s.add(Subscription(user_id=uid, plan=plan, status="active", provider="none",
                                   current_period_end=datetime.now(UTC) + timedelta(days=30)))
                if gmail:  # active inbox seed (dashboard/scanner is ke baghair 428 dete hain)
                    s.add(GmailAccount(
                        user_id=uid, google_email=f"inbox-{uid.hex[:8]}@gmail.com", status="active",
                        refresh_token_encrypted=encrypt_secret("seed-refresh"),
                        access_token_encrypted=encrypt_secret("seed-access"),
                        scopes="https://www.googleapis.com/auth/gmail.modify"))
                s.commit()

    def login(self, email="user@example.com", pw=PW):
        return self.post("/api/auth/login", {"email": email, "password": pw})


@pytest.fixture(autouse=True)
def _reset_rate_limit_breaker():
    ratelimit.reset_breaker()
    yield
    ratelimit.reset_breaker()


@pytest.fixture
def mails(monkeypatch):
    sent = []
    monkeypatch.setattr(auth_router, "safe_send", lambda to, subj, body: sent.append((to, subj, body)))
    return sent


@pytest.fixture
def api(mails, monkeypatch):
    Base.metadata.create_all(engine)
    fake = fakeredis.FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    monkeypatch.setattr(passwords, "is_breached", lambda pw: False)
    yield Api(mails)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def api2(api, mails):
    """Doosra alag browser/user (tenant isolation tests ke liye)."""
    return Api(mails)


@pytest.fixture
def user_id(db):
    def _get(email):
        db.expire_all()
        return db.scalar(select(User.id).where(User.email == email))

    return _get


@pytest.fixture
def make_account(db):
    def _make(owner_id, google_email="ali@gmail.com", status="active"):
        acc = GmailAccount(
            user_id=owner_id, google_email=google_email, status=status,
            refresh_token_encrypted=encrypt_secret("seed-refresh"),
            access_token_encrypted=encrypt_secret("seed-access"),
            scopes="https://www.googleapis.com/auth/gmail.modify",
        )
        db.add(acc)
        db.commit()
        return acc

    return _make


@pytest.fixture
def make_scan(db):
    counter = {"n": 0}

    def _make(acc, subject="Hello", sender="a@example.com", verdict="SAFE", score=5, action="none", **kw):
        counter["n"] += 1
        scan = Scan(
            user_id=acc.user_id, gmail_account_id=acc.id, gmail_message_id=kw.pop("mid", uuid.uuid4().hex),
            sender=sender, subject=subject, verdict=verdict, score=score, action_taken=action,
            reasons=kw.pop("reasons", ["reason"]), layer_scores=kw.pop("layer_scores", {"heuristics": 10.0, "ml": None}),
            urls=kw.pop("urls", []), model_version="test-1",
            created_at=datetime.now(UTC) + timedelta(seconds=counter["n"]),  # ordering saaf rahe
        )
        db.add(scan)
        db.commit()
        return scan

    return _make
