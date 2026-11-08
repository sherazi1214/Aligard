"""Worker ke asli rules: dedupe, crash recovery, lock, backoff, needs_reauth, account isolation.

Gmail aur engine fake hain (network nahi). Redis fakeredis hai; uski Lua eval ki jagah
compare-and-delete ka chhota stand-in use hota hai (fakeredis mein lupa install nahi).
"""
from types import SimpleNamespace

import fakeredis
import pytest
from sqlalchemy import func, select

from backend.app.config import get_settings
from backend.app.db import SessionLocal
from backend.app.gmail import api as gmail_api
from backend.app.gmail.tokens import NeedsReauth
from backend.app.models import GmailAccount, Scan, utcnow
from backend.app.worker import scanner, scheduler


class LockRedis(fakeredis.FakeRedis):
    """Sirf worker ka compare-and-delete lock-release script samajhta hai."""

    def eval(self, script, numkeys, *args):  # noqa: A003
        key, token = args[0], args[1]
        value = self.get(key)
        if value is not None and value.decode() == token:
            return self.delete(key)
        return 0


class FakeGmail:
    """GmailClient ka chhota stand-in. `actions` mein har Gmail-side action record hota hai."""

    def __init__(self, inbox=(), history_batches=None):
        self.inbox = list(inbox)
        self.batches = history_batches or {}
        self.actions: list[tuple[str, str]] = []
        self.fail_quarantine_once = False
        self.history_expired = False
        self.current_history = "100"

    def profile(self):
        return {"email": "x@gmail.com", "history_id": self.current_history}

    def list_inbox_ids(self, n):
        return self.inbox[:n]

    def history(self, start):
        if self.history_expired:
            raise gmail_api.GmailHistoryExpired("expired")
        return self.batches.get(start, gmail_api.HistoryBatch(items=[], next_start=None))

    def get_raw(self, message_id):
        return b"From: a@example.com\r\nSubject: " + message_id.encode() + b"\r\n\r\nbody"

    def get_headers(self, message_id):
        return [("From", "a@example.com"), ("Subject", message_id)]

    def quarantine(self, message_id):
        if self.fail_quarantine_once:
            self.fail_quarantine_once = False
            raise gmail_api.GmailTransient("http_503")
        self.actions.append(("quarantine", message_id))

    def label_suspicious(self, message_id):
        self.actions.append(("label", message_id))


def _verdict_for(subject):
    """Subject se verdict: 'phish*' => PHISHING, 'sus*' => SUSPICIOUS, warna SAFE."""
    if subject.startswith("phish"):
        return "PHISHING", 95, 0.95
    if subject.startswith("sus"):
        return "SUSPICIOUS", 55, 0.6
    return "SAFE", 3, 0.9


@pytest.fixture
def worker_env(api, monkeypatch):
    """Tables (api fixture) + fake redis + fake analyze + fake alerts. Fake Gmail per-account set hota hai."""
    r = LockRedis()
    clients: dict = {}
    alerts: list = []

    def fake_analyze(email):
        verdict, score, conf = _verdict_for(email.subject or "")
        return SimpleNamespace(
            verdict=verdict, score=score, confidence=conf, reasons=["r"], layer_scores={"heuristics": 1.0},
            defanged_urls=[], model_version="t-1",
        )

    class FakeAlerts:
        def __init__(self, *a, **k):
            pass

        def dispatch_scan(self, db, scan_id):
            alerts.append(scan_id)
            db.execute(Scan.__table__.update().where(Scan.id == scan_id).values(alert_state="sent"))
            db.commit()
            return "sent"

        def notify_user(self, *a, **k):
            alerts.append(("reauth", a[1] if len(a) > 1 else None))

    def fake_get_client(db, account):
        client = clients[account.id]
        if isinstance(client, Exception):
            raise client
        return client

    monkeypatch.setattr(scanner, "analyze", fake_analyze)
    monkeypatch.setattr(scanner, "AlertService", FakeAlerts)
    monkeypatch.setattr(scanner, "get_telegram_client", lambda: None)
    monkeypatch.setattr(scanner, "_get_client", fake_get_client)
    monkeypatch.setattr(scanner, "mark_needs_reauth", scanner.mark_needs_reauth)
    return SimpleNamespace(r=r, clients=clients, alerts=alerts)


def _signup(api, email):
    api.signup_verify(email)


def _scans(db, acc_id=None):
    db.expire_all()
    q = select(Scan)
    if acc_id is not None:
        q = q.where(Scan.gmail_account_id == acc_id)
    return db.scalars(q).all()


def test_backfill_creates_scans_and_applies_actions(api, db, worker_env, user_id, make_account):
    _signup(api, "w1@example.com")
    acc = make_account(user_id("w1@example.com"))
    gm = FakeGmail(inbox=["hello1", "phish1", "sus1"])
    worker_env.clients[acc.id] = gm

    res = scanner.scan_account(db, acc.id, worker_env.r)

    assert res["status"] == "ok" and res["scanned"] == 3
    by_subject = {s.subject: s for s in _scans(db, acc.id)}
    assert by_subject["hello1"].action_taken == "none"
    assert by_subject["phish1"].action_taken == "quarantined"
    assert by_subject["sus1"].action_taken == "labeled"
    assert sorted(gm.actions) == [("label", "sus1"), ("quarantine", "phish1")]
    db.expire_all()
    acc = db.get(GmailAccount, acc.id)
    assert acc.history_id == "100" and acc.consecutive_failures == 0 and acc.last_run_at is not None


def test_no_duplicate_scan_action_or_alert_on_repeat_run(api, db, worker_env, user_id, make_account):
    _signup(api, "w2@example.com")
    acc = make_account(user_id("w2@example.com"))
    gm = FakeGmail(inbox=["phish1"])
    worker_env.clients[acc.id] = gm
    scanner.scan_account(db, acc.id, worker_env.r)

    # Gmail history wahi message dobara dikhaye (jaisa restart/overlap mein hota hai)
    gm.batches["100"] = gmail_api.HistoryBatch(items=[("phish1", "101")], next_start="101")
    scanner.scan_account(db, acc.id, worker_env.r)
    scanner.scan_account(db, acc.id, worker_env.r)

    assert len(_scans(db, acc.id)) == 1
    assert gm.actions == [("quarantine", "phish1")]  # Gmail par ek hi baar
    assert len(worker_env.alerts) == 1  # alert bhi ek hi baar


def test_crash_between_commit_and_gmail_action_is_recovered(api, db, worker_env, user_id, make_account):
    _signup(api, "w3@example.com")
    acc = make_account(user_id("w3@example.com"))
    gm = FakeGmail(inbox=["phish1"])
    gm.fail_quarantine_once = True  # pehli bar Gmail 503 (process crash jaisa: scan DB mein, action baqi)
    worker_env.clients[acc.id] = gm

    first = scanner.scan_account(db, acc.id, worker_env.r)
    assert first["status"] == "error"
    scans = _scans(db, acc.id)
    assert len(scans) == 1 and scans[0].action_taken == "pending" and scans[0].planned_action == "quarantine"

    # Agle run mein reconcile pending action poora kare, naya scan row na bane
    second = scanner.scan_account(db, acc.id, worker_env.r, force=True)
    assert second["status"] == "ok"
    scans = _scans(db, acc.id)
    assert len(scans) == 1 and scans[0].action_taken == "quarantined"
    assert gm.actions == [("quarantine", "phish1")]


def test_account_lock_prevents_overlap(api, db, worker_env, user_id, make_account):
    _signup(api, "w4@example.com")
    acc = make_account(user_id("w4@example.com"))
    gm = FakeGmail(inbox=["hello1"])
    worker_env.clients[acc.id] = gm
    worker_env.r.set(scanner._account_lock_key(acc.id), "other-worker", ex=60)

    res = scanner.scan_account(db, acc.id, worker_env.r)

    assert res["status"] == "locked" and _scans(db, acc.id) == []
    # Doosre worker ka lock hamare run ne chheda nahi
    assert worker_env.r.get(scanner._account_lock_key(acc.id)) == b"other-worker"


def test_lock_released_after_run(api, db, worker_env, user_id, make_account):
    _signup(api, "w5@example.com")
    acc = make_account(user_id("w5@example.com"))
    worker_env.clients[acc.id] = FakeGmail(inbox=[])
    scanner.scan_account(db, acc.id, worker_env.r)
    assert worker_env.r.get(scanner._account_lock_key(acc.id)) is None


def test_redis_down_fails_closed(api, db, worker_env, user_id, make_account):
    import redis as redis_lib

    _signup(api, "w6@example.com")
    acc = make_account(user_id("w6@example.com"))
    worker_env.clients[acc.id] = FakeGmail(inbox=["hello1"])

    class Broken:
        def set(self, *a, **k):
            raise redis_lib.RedisError("down")

    with pytest.raises(RuntimeError):
        scanner.scan_account(db, acc.id, Broken())
    assert _scans(db, acc.id) == []  # lock ke baghair kuch scan nahi


def test_failure_sets_exponential_backoff(api, db, worker_env, user_id, make_account, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "worker_backoff_base_seconds", 60)
    monkeypatch.setattr(s, "worker_backoff_max_seconds", 3600)
    _signup(api, "w7@example.com")
    acc = make_account(user_id("w7@example.com"))
    worker_env.clients[acc.id] = RuntimeError("boom")

    delays = []
    for _ in range(3):
        before = utcnow()
        assert scanner.scan_account(db, acc.id, worker_env.r, force=True)["status"] == "error"
        db.expire_all()
        a = db.get(GmailAccount, acc.id)
        delays.append(round((a.next_run_at - before).total_seconds() / 10) * 10)
    assert a.consecutive_failures == 3 and a.status == "active"
    assert delays == [60, 120, 240]


def test_invalid_grant_marks_needs_reauth_and_notifies_once(api, db, worker_env, user_id, make_account):
    _signup(api, "w8@example.com")
    acc = make_account(user_id("w8@example.com"))
    worker_env.clients[acc.id] = NeedsReauth("invalid_grant")

    assert scanner.scan_account(db, acc.id, worker_env.r)["status"] == "needs_reauth"
    db.expire_all()
    assert db.get(GmailAccount, acc.id).status == "needs_reauth"
    # Dobara run: account ab active nahi, na scan na dobara notice
    assert scanner.scan_account(db, acc.id, worker_env.r)["status"] == "inactive"
    assert [a for a in worker_env.alerts if isinstance(a, tuple)] == [("reauth", acc.user_id)]


def test_history_expired_falls_back_to_backfill(api, db, worker_env, user_id, make_account):
    _signup(api, "w9@example.com")
    acc = make_account(user_id("w9@example.com"))
    acc.history_id = "5"
    db.commit()
    gm = FakeGmail(inbox=["hello1", "hello2"])
    gm.history_expired = True
    gm.current_history = "900"
    worker_env.clients[acc.id] = gm

    res = scanner.scan_account(db, acc.id, worker_env.r)

    assert res["status"] == "ok" and res["scanned"] == 2
    db.expire_all()
    assert db.get(GmailAccount, acc.id).history_id == "900"


def test_budget_exceeded_does_not_move_bookmark(api, db, worker_env, user_id, make_account, monkeypatch):
    monkeypatch.setattr(get_settings(), "worker_run_budget_seconds", 0)
    _signup(api, "w10@example.com")
    acc = make_account(user_id("w10@example.com"))
    worker_env.clients[acc.id] = FakeGmail(inbox=["hello1", "hello2"])

    res = scanner.scan_account(db, acc.id, worker_env.r)

    assert res["status"] == "budget_exceeded"
    db.expire_all()
    assert db.get(GmailAccount, acc.id).history_id is None  # bookmark aage nahi gaya


def test_large_email_falls_back_to_headers_only(api, db, worker_env, user_id, make_account):
    _signup(api, "w11@example.com")
    acc = make_account(user_id("w11@example.com"))
    gm = FakeGmail(inbox=["phishBIG"])

    def too_large(_):
        raise gmail_api.GmailTooLarge("too_large")

    gm.get_raw = too_large
    worker_env.clients[acc.id] = gm

    assert scanner.scan_account(db, acc.id, worker_env.r)["scanned"] == 1
    assert _scans(db, acc.id)[0].subject == "phishBIG"


def test_scheduler_one_failing_account_does_not_stop_others_and_users_stay_isolated(
        api, api2, db, worker_env, user_id, make_account, monkeypatch):
    # Test DB SQLite StaticPool hai (ek shared connection), is liye yahan threads parallel nahi chala sakte;
    # parallel concurrency sirf Postgres par verify hoti hai (README mein likha hai).
    monkeypatch.setattr(get_settings(), "worker_concurrency", 1)
    _signup(api, "a@example.com")
    _signup(api2, "b@example.com")
    ua, ub = user_id("a@example.com"), user_id("b@example.com")
    good1 = make_account(ua, "g1@gmail.com")
    bad = make_account(ua, "bad@gmail.com")
    good2 = make_account(ub, "g2@gmail.com")
    worker_env.clients[good1.id] = FakeGmail(inbox=["hello-a"])
    worker_env.clients[bad.id] = RuntimeError("boom")
    worker_env.clients[good2.id] = FakeGmail(inbox=["phish-b"])

    summary = scheduler.run_once(session_factory=SessionLocal, redis_conn=worker_env.r)

    assert summary["accounts_selected"] == 3
    statuses = sorted(x["status"] for x in summary["results"])
    assert statuses == ["error", "ok", "ok"]
    db.expire_all()
    assert db.get(GmailAccount, bad.id).consecutive_failures == 1
    # Har scan sirf apne account ke owner ka
    for s in _scans(db):
        owner = db.get(GmailAccount, s.gmail_account_id).user_id
        assert s.user_id == owner
    assert db.scalar(select(func.count()).select_from(Scan).where(Scan.user_id == ub)) == 1

    # Backoff wala account agle (non-forced) cycle mein due nahi
    again = scheduler.run_once(session_factory=SessionLocal, redis_conn=worker_env.r)
    ids = {x["account_id"] for x in again["results"]}
    assert str(bad.id) not in ids
