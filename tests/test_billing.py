"""Plans + payments: gating, free/paid flows, Stripe checkout, signed webhook, IDOR, replay, config safety."""
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from backend.app.billing import service, stripe_client
from backend.app.config import Settings, get_settings
from backend.app.models import AuditLog, GmailAccount, PaymentEvent, Subscription

WH_SECRET = "whsec_" + "t" * 20
PW = "correct-horse-battery-9"


@pytest.fixture
def stripe_mode(monkeypatch):
    s = get_settings()
    for k, v in {"payments_provider": "stripe", "stripe_secret_key": "sk_test_" + "a" * 24,
                 "stripe_webhook_secret": WH_SECRET, "stripe_price_pro": "price_pro1",
                 "stripe_price_business": "price_biz1"}.items():
        monkeypatch.setattr(s, k, v)
    return s


def _user(api, email="u@example.com", plan=None):
    api.signup_verify(email, plan=plan)
    assert api.login(email).status_code == 200
    return email


def _sub(db, user_id):
    db.expire_all()
    return db.get(Subscription, user_id)


def _stripe_sub(uid, price="price_pro1", status="active", sub_id="sub_1", end=None, cust="cus_1", **kw):
    end = end or int(time.time()) + 30 * 86400
    return {"id": sub_id, "status": status, "customer": cust, "current_period_end": end,
            "metadata": {"user_id": str(uid)}, "items": {"data": [{"price": {"id": price}}]}, **kw}


def _signed(payload: dict, secret=WH_SECRET, ts=None):
    raw = json.dumps(payload).encode()
    ts = int(ts if ts is not None else time.time())
    sig = hmac.new(secret.encode(), str(ts).encode() + b"." + raw, hashlib.sha256).hexdigest()
    return raw, {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def _event(etype, obj, eid=None, created=None):
    return {"id": eid or f"evt_{uuid.uuid4().hex[:12]}", "type": etype, "created": created or int(time.time()),
            "data": {"object": obj}}


def _hook(api, payload, **kw):
    raw, headers = _signed(payload, **kw)
    return api.c.post("/api/billing/webhook", content=raw, headers=headers)


# ---------------------------------------------------------------- gating
def test_no_plan_blocks_every_product_endpoint(api):
    _user(api)
    me = api.get("/api/auth/me").json()
    assert me["billing"]["active"] is False and me["billing"]["plan"] is None and me["gmail_connected"] is False
    assert api.get("/api/scans").status_code == 402
    assert api.get("/api/scans/stats").status_code == 402
    assert api.get("/api/settings").status_code == 402
    assert api.post("/api/gmail/connect").status_code == 402
    assert api.post("/api/check", {"kind": "link", "url": "http://example.com"}).status_code == 402
    assert api.get("/api/billing/plans").status_code == 200  # plans page ke liye khula


def test_plans_listing_requires_login_and_hides_nothing_secret(api):
    assert api.get("/api/billing/plans").status_code == 401
    _user(api)
    body = api.get("/api/billing/plans").json()
    assert [p["id"] for p in body["plans"]] == ["free", "pro", "business"]
    assert [p["card_required"] for p in body["plans"]] == [False, True, True]
    assert "price_" not in json.dumps(body) and "sk_" not in json.dumps(body)


def test_gmail_gate_until_inbox_connected(api, db, user_id, make_account):
    email = _user(api)
    assert api.post("/api/billing/free", {}).status_code == 200
    for path in ("/api/scans", "/api/scans/stats"):
        r = api.get(path)
        assert r.status_code == 428 and r.json()["detail"] == "gmail_required"
    assert api.post("/api/check", {"kind": "link", "url": "http://example.com"}).status_code == 428
    assert api.get("/api/settings").status_code == 200  # settings plan se khulti hai, Gmail se nahi
    make_account(user_id(email))
    assert api.get("/api/scans").status_code == 200
    assert api.get("/api/auth/me").json()["gmail_connected"] is True


def test_needs_reauth_inbox_does_not_count_as_connected(api, user_id, make_account):
    email = _user(api)
    api.post("/api/billing/free", {})
    make_account(user_id(email), status="needs_reauth")
    assert api.get("/api/scans").status_code == 428


# ---------------------------------------------------------------- free plan
def test_free_plan_needs_no_card_and_requires_csrf(api, db, user_id):
    email = _user(api)
    assert api.post("/api/billing/free", {}, csrf=False).status_code == 403
    r = api.post("/api/billing/free", {})
    assert r.status_code == 200 and r.json()["current"]["plan"] == "free" and r.json()["current"]["active"]
    assert _sub(db, user_id(email)).provider == "none"


def test_free_plan_limits_one_inbox_and_no_telegram(api, db, user_id, make_account):
    email = _user(api)
    api.post("/api/billing/free", {})
    make_account(user_id(email), google_email="one@gmail.com")
    assert api.get("/api/gmail/accounts").json()["max_accounts"] == 1
    assert api.post("/api/settings/telegram/link", {}).status_code == 402
    assert api.c.patch("/api/settings", json={"telegram_alerts": True},
                       headers={"X-CSRF-Token": api.c.cookies.get("aliguard_csrf", "")}).status_code == 402


def test_free_plan_manual_check_limit_is_lower_than_paid(api, db, user_id, make_account, monkeypatch):
    email = _user(api)
    api.post("/api/billing/free", {})
    make_account(user_id(email))
    monkeypatch.setattr(get_settings(), "check_user_limit", 1000)
    codes = [api.post("/api/check", {"kind": "message", "text": "hi"}).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


# ---------------------------------------------------------------- mock provider (dev)
def test_mock_checkout_flow_activates_paid_plan(api, db, user_id):
    email = _user(api)
    r = api.post("/api/billing/checkout", {"plan": "pro"})
    assert r.status_code == 200 and r.json()["url"].startswith("/billing/mock?token=")
    assert _sub(db, user_id(email)) is None  # checkout shuru karne se plan nahi milta
    token = r.json()["url"].split("token=")[1]
    done = api.post("/api/billing/mock/complete", {"token": token})
    assert done.status_code == 200 and done.json()["current"]["plan"] == "pro" and done.json()["current"]["active"]
    assert api.post("/api/gmail/connect").status_code == 200


def test_mock_token_is_bound_to_user_signed_and_expiring(api, api2, db, user_id):
    _user(api, "a@example.com")
    _user(api2, "b@example.com")
    token = api.post("/api/billing/checkout", {"plan": "business"}).json()["url"].split("token=")[1]
    assert api2.post("/api/billing/mock/complete", {"token": token}).status_code == 400  # doosre user ka token
    assert api.post("/api/billing/mock/complete", {"token": token[:-3] + "000"}).status_code == 400  # tampered
    uid, plan, _exp, sig = token.split(".")
    forged = f"{uid}.business.{int(time.time()) + 99999}.{sig}"
    assert api.post("/api/billing/mock/complete", {"token": forged}).status_code == 400
    assert _sub(db, user_id("a@example.com")) is None


def test_mock_complete_is_404_in_stripe_mode(api, stripe_mode):
    _user(api)
    assert api.post("/api/billing/mock/complete", {"token": "x" * 40}).status_code == 404


def test_checkout_rejects_free_unknown_plan_and_extra_fields(api):
    _user(api)
    for body in ({"plan": "free"}, {"plan": "enterprise"}, {"plan": "pro", "price": 1}, {}):
        assert api.post("/api/billing/checkout", body).status_code == 422, body
    assert api.post("/api/billing/checkout", {"plan": "pro"}, csrf=False).status_code == 403


# ---------------------------------------------------------------- stripe checkout
def test_stripe_checkout_uses_server_side_price_and_urls(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    seen = {}

    def fake_create(**kw):
        seen.update(kw)
        return {"url": "https://checkout.stripe.com/c/pay/cs_test_abc"}

    monkeypatch.setattr(stripe_client, "create_checkout_session", fake_create)
    r = api.post("/api/billing/checkout", {"plan": "business"})
    assert r.status_code == 200 and r.json()["url"].startswith("https://checkout.stripe.com/")
    assert seen["price_id"] == "price_biz1" and seen["user_id"] == str(user_id(email))
    assert seen["success_url"].startswith(stripe_mode.base_url.rstrip("/") + "/billing/success?session_id=")
    assert seen["cancel_url"].startswith(stripe_mode.base_url.rstrip("/") + "/plans")
    assert _sub(db, user_id(email)) is None  # redirect se plan activate nahi hota


def test_stripe_checkout_refuses_foreign_redirect_host_and_provider_errors(api, stripe_mode, monkeypatch):
    _user(api)
    monkeypatch.setattr(stripe_client, "create_checkout_session", lambda **kw: {"url": "https://evil.example/pay"})
    assert api.post("/api/billing/checkout", {"plan": "pro"}).status_code == 502

    def boom(**kw):
        raise stripe_client.StripeError("http_500")

    monkeypatch.setattr(stripe_client, "create_checkout_session", boom)
    r = api.post("/api/billing/checkout", {"plan": "pro"})
    assert r.status_code == 502 and "http_500" not in r.text


def test_no_second_checkout_or_free_downgrade_while_paid_active(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    db.add(Subscription(user_id=user_id(email), plan="pro", status="active", provider="stripe",
                        provider_subscription_id="sub_1", provider_customer_id="cus_1",
                        current_period_end=datetime.now(UTC) + timedelta(days=20)))
    db.commit()
    monkeypatch.setattr(stripe_client, "create_checkout_session", lambda **kw: pytest.fail("double charge"))
    assert api.post("/api/billing/checkout", {"plan": "business"}).status_code == 409
    assert api.post("/api/billing/free", {}).status_code == 409
    assert _sub(db, user_id(email)).plan == "pro"


def test_checkout_rate_limited_per_user(api, stripe_mode, monkeypatch):
    _user(api)
    monkeypatch.setattr(get_settings(), "billing_user_limit", 2)
    monkeypatch.setattr(stripe_client, "create_checkout_session",
                        lambda **kw: {"url": "https://checkout.stripe.com/c/pay/cs_test_abc"})
    assert [api.post("/api/billing/checkout", {"plan": "pro"}).status_code for _ in range(3)] == [200, 200, 429]


# ---------------------------------------------------------------- webhook
def test_webhook_rejects_missing_bad_stale_signature(api, stripe_mode):
    payload = _event("customer.subscription.updated", _stripe_sub(uuid.uuid4()))
    raw = json.dumps(payload).encode()
    assert api.c.post("/api/billing/webhook", content=raw).status_code == 400
    assert api.c.post("/api/billing/webhook", content=raw,
                      headers={"Stripe-Signature": "t=1,v1=deadbeef"}).status_code == 400
    assert _hook(api, payload, secret="whsec_wrong" + "x" * 10).status_code == 400
    assert _hook(api, payload, ts=time.time() - 3600).status_code == 400  # replay: bohat purana timestamp
    assert _hook(api, payload).status_code == 200


def test_webhook_404_when_not_stripe_mode_and_size_limit(api, stripe_mode, monkeypatch):
    big = b"x" * (300 * 1024)
    assert api.c.post("/api/billing/webhook", content=big, headers={"Stripe-Signature": "t=1,v1=a"}).status_code == 413
    monkeypatch.setattr(get_settings(), "payments_provider", "mock")
    assert api.c.post("/api/billing/webhook", content=b"{}").status_code == 404


def test_checkout_completed_activates_plan_from_stripe_not_payload(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    uid = user_id(email)
    # payload "business" keh sakta hai, par asli subscription Stripe se aati hai (pro price)
    monkeypatch.setattr(stripe_client, "retrieve_subscription", lambda sid: _stripe_sub(uid, price="price_pro1"))
    ev = _event("checkout.session.completed", {
        "mode": "subscription", "payment_status": "paid", "client_reference_id": str(uid),
        "subscription": "sub_1", "customer": "cus_1", "metadata": {"plan": "business", "user_id": str(uid)}})
    r = _hook(api, ev)
    assert r.status_code == 200 and r.json()["result"] == "handled"
    sub = _sub(db, uid)
    assert (sub.plan, sub.status, sub.provider, sub.provider_customer_id) == ("pro", "active", "stripe", "cus_1")
    assert api.get("/api/auth/me").json()["billing"]["active"] is True
    assert "subscription_activated" in {e for (e,) in db.execute(select(AuditLog.event))}


def test_unpaid_checkout_session_does_not_activate(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    uid = user_id(email)
    monkeypatch.setattr(stripe_client, "retrieve_subscription", lambda sid: pytest.fail("should not fetch"))
    ev = _event("checkout.session.completed", {
        "mode": "subscription", "payment_status": "unpaid", "client_reference_id": str(uid), "subscription": "sub_1"})
    assert _hook(api, ev).json()["result"] == "ignored"
    assert _sub(db, uid) is None


def test_webhook_is_idempotent_and_ignores_out_of_order(api, db, user_id, stripe_mode):
    email = _user(api)
    uid = user_id(email)
    now = int(time.time())
    newer = _event("customer.subscription.updated", _stripe_sub(uid, status="past_due"), created=now)
    older = _event("customer.subscription.updated", _stripe_sub(uid, status="active"), created=now - 500)
    assert _hook(api, newer).json()["result"] == "handled"
    assert _hook(api, newer).json()["result"] == "duplicate"  # same event id dobara
    assert _hook(api, older).json()["result"] == "ignored"  # purana event naye ko overwrite nahi karta
    assert _sub(db, uid).status == "past_due"
    assert db.query(PaymentEvent).count() == 2


def test_failed_payment_and_cancellation_lock_the_product(api, db, user_id, stripe_mode):
    email = _user(api)
    uid = user_id(email)
    t = int(time.time())
    assert _hook(api, _event("customer.subscription.created", _stripe_sub(uid), created=t)).status_code == 200
    assert api.get("/api/billing/plans").json()["current"]["active"] is True
    _hook(api, _event("customer.subscription.updated", _stripe_sub(uid, status="past_due"), created=t + 1))
    assert api.get("/api/auth/me").json()["billing"]["active"] is False
    assert api.get("/api/scans").status_code == 402
    _hook(api, _event("customer.subscription.deleted", _stripe_sub(uid, status="canceled"), created=t + 2))
    assert _sub(db, uid).status == "canceled"


def test_unknown_price_and_unknown_user_are_ignored(api, db, user_id, stripe_mode):
    email = _user(api)
    uid = user_id(email)
    r = _hook(api, _event("customer.subscription.updated", _stripe_sub(uid, price="price_evil")))
    assert r.json()["result"] == "ignored" and _sub(db, uid) is None
    r = _hook(api, _event("customer.subscription.updated", _stripe_sub(uuid.uuid4())))
    assert r.json()["result"] == "ignored"
    assert _hook(api, _event("invoice.paid", {})).json()["result"] == "ignored"  # unrelated event


def test_old_subscription_cancel_does_not_kill_new_active_plan(api, db, user_id, stripe_mode):
    email = _user(api)
    uid = user_id(email)
    t = int(time.time())
    _hook(api, _event("customer.subscription.created", _stripe_sub(uid, sub_id="sub_new"), created=t))
    _hook(api, _event("customer.subscription.deleted", _stripe_sub(uid, sub_id="sub_old", status="canceled"),
                      created=t + 5))
    sub = _sub(db, uid)
    assert sub.status == "active" and sub.provider_subscription_id == "sub_new"


def test_webhook_failure_rolls_back_so_stripe_retries(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    uid = user_id(email)

    def down(sid):
        raise stripe_client.StripeError("network")

    monkeypatch.setattr(stripe_client, "retrieve_subscription", down)
    ev = _event("checkout.session.completed", {
        "mode": "subscription", "payment_status": "paid", "client_reference_id": str(uid), "subscription": "sub_1"})
    c = api.c
    c.raise_server_exceptions = False
    assert _hook(api, ev).status_code == 500
    assert db.query(PaymentEvent).count() == 0  # event "processed" mark nahi hua, retry kaam karega


# ---------------------------------------------------------------- sync (IDOR)
def test_sync_only_confirms_own_paid_session(api, api2, db, user_id, stripe_mode, monkeypatch):
    a, b = _user(api, "a@example.com"), _user(api2, "b@example.com")
    ua = user_id(a)
    cs = {"client_reference_id": str(ua), "mode": "subscription", "payment_status": "paid",
          "subscription": "sub_1", "customer": "cus_1"}
    monkeypatch.setattr(stripe_client, "retrieve_checkout_session", lambda sid: cs)
    monkeypatch.setattr(stripe_client, "retrieve_subscription", lambda sid: _stripe_sub(ua))
    sid = "cs_test_" + "a" * 20
    assert api2.post("/api/billing/sync", {"session_id": sid}).status_code == 404  # b ke liye a ki session nahi
    assert _sub(db, user_id(b)) is None
    assert api.post("/api/billing/sync", {"session_id": sid}).json()["current"]["plan"] == "pro"
    assert api.post("/api/billing/sync", {"session_id": "../etc/passwd"}).status_code == 422


def test_sync_unpaid_session_gives_no_plan(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    uid = user_id(email)
    monkeypatch.setattr(stripe_client, "retrieve_checkout_session", lambda sid: {
        "client_reference_id": str(uid), "mode": "subscription", "payment_status": "unpaid", "subscription": None})
    r = api.post("/api/billing/sync", {"session_id": "cs_test_" + "a" * 20})
    assert r.status_code == 200 and r.json()["current"]["active"] is False


# ---------------------------------------------------------------- portal
def test_portal_only_for_own_stripe_customer(api, db, user_id, stripe_mode, monkeypatch):
    email = _user(api)
    assert api.post("/api/billing/portal", {}).status_code == 404
    db.add(Subscription(user_id=user_id(email), plan="pro", status="active", provider="stripe",
                        provider_customer_id="cus_mine", provider_subscription_id="sub_1",
                        current_period_end=datetime.now(UTC) + timedelta(days=5)))
    db.commit()
    seen = {}
    monkeypatch.setattr(stripe_client, "create_portal_session",
                        lambda cid, ret: seen.update(c=cid) or {"url": "https://billing.stripe.com/p/session/x"})
    assert api.post("/api/billing/portal", {}).json()["url"].startswith("https://billing.stripe.com/")
    assert seen["c"] == "cus_mine"


# ---------------------------------------------------------------- units / config / worker
def test_verify_webhook_unit():
    raw = b'{"a":1}'
    ts = 1_700_000_000
    good = hmac.new(b"whsec_x", f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    ok = stripe_client.verify_webhook
    assert ok(raw, f"t={ts},v1={good}", "whsec_x", 300, now=ts + 10)
    assert ok(raw, f"t={ts},v1=bad,v1={good}", "whsec_x", 300, now=ts)  # key rotation: kai v1
    assert not ok(raw + b" ", f"t={ts},v1={good}", "whsec_x", 300, now=ts)  # body badla
    assert not ok(raw, f"t={ts},v1={good}", "whsec_x", 300, now=ts + 301)
    assert not ok(raw, f"t={ts},v1={good}", "", 300, now=ts)
    assert not ok(raw, None, "whsec_x", 300) and not ok(raw, "garbage", "whsec_x", 300)
    assert not ok(raw, f"t=abc,v1={good}", "whsec_x", 300)


def test_production_refuses_mock_payments_and_test_keys():
    base = {"_env_file": None, "app_env": "production", "secret_key": "x" * 40, "encryption_key": "k",
            "email_backend": "smtp", "base_url": "https://aliguard.example.com"}
    stripe = {"payments_provider": "stripe", "stripe_secret_key": "sk_live_" + "a" * 24,
              "stripe_webhook_secret": "whsec_" + "b" * 16, "stripe_price_pro": "price_1", "stripe_price_business": "price_2"}
    with pytest.raises(ValueError):
        Settings(**base)  # default mock => production mein band
    with pytest.raises(ValueError):
        Settings(**base, **{**stripe, "stripe_secret_key": "sk_test_" + "a" * 24})
    with pytest.raises(ValueError):
        Settings(**base, **{**stripe, "stripe_webhook_secret": ""})
    with pytest.raises(ValueError):
        Settings(**base, **{**stripe, "stripe_price_pro": ""})
    assert Settings(**base, **stripe).payments_provider == "stripe"


def test_entitlement_rules(db, user_id, api):
    now = datetime.now(UTC)
    mk = lambda **kw: Subscription(user_id=uuid.uuid4(), **kw)  # noqa: E731
    assert service.is_entitled(mk(plan="free", status="active"))
    assert not service.is_entitled(None)
    assert not service.is_entitled(mk(plan="free", status="canceled"))
    assert not service.is_entitled(mk(plan="pro", status="active"))  # period_end nahi => no
    assert service.is_entitled(mk(plan="pro", status="active", current_period_end=now + timedelta(days=1)))
    assert service.is_entitled(mk(plan="pro", status="active", current_period_end=now - timedelta(hours=5)))  # grace
    assert not service.is_entitled(mk(plan="pro", status="active", current_period_end=now - timedelta(days=3)))
    assert not service.is_entitled(mk(plan="pro", status="past_due", current_period_end=now + timedelta(days=1)))


def test_worker_scans_only_entitled_users(api, db, user_id, make_account, monkeypatch):
    from backend.app.worker import scheduler

    ok, lapsed, none = "ok@example.com", "lapsed@example.com", "none@example.com"
    api.signup_verify(ok, plan="pro")
    api.signup_verify(lapsed, plan="pro")
    api.signup_verify(none, plan=None)
    db.query(Subscription).filter(Subscription.user_id == user_id(lapsed)).update(
        {"current_period_end": datetime.now(UTC) - timedelta(days=10)})
    db.commit()
    accs = {e: make_account(user_id(e), google_email=f"{e.split('@')[0]}@gmail.com") for e in (ok, lapsed, none)}
    scanned = []
    monkeypatch.setattr(scheduler, "scan_account", lambda db_, aid, **kw: scanned.append(aid) or {"status": "ok"})
    scheduler.run_once()
    assert scanned == [accs[ok].id]


def test_delete_my_data_also_removes_subscription(api, db, user_id):
    email = _user(api)
    api.post("/api/billing/free", {})
    uid = user_id(email)
    r = api.c.delete("/api/settings/data?confirm=DELETE_MY_DATA",
                     headers={"X-CSRF-Token": api.c.cookies.get("aliguard_csrf", "")})
    assert r.status_code == 200
    db.expire_all()
    assert db.get(Subscription, uid) is None
    assert db.scalar(select(GmailAccount)) is None
