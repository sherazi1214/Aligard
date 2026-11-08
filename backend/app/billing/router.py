"""/api/billing/* : plans, free activation, checkout (Stripe hosted), webhook, portal.

Security:
- Paid plan sirf (a) verified Stripe webhook ya (b) server-to-server Stripe lookup (/sync) se active hota hai.
- Price/plan server tay karta hai (env Price ids); client sirf plan ka naam (enum) bhejta hai.
- Card data hamare paas kabhi nahi: Stripe-hosted Checkout.
- Webhook: HMAC signature + timestamp tolerance + event-id idempotency + raw body size limit.
- Har endpoint user-scoped (sirf apni subscription); CSRF + per-user rate limit.
"""
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app.auth import service as auth_service
from backend.app.auth.deps import current_user, get_redis, require_csrf
from backend.app.billing import service, stripe_client
from backend.app.billing.plans import PLANS, public_plans, stripe_price_id
from backend.app.config import get_settings
from backend.app.db import SessionLocal, get_db
from backend.app.models import PaymentEvent, Subscription
from backend.app.ratelimit import allow, client_ip

log = logging.getLogger("aliguard.billing")
router = APIRouter(prefix="/api/billing", tags=["billing"])

TOO_MANY = "Bohat zyada koshishein. Thori der baad dobara try karein"
_SESSION_ID_RE = re.compile(r"cs_(?:test|live)_[A-Za-z0-9]{10,200}")
_MAX_WEBHOOK_BYTES = 256 * 1024
_MOCK_TTL = 900


class PlanBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: Literal["pro", "business"]


class SyncBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=10, max_length=250, pattern=_SESSION_ID_RE.pattern)


class MockBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=20, max_length=300)


def _limit(r, user, what: str) -> None:
    if not allow(r, f"rl:billing:{what}:{user.id}", get_settings().billing_user_limit, 3600):
        raise HTTPException(429, TOO_MANY)


def _base() -> str:
    return get_settings().base_url.rstrip("/")


# ---------- read ----------
@router.get("/plans")
def plans(auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, _ = auth
    return {"provider": get_settings().payments_provider, "plans": public_plans(),
            "current": service.summary(db, user.id)}


# ---------- free (card nahi) ----------
@router.post("/free", dependencies=[Depends(require_csrf)])
def choose_free(request: Request, auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, _ = auth
    if service.activate_free(db, user.id) == "paid_active":
        raise HTTPException(409, "Aap ka paid plan chal raha hai. Pehle Manage billing se cancel karein.")
    auth_service.audit(db, "plan_free_selected", user.id, client_ip(request))
    db.commit()
    return {"status": "ok", "current": service.summary(db, user.id)}


# ---------- paid: checkout ----------
@router.post("/checkout", dependencies=[Depends(require_csrf)])
def checkout(body: PlanBody, request: Request, auth=Depends(current_user), db: DbSession = Depends(get_db),
             r=Depends(get_redis)):
    user, _ = auth
    s = get_settings()
    _limit(r, user, "checkout")
    sub = service.get_subscription(db, user.id)
    if service.is_entitled(sub) and service.has_live_paid_subscription(sub):
        # Double charge se bachao: chalte paid plan par doosra checkout nahi, portal se badlein
        raise HTTPException(409, "Aap ka paid plan pehle se active hai. Manage billing se badlein.")
    auth_service.audit(db, f"checkout_{body.plan}", user.id, client_ip(request))
    db.commit()

    if s.payments_provider == "mock":
        exp = int(time.time()) + _MOCK_TTL
        raw = f"{user.id}.{body.plan}.{exp}"
        sig = hmac.new(s.secret_key.encode(), b"mock:" + raw.encode(), hashlib.sha256).hexdigest()
        return {"url": f"/billing/mock?token={raw}.{sig}", "mode": "mock"}

    price_id = stripe_price_id(body.plan)
    if not price_id:
        raise HTTPException(503, "Ye plan abhi available nahi hai")
    try:
        session = stripe_client.create_checkout_session(
            user_id=str(user.id), email=user.email, price_id=price_id, plan_id=body.plan,
            customer_id=sub.provider_customer_id if sub and sub.provider == "stripe" else None,
            success_url=f"{_base()}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{_base()}/plans?checkout=cancelled",
            idempotency_key=f"co:{user.id}:{body.plan}:{secrets.token_hex(8)}",
        )
    except stripe_client.StripeError as exc:
        raise HTTPException(502, "Payment page abhi nahi ban saka. Thori der baad try karein.") from exc
    url = session.get("url")
    if not isinstance(url, str) or not url.startswith("https://checkout.stripe.com/"):
        log.error("Stripe checkout URL expected host par nahi")
        raise HTTPException(502, "Payment page abhi nahi ban saka. Thori der baad try karein.")
    return {"url": url, "mode": "stripe"}


# ---------- paid: success page ke baad server-side confirm (webhook late ho tab bhi) ----------
@router.post("/sync", dependencies=[Depends(require_csrf)])
def sync(body: SyncBody, request: Request, auth=Depends(current_user), db: DbSession = Depends(get_db),
         r=Depends(get_redis)):
    user, _ = auth
    s = get_settings()
    if s.payments_provider != "stripe":
        return {"current": service.summary(db, user.id)}
    _limit(r, user, "sync")
    try:
        cs = stripe_client.retrieve_checkout_session(body.session_id)
        # Sirf apni session: Stripe ne jo client_reference_id yaad rakha wo token se match karna chahiye
        if cs.get("client_reference_id") != str(user.id) or cs.get("mode") != "subscription":
            raise HTTPException(404, "Payment session nahi mili")
        if cs.get("payment_status") in ("paid", "no_payment_required") and cs.get("subscription"):
            sub_id = cs["subscription"] if isinstance(cs["subscription"], str) else cs["subscription"].get("id")
            stripe_sub = stripe_client.retrieve_subscription(sub_id)
            cust = cs.get("customer") if isinstance(cs.get("customer"), str) else None
            if service.apply_stripe_subscription(db, user.id, stripe_sub, int(time.time()), customer_id=cust):
                auth_service.audit(db, "subscription_synced", user.id, client_ip(request))
                db.commit()
    except stripe_client.StripeError as exc:
        raise HTTPException(502, "Payment status abhi confirm nahi ho saka. Thori der baad dobara dekhein.") from exc
    return {"current": service.summary(db, user.id)}


# ---------- paid: manage / cancel (Stripe Billing Portal) ----------
@router.post("/portal", dependencies=[Depends(require_csrf)])
def portal(auth=Depends(current_user), db: DbSession = Depends(get_db), r=Depends(get_redis)):
    user, _ = auth
    if get_settings().payments_provider != "stripe":
        raise HTTPException(404, "Not found")
    sub = service.get_subscription(db, user.id)
    if sub is None or sub.provider != "stripe" or not sub.provider_customer_id:
        raise HTTPException(404, "Koi paid subscription nahi mili")
    _limit(r, user, "portal")
    try:
        ps = stripe_client.create_portal_session(sub.provider_customer_id, f"{_base()}/settings")
    except stripe_client.StripeError as exc:
        raise HTTPException(502, "Billing page abhi nahi khul saka") from exc
    url = ps.get("url")
    if not isinstance(url, str) or not url.startswith("https://billing.stripe.com/"):
        raise HTTPException(502, "Billing page abhi nahi khul saka")
    return {"url": url}


# ---------- dev/test only: mock provider ----------
@router.post("/mock/complete", dependencies=[Depends(require_csrf)])
def mock_complete(body: MockBody, request: Request, auth=Depends(current_user), db: DbSession = Depends(get_db)):
    s = get_settings()
    if s.payments_provider != "mock" or s.is_production:
        raise HTTPException(404, "Not found")
    user, _ = auth
    try:
        uid, plan_id, exp, sig = body.token.split(".")
        expected = hmac.new(s.secret_key.encode(), f"mock:{uid}.{plan_id}.{exp}".encode(), hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(sig, expected) and int(exp) > time.time() and uid == str(user.id)
    except ValueError:
        ok = False
    if not ok or plan_id not in PLANS or not PLANS[plan_id].paid:
        raise HTTPException(400, "Test payment link ghalat ya expire ho gaya")
    service.activate_mock(db, user.id, plan_id)
    auth_service.audit(db, "subscription_mock_active", user.id, client_ip(request))
    db.commit()
    return {"current": service.summary(db, user.id)}


# ---------- webhook ----------
def _user_id_from(obj: dict) -> uuid.UUID | None:
    raw = (obj.get("metadata") or {}).get("user_id") or obj.get("client_reference_id")
    try:
        return uuid.UUID(str(raw)) if raw else None
    except ValueError:
        return None


def process_event(db: DbSession, event: dict) -> str:
    """Ek verified event. Returns 'duplicate' | 'handled' | 'ignored'. Exception => caller rollback (Stripe retry)."""
    etype = str(event.get("type", ""))[:64]
    eid = str(event.get("id", ""))[:96]
    obj = (event.get("data") or {}).get("object") or {}
    ts = int(event.get("created") or time.time())
    if not eid:
        return "ignored"
    try:
        db.add(PaymentEvent(event_id=eid, provider="stripe", type=etype))
        db.flush()
    except IntegrityError:
        db.rollback()
        return "duplicate"

    handled = False
    if etype == "checkout.session.completed":
        uid = _user_id_from(obj)
        sub_id = obj.get("subscription")
        if (uid and obj.get("mode") == "subscription" and isinstance(sub_id, str)
                and obj.get("payment_status") in ("paid", "no_payment_required")):
            stripe_sub = stripe_client.retrieve_subscription(sub_id)  # asli state Stripe se, event payload par nahi
            cust = obj.get("customer") if isinstance(obj.get("customer"), str) else None
            handled = service.apply_stripe_subscription(db, uid, stripe_sub, ts, customer_id=cust)
            if handled:
                auth_service.audit(db, "subscription_activated", uid, None)
    elif etype in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
        uid = _user_id_from(obj)
        if uid is None:
            row = db.scalar(select(Subscription).where(Subscription.provider_subscription_id == obj.get("id")))
            uid = row.user_id if row else None
        if uid:
            handled = service.apply_stripe_subscription(db, uid, obj, ts)
            if handled:
                auth_service.audit(db, f"subscription_{etype.rsplit('.', 1)[-1]}", uid, None)
    db.commit()
    return "handled" if handled else "ignored"


@router.post("/webhook", include_in_schema=False)
async def webhook(request: Request):
    s = get_settings()
    if s.payments_provider != "stripe":
        raise HTTPException(404, "Not found")
    declared = request.headers.get("content-length")
    if declared and (not declared.isdigit() or int(declared) > _MAX_WEBHOOK_BYTES):
        raise HTTPException(413, "Too large")
    chunks, total = [], 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_WEBHOOK_BYTES:
            raise HTTPException(413, "Too large")
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not stripe_client.verify_webhook(payload, request.headers.get("stripe-signature"),
                                        s.stripe_webhook_secret, s.webhook_tolerance_seconds):
        log.warning("Webhook signature reject")
        raise HTTPException(400, "Bad signature")
    try:
        event = json.loads(payload)
        if not isinstance(event, dict):
            raise ValueError
    except ValueError as exc:
        raise HTTPException(400, "Bad payload") from exc

    def _run() -> str:
        with SessionLocal() as db:
            try:
                return process_event(db, event)
            except Exception:
                db.rollback()
                raise

    try:
        result = await run_in_threadpool(_run)
    except Exception as exc:  # 5xx => Stripe baad mein dobara bhejega
        log.exception("Webhook processing nakam")
        raise HTTPException(500, "Processing failed") from exc
    return {"received": True, "result": result}
