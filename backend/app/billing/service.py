"""Billing ka logic (HTTP se alag). Entitlement ka sach sirf yahan: subscriptions table."""
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session as DbSession

from backend.app.billing.plans import PLANS, Plan, plan_for_price
from backend.app.models import GmailAccount, Subscription, User, utcnow

log = logging.getLogger("aliguard.billing")

PERIOD_GRACE = timedelta(days=2)  # renewal webhook thora late ho to user achanak lock na ho
_STRIPE_STATUS = {
    "active": "active", "trialing": "active",
    "past_due": "past_due", "unpaid": "past_due",
    "canceled": "canceled", "incomplete_expired": "canceled",
    "incomplete": "incomplete", "paused": "past_due",
}


def get_subscription(db: DbSession, user_id) -> Subscription | None:
    return db.get(Subscription, user_id)


def is_entitled(sub: Subscription | None, now: datetime | None = None) -> bool:
    if sub is None or sub.status != "active" or sub.plan not in PLANS:
        return False
    if sub.plan == "free":
        return True
    now = now or utcnow()
    return sub.current_period_end is not None and sub.current_period_end + PERIOD_GRACE > now


def plan_for_user(db: DbSession, user_id) -> Plan | None:
    """Active plan, ya None (plan chuna hi nahi / expire / cancel / payment fail)."""
    sub = get_subscription(db, user_id)
    return PLANS[sub.plan] if is_entitled(sub) else None


def entitled_clause(now: datetime | None = None):
    """SQL condition (Subscription par): worker sirf entitled users ke inbox scan kare."""
    now = now or utcnow()
    return and_(
        Subscription.status == "active",
        or_(Subscription.plan == "free",
            and_(Subscription.current_period_end.is_not(None), Subscription.current_period_end > now - PERIOD_GRACE)),
    )


def has_active_gmail(db: DbSession, user_id) -> bool:
    return db.scalar(
        select(GmailAccount.id).where(GmailAccount.user_id == user_id, GmailAccount.status == "active").limit(1)
    ) is not None


def summary(db: DbSession, user_id) -> dict:
    sub = get_subscription(db, user_id)
    entitled = is_entitled(sub)
    return {
        "plan": sub.plan if sub else None,
        "status": sub.status if sub else None,
        "active": entitled,
        "provider": sub.provider if sub else None,
        "current_period_end": sub.current_period_end.isoformat() if sub and sub.current_period_end else None,
        "cancel_at_period_end": bool(sub and sub.cancel_at_period_end),
        "can_manage": bool(sub and sub.provider == "stripe" and sub.provider_customer_id),
    }


def _upsert(db: DbSession, user_id) -> Subscription:
    sub = db.get(Subscription, user_id)
    if sub is None:
        sub = Subscription(user_id=user_id, plan="free", status="incomplete", provider="none")
        db.add(sub)
    return sub


def activate_free(db: DbSession, user_id) -> str:
    """Returns 'ok' | 'paid_active' (paid plan chal raha hai, pehle usay cancel karna hoga)."""
    sub = get_subscription(db, user_id)
    if sub is not None and sub.plan != "free" and sub.status in ("active", "past_due") and sub.provider != "none":
        return "paid_active"
    sub = _upsert(db, user_id)
    sub.plan, sub.status, sub.provider = "free", "active", "none"
    sub.provider_subscription_id = sub.current_period_end = None
    sub.cancel_at_period_end = False
    return "ok"


def has_live_paid_subscription(sub: Subscription | None) -> bool:
    return bool(sub and sub.plan != "free" and sub.provider != "none" and sub.status in ("active", "past_due")
                and sub.provider_subscription_id)


def activate_mock(db: DbSession, user_id, plan_id: str) -> None:
    """Sirf dev/test provider. Production mein config hi start nahi hone deti."""
    sub = _upsert(db, user_id)
    sub.plan, sub.status, sub.provider = plan_id, "active", "mock"
    sub.provider_subscription_id = f"mock_{uuid.uuid4().hex[:16]}"
    sub.current_period_end = utcnow() + timedelta(days=30)
    sub.cancel_at_period_end = False


def _period_end(stripe_sub: dict) -> datetime | None:
    ts = stripe_sub.get("current_period_end")
    if ts is None:  # naye Stripe API versions mein ye subscription item par hota hai
        items = (stripe_sub.get("items") or {}).get("data") or []
        ts = items[0].get("current_period_end") if items else None
    return datetime.fromtimestamp(int(ts), UTC) if isinstance(ts, (int, float)) else None


def apply_stripe_subscription(db: DbSession, user_id, stripe_sub: dict, event_ts: int,
                              customer_id: str | None = None) -> bool:
    """Stripe subscription object se local plan update. Returns True agar kuch badla."""
    if db.get(User, user_id) is None:
        log.warning("Stripe subscription ka user maujood nahi")
        return False
    items = (stripe_sub.get("items") or {}).get("data") or []
    price_id = ((items[0].get("price") or {}).get("id")) if items else None
    plan_id = plan_for_price(price_id) if price_id else None
    if plan_id is None:
        log.warning("Stripe subscription ka price hamare plans mein nahi: ignore")
        return False
    sub_id = stripe_sub.get("id")
    status = _STRIPE_STATUS.get(str(stripe_sub.get("status")), "incomplete")
    sub = _upsert(db, user_id)
    if sub.last_event_ts and event_ts < sub.last_event_ts and sub.provider_subscription_id == sub_id:
        return False  # purana (out-of-order) event
    if (sub.provider == "stripe" and sub.provider_subscription_id and sub.provider_subscription_id != sub_id
            and status != "active" and sub.status == "active"):
        return False  # kisi purani subscription ka cancel naye chalte plan ko na girae
    sub.plan, sub.status, sub.provider = plan_id, status, "stripe"
    sub.provider_subscription_id = sub_id
    cust = customer_id or stripe_sub.get("customer")
    if isinstance(cust, str):
        sub.provider_customer_id = cust
    sub.current_period_end = _period_end(stripe_sub)
    sub.cancel_at_period_end = bool(stripe_sub.get("cancel_at_period_end") or stripe_sub.get("cancel_at"))
    sub.last_event_ts = max(sub.last_event_ts or 0, event_ts)
    return True
