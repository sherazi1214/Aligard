"""Plan catalogue. Server hi tay karta hai kaun sa plan kya deta hai; browser ka bheja hua kuch bhi price/limit
nahi banta. Free plan mein card ki zarurat nahi, Pro/Business mein hai."""
from dataclasses import dataclass

from backend.app.config import get_settings


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    paid: bool
    tagline: str
    max_gmail_accounts: int
    check_limit: int  # manual link/message checks per 10 minute
    telegram: bool
    features: tuple[str, ...]


PLANS: dict[str, Plan] = {
    "free": Plan(
        "free", "Free", False, "Try AliGuard on one inbox. No card needed.",
        max_gmail_accounts=1, check_limit=10, telegram=False,
        features=("1 Gmail inbox protected", "Automatic phishing detection and labels",
                  "10 manual link/message checks per 10 min", "Email alerts"),
    ),
    "pro": Plan(
        "pro", "Pro", True, "For people who live in their inbox.",
        max_gmail_accounts=3, check_limit=40, telegram=True,
        features=("Up to 3 Gmail inboxes", "Auto-quarantine of high-confidence phishing",
                  "Telegram + email alerts", "40 manual checks per 10 min"),
    ),
    "business": Plan(
        "business", "Business", True, "For teams and shared mailboxes.",
        max_gmail_accounts=10, check_limit=120, telegram=True,
        features=("Up to 10 Gmail inboxes", "Everything in Pro",
                  "120 manual checks per 10 min", "Priority support"),
    ),
}
ORDER = ("free", "pro", "business")


def get_plan(plan_id: str) -> Plan | None:
    return PLANS.get(plan_id)


def price_label(plan_id: str) -> str:
    s = get_settings()
    return {"free": "$0", "pro": s.price_pro_label, "business": s.price_business_label}[plan_id]


def stripe_price_id(plan_id: str) -> str | None:
    s = get_settings()
    return {"pro": s.stripe_price_pro, "business": s.stripe_price_business}.get(plan_id) or None


def plan_for_price(price_id: str) -> str | None:
    s = get_settings()
    for pid, configured in (("pro", s.stripe_price_pro), ("business", s.stripe_price_business)):
        if configured and configured == price_id:
            return pid
    return None


def public_plans() -> list[dict]:
    out = []
    for pid in ORDER:
        p = PLANS[pid]
        out.append({
            "id": p.id, "name": p.name, "paid": p.paid, "tagline": p.tagline,
            "price": price_label(pid), "interval": "month" if p.paid else None,
            "features": list(p.features), "max_gmail_accounts": p.max_gmail_accounts,
            "card_required": p.paid,
        })
    return out
