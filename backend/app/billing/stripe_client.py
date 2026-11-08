"""Minimal Stripe REST client (httpx). Card number/CVC hamare server ya browser-JS se kabhi nahi guzarte:
user Stripe ke hosted Checkout page par card dalta hai (PCI SAQ-A). Hum sirf session banate hain aur
signed webhook sunte hain. Host fixed hai (settings.stripe_api_base), koi user-controlled URL nahi (SSRF band)."""
import hashlib
import hmac
import logging
import time

import httpx

from backend.app.config import get_settings

log = logging.getLogger("aliguard.stripe")


class StripeError(Exception):
    """Stripe call nakam. Message mein Stripe ki tafseel nahi, sirf code."""


def _client() -> httpx.Client:
    s = get_settings()
    return httpx.Client(
        base_url=s.stripe_api_base, timeout=s.stripe_http_timeout_seconds,
        headers={"Authorization": f"Bearer {s.stripe_secret_key}", "Stripe-Version": "2025-09-30.clover"},
        follow_redirects=False,
    )


def _call(method: str, path: str, data: dict | None = None, params: dict | None = None,
          idempotency_key: str | None = None) -> dict:
    headers = {"Idempotency-Key": idempotency_key} if idempotency_key else {}
    try:
        with _client() as c:
            r = c.request(method, path, data=data, params=params, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("Stripe request nakam: %s", type(exc).__name__)
        raise StripeError("network") from exc
    if r.status_code >= 400:
        try:
            code = (r.json().get("error") or {}).get("code") or "unknown"
        except ValueError:
            code = "unknown"
        log.warning("Stripe error status=%s code=%s", r.status_code, str(code)[:40])
        raise StripeError(f"http_{r.status_code}")
    try:
        return r.json()
    except ValueError as exc:
        raise StripeError("bad_json") from exc


def create_checkout_session(*, user_id: str, email: str, price_id: str, plan_id: str, customer_id: str | None,
                            success_url: str, cancel_url: str, idempotency_key: str) -> dict:
    data = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": user_id,
        "metadata[user_id]": user_id,
        "metadata[plan]": plan_id,
        "subscription_data[metadata][user_id]": user_id,
        "payment_method_types[0]": "card",
    }
    if customer_id:
        data["customer"] = customer_id
    else:
        data["customer_email"] = email
    return _call("POST", "/v1/checkout/sessions", data=data, idempotency_key=idempotency_key)


def retrieve_checkout_session(session_id: str) -> dict:
    return _call("GET", f"/v1/checkout/sessions/{session_id}")


def retrieve_subscription(sub_id: str) -> dict:
    return _call("GET", f"/v1/subscriptions/{sub_id}")


def create_portal_session(customer_id: str, return_url: str) -> dict:
    return _call("POST", "/v1/billing_portal/sessions", data={"customer": customer_id, "return_url": return_url})


def verify_webhook(payload: bytes, sig_header: str | None, secret: str, tolerance: int,
                   now: float | None = None) -> bool:
    """Stripe-Signature: t=<ts>,v1=<hmac>[,v1=...]. HMAC-SHA256(secret, f"{t}.{payload}"), constant-time compare,
    timestamp tolerance (replay)."""
    if not sig_header or not secret or len(sig_header) > 1000:
        return False
    ts, sigs = None, []
    for part in sig_header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            ts = v
        elif k == "v1":
            sigs.append(v)
    if ts is None or not ts.isdigit() or not sigs:
        return False
    if abs((now if now is not None else time.time()) - int(ts)) > tolerance:
        return False
    expected = hmac.new(secret.encode(), ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)
