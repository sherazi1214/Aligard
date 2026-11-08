"""/api/gmail/* : Gmail connect (OAuth2 authorization code + PKCE), accounts list, disconnect.

Security:
- state: random, Redis mein single-use (getdel) + browser cookie se bandha (login-CSRF: attacker apna Gmail
  victim ke account se na jor sake) + usi user ki session lazmi.
- PKCE S256 verifier sirf server (Redis) mein rehta hai.
- Tokens Fernet se encrypted; API kabhi tokens wapas nahi deti.
- Har query mein user_id filter; doosre user ka account 404.
"""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import uuid
from datetime import timedelta
from urllib.parse import urlencode

import redis
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app.auth import service
from backend.app.auth.deps import current_user, get_redis, optional_user, require_csrf
from backend.app.billing import service as billing_service
from backend.app.billing.deps import require_plan
from backend.app.config import get_settings
from backend.app.db import get_db
from backend.app.gmail import google
from backend.app.models import GmailAccount, utcnow
from backend.app.ratelimit import allow, client_ip
from backend.app.security import decrypt_secret, encrypt_secret

log = logging.getLogger("aliguard.gmail")
router = APIRouter(prefix="/api/gmail", tags=["gmail"])

STATE_COOKIE = "aliguard_oauth_state"
_STATE_PREFIX = "gmail:oauth:"
_MAX_CODE_LEN = 2048
_MAX_STATE_LEN = 100


def _state_key(state: str) -> str:
    return _STATE_PREFIX + hashlib.sha256(state.encode()).hexdigest()  # raw state Redis mein nahi


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _done(result: str) -> RedirectResponse:
    """Callback ka nateeja: sirf fixed code URL mein (koi Google/user text nahi), cookie saaf."""
    resp = RedirectResponse(f"/dashboard?gmail={result}", status_code=303)
    resp.delete_cookie(STATE_COOKIE, path="/api/gmail")
    resp.headers["Cache-Control"] = "no-store"
    return resp


class ConnectIn(BaseModel):
    """User ne jo Gmail address type kiya (optional). Google ko login_hint ke tor par jata hai."""
    email: str | None = Field(default=None, max_length=254)


def _norm_email(value: str | None) -> str | None:
    """Valid-lagne wala email lowercase mein, warna None."""
    if not value:
        return None
    v = value.strip().lower()
    if len(v) > 254 or v.count("@") != 1 or " " in v:
        return None
    local, domain = v.split("@")
    return v if local and "." in domain else None


def _same_mailbox(a: str, b: str) -> bool:
    """Gmail mein dots aur +tag se mailbox nahi badalta: ali.k+x@gmail.com == alik@gmail.com."""
    def canon(e: str) -> str:
        local, domain = e.split("@")
        if domain in ("gmail.com", "googlemail.com"):
            return local.split("+")[0].replace(".", "") + "@gmail.com"
        return e
    return canon(a) == canon(b)


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


# ---------- list ----------
@router.get("/accounts")
def list_accounts(auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, _ = auth
    s = get_settings()
    plan = billing_service.plan_for_user(db, user.id)
    rows = db.scalars(
        select(GmailAccount).where(GmailAccount.user_id == user.id).order_by(GmailAccount.created_at)
    ).all()
    return {
        "configured": s.gmail_configured,
        "max_accounts": min(s.gmail_max_accounts_per_user, plan.max_gmail_accounts) if plan else 0,
        "accounts": [
            {
                "id": str(a.id),
                "email": a.google_email,
                "status": a.status,
                "last_run_at": _iso(a.last_run_at),
                "created_at": _iso(a.created_at),
            }
            for a in rows
        ],
    }


def _active_count(db: DbSession, user_id) -> int:
    return db.scalar(
        select(func.count()).select_from(GmailAccount).where(
            GmailAccount.user_id == user_id, GmailAccount.status != "disconnected"
        )
    ) or 0


# ---------- connect ----------
@router.post("/connect", dependencies=[Depends(require_csrf)])
def connect(response: Response, payload: ConnectIn | None = Body(default=None), auth=Depends(require_plan), db: DbSession = Depends(get_db),
            r=Depends(get_redis)):
    s = get_settings()
    if not s.gmail_configured:
        raise HTTPException(503, "Gmail connect abhi configure nahi hai")
    user, _ = auth
    if not allow(r, f"rl:gmail:connect:{user.id}", 10, 3600):
        raise HTTPException(429, "Bohat zyada koshishein. Thori der baad dobara try karein")
    # Account limit callback mein enforce hoti hai: needs_reauth account ko dobara connect karne
    # ke liye bhi OAuth shuru hona chahiye, chahe user ki account limit pehle hi full ho.

    hint = _norm_email(payload.email) if payload else None
    if payload and payload.email and payload.email.strip() and hint is None:
        raise HTTPException(422, "Sahi Gmail address likhein (jaise name@gmail.com)")

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)  # 86 chars (RFC 7636: 43-128)
    try:
        r.set(_state_key(state), json.dumps({"u": str(user.id), "v": verifier, "e": hint}), ex=s.oauth_state_ttl_seconds)
    except redis.RedisError as exc:
        # Fail-closed: state store ke baghair OAuth shuru nahi karte
        log.warning("OAuth state store nakam: %s", type(exc).__name__)
        raise HTTPException(503, "Abhi connect nahi ho sakta. Thori der baad try karein") from exc

    response.set_cookie(
        STATE_COOKIE, state, max_age=s.oauth_state_ttl_seconds, httponly=True,
        secure=s.secure_cookies, samesite="lax", path="/api/gmail",
    )
    response.headers["Cache-Control"] = "no-store"
    params = {
        "client_id": s.google_client_id,
        "redirect_uri": s.oauth_redirect_uri,
        "response_type": "code",
        "scope": google.GMAIL_SCOPE,
        "state": state,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
        "access_type": "offline",  # refresh token chahiye
        "prompt": "select_account consent",  # account chooser + har bar refresh token ki zamanat
        "include_granted_scopes": "false",
    }
    if hint:
        params["login_hint"] = hint  # Google isi account ko pehle se chun kar dikhata hai
    return {"auth_url": f"{google.AUTH_URL}?{urlencode(params)}"}


# ---------- callback (Google browser ko yahan redirect karta hai, isliye GET) ----------
@router.get("/callback", include_in_schema=False)
def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None,
             auth=Depends(optional_user), db: DbSession = Depends(get_db), r=Depends(get_redis)):
    if auth is None:
        return _done("session")
    user, _ = auth
    if error:
        return _done("denied")  # error text kabhi aage nahi jata
    if not code or not state or len(code) > _MAX_CODE_LEN or len(state) > _MAX_STATE_LEN:
        return _done("error")

    # 1) browser-binding: state cookie wahi honi chahiye jo connect par is browser ko mili thi
    cookie_state = request.cookies.get(STATE_COOKIE) or ""
    if not hmac.compare_digest(cookie_state.encode(), state.encode()):
        log.warning("OAuth callback: state cookie mismatch")
        return _done("error")

    # 2) single-use state Redis se
    try:
        raw = r.getdel(_state_key(state))
    except redis.RedisError as exc:
        log.warning("OAuth state read nakam: %s", type(exc).__name__)
        return _done("error")
    if raw is None:
        return _done("error")  # expire ho gayi ya replay
    try:
        record = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        state_user, verifier = record["u"], record["v"]
        expected_email = record.get("e")
    except (ValueError, KeyError, TypeError):
        return _done("error")
    if state_user != str(user.id):
        log.warning("OAuth callback: state kisi aur user ki thi")
        return _done("error")

    # 3) code -> tokens
    try:
        tokens = google.exchange_code(code, verifier)
    except google.GoogleError:
        return _done("error")
    access = tokens["access_token"]
    refresh = tokens.get("refresh_token") if isinstance(tokens.get("refresh_token"), str) else None
    scopes = str(tokens.get("scope", "")).split()

    def _abort(result: str) -> RedirectResponse:
        # Jo token mil chuka usay Google par bhi revoke kar do, hum ne rakhna nahi
        google.revoke(refresh or access)
        return _done(result)

    if google.GMAIL_SCOPE not in scopes:
        return _abort("scope")
    if not refresh:
        return _abort("error")
    try:
        email = google.fetch_profile_email(access)
    except google.GoogleError:
        return _abort("error")

    if expected_email and not _same_mailbox(expected_email, email):
        return _abort("mismatch")  # user ne X type kiya tha par Google mein Y se login kiya

    try:
        expires_in = int(tokens.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600
    expires_in = max(60, min(expires_in, 86400))

    s = get_settings()
    existing = db.scalar(
        select(GmailAccount).where(GmailAccount.user_id == user.id, GmailAccount.google_email == email)
    )
    plan = billing_service.plan_for_user(db, user.id)
    if plan is None:
        return _abort("plan")  # payment/plan ke baghair inbox connect nahi
    if existing is None and _active_count(db, user.id) >= min(s.gmail_max_accounts_per_user, plan.max_gmail_accounts):
        return _abort("limit")
    acc = existing or GmailAccount(user_id=user.id, google_email=email)
    acc.refresh_token_encrypted = encrypt_secret(refresh)
    acc.access_token_encrypted = encrypt_secret(access)
    acc.access_expires_at = utcnow() + timedelta(seconds=expires_in)
    acc.scopes = " ".join(scopes)[:500]
    acc.status = "active"
    acc.last_error = None
    if existing is None:
        db.add(acc)
    service.audit(db, "gmail_connected", user.id, client_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # do tabs ek sath connect hue
        return _done("error")
    return _done("connected")


# ---------- disconnect ----------
@router.post("/accounts/{account_id}/disconnect", dependencies=[Depends(require_csrf)])
def disconnect(account_id: uuid.UUID, request: Request, auth=Depends(current_user),
               db: DbSession = Depends(get_db)):
    user, _ = auth
    acc = db.scalar(
        select(GmailAccount).where(GmailAccount.id == account_id, GmailAccount.user_id == user.id)
    )
    if acc is None:
        raise HTTPException(404, "Account nahi mila")  # doosre user ka ho ya na ho, jawab ek jaisa
    token = None
    if acc.refresh_token_encrypted:
        token = decrypt_secret(acc.refresh_token_encrypted)
    if token is None and acc.access_token_encrypted:
        token = decrypt_secret(acc.access_token_encrypted)
    revoked = google.revoke(token) if token else False
    # Tokens har haal mein delete (revoke nakam bhi ho to hamare paas se jaate hain)
    acc.refresh_token_encrypted = None
    acc.access_token_encrypted = None
    acc.access_expires_at = None
    acc.status = "disconnected"
    acc.last_error = None
    service.audit(db, "gmail_disconnected", user.id, client_ip(request))
    db.commit()
    return {"status": "disconnected", "revoked": revoked}
