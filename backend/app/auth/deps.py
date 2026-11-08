"""FastAPI dependencies: Redis, CSRF, current user."""
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session as DbSession

from backend.app import redis_client
from backend.app.auth import service
from backend.app.config import get_settings
from backend.app.db import get_db
from backend.app.models import Session, User

SESSION_COOKIE = "aliguard_session"
CSRF_COOKIE = "aliguard_csrf"
CSRF_HEADER = "x-csrf-token"


def get_redis():
    return redis_client.redis_client


# ---------- CSRF: signed double-submit cookie + Origin check ----------
def _sign(raw: str) -> str:
    key = get_settings().secret_key.encode()
    return hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()[:32]


def _valid_csrf_value(value: str | None) -> bool:
    if not value or "." not in value or len(value) > 200:
        return False
    raw, _, sig = value.partition(".")
    return hmac.compare_digest(sig, _sign(raw))


def issue_csrf_cookie(request: Request, response: Response) -> str:
    """Valid cookie ho to wahi reuse, warna naya. JS isay padh kar header mein bhejta hai."""
    current = request.cookies.get(CSRF_COOKIE)
    if _valid_csrf_value(current):
        return current  # type: ignore[return-value]
    raw = secrets.token_urlsafe(24)
    value = f"{raw}.{_sign(raw)}"
    response.set_cookie(
        CSRF_COOKIE, value, httponly=False, samesite="lax", path="/",
        secure=get_settings().secure_cookies, max_age=60 * 60 * 24,
    )
    return value


def _allowed_origins() -> set[str]:
    s = get_settings()
    out = set(s.cors_origin_list)
    p = urlsplit(s.base_url)
    out.add(f"{p.scheme}://{p.netloc}")
    return out


def require_csrf(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin not in _allowed_origins():
        raise HTTPException(403, "Request origin allow nahi")
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not (_valid_csrf_value(cookie) and header and hmac.compare_digest(cookie, header)):
        raise HTTPException(403, "CSRF token ghalat ya missing")


# ---------- sessions ----------
def set_session_cookie(response: Response, token: str, minutes: int) -> None:
    response.set_cookie(
        SESSION_COOKIE, token, max_age=minutes * 60, httponly=True,
        secure=get_settings().secure_cookies, samesite="lax", path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def optional_user(request: Request, db: DbSession = Depends(get_db)) -> tuple[User, Session] | None:
    return service.load_session(db, request.cookies.get(SESSION_COOKIE))


def current_user(auth: tuple[User, Session] | None = Depends(optional_user)) -> tuple[User, Session]:
    if auth is None:
        raise HTTPException(401, "Login zaroori hai")
    return auth
