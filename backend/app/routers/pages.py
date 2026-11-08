"""HTML pages (Jinja2, autoescape on). Saari logic /api/auth mein; yahan sirf shell."""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from backend.app.auth.deps import issue_csrf_cookie, optional_user
from backend.app.config import get_settings

WEB_DIR = Path(__file__).resolve().parents[3] / "web"
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
router = APIRouter(include_in_schema=False)


def _page(request: Request, name: str, **ctx):
    resp = templates.TemplateResponse(request, name, ctx)
    issue_csrf_cookie(request, resp)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.get("/")
def index(auth=Depends(optional_user)):
    return RedirectResponse("/dashboard" if auth else "/login", status_code=303)


@router.get("/signup")
def signup(request: Request):
    return _page(request, "signup.html")


@router.get("/login")
def login(request: Request):
    return _page(request, "login.html")


@router.get("/login/2fa")
def login_2fa(request: Request):
    return _page(request, "login_2fa.html")


@router.get("/verify-email")
def verify_email(request: Request):
    return _page(request, "verify.html")


@router.get("/forgot-password")
def forgot_password(request: Request):
    return _page(request, "forgot.html")


@router.get("/reset-password")
def reset_password(request: Request):
    return _page(request, "reset.html")


@router.get("/account")
def account(request: Request, auth=Depends(optional_user)):
    if auth is None:
        return RedirectResponse("/login", status_code=303)
    user, _ = auth
    return _page(request, "account.html", email=user.email, totp_enabled=user.totp_enabled)


@router.get("/dashboard")
def dashboard(request: Request, auth=Depends(optional_user)):
    if auth is None:
        return RedirectResponse("/login", status_code=303)
    user, _ = auth
    return _page(request, "dashboard.html", email=user.email)


@router.get("/settings")
def settings_page(request: Request, auth=Depends(optional_user)):
    if auth is None:
        return RedirectResponse("/login", status_code=303)
    user, _ = auth
    return _page(request, "settings.html", email=user.email)


def _legal_ctx() -> dict:
    s = get_settings()
    return {
        "operator": s.operator_name, "support_email": s.support_email,
        "retention_days": s.scan_retention_days, "audit_days": s.audit_retention_days,
        "vt_enabled": bool(s.vt_api_key), "llm_enabled": bool(s.openai_api_key),
        "telegram_enabled": s.telegram_configured,
    }


@router.get("/privacy")
def privacy(request: Request):
    return _page(request, "privacy.html", **_legal_ctx())


@router.get("/terms")
def terms(request: Request):
    return _page(request, "terms.html", **_legal_ctx())
