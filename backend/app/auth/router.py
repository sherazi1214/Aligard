"""/api/auth/* endpoints. Sab sync def (threadpool); state-changing par CSRF lazmi."""
import logging
import secrets
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app import passwords
from backend.app.auth import service
from backend.app.auth import sso as sso_lib
from backend.app.auth.deps import (
    SESSION_COOKIE,
    clear_session_cookie,
    current_user,
    get_redis,
    issue_csrf_cookie,
    optional_user,
    require_csrf,
    set_session_cookie,
)
from backend.app.auth.schemas import (
    ChangePasswordBody,
    DisableTotpBody,
    EmailBody,
    LoginBody,
    MfaBody,
    ResetBody,
    SignupBody,
    TokenBody,
)
from backend.app.billing import service as billing_service
from backend.app.config import get_settings
from backend.app.db import SessionLocal, get_db
from backend.app.mailer import safe_send
from backend.app.models import Entitlement, SsoNonce, utcnow
from backend.app.ratelimit import allow, client_ip
from backend.app.security import hash_password, sha256_hex, verify_password

log = logging.getLogger("aliguard.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])

GENERIC_LOGIN_ERR = "Email ya password ghalat hai"
TOO_MANY = "Bohat zyada koshishein. Thori der baad dobara try karein"
SIGNUP_MSG = "Agar ye email naya hai to verification email bhej di gayi hai. Inbox check karein."
FORGOT_MSG = "Agar ye email registered hai to reset link bhej diya gaya hai."


def _limit(r, key: str, limit: int, window: int) -> None:
    if not allow(r, key, limit, window):
        raise HTTPException(429, TOO_MANY)


def _verify_link(raw: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/verify-email?token={raw}"


def _reset_link(raw: str) -> str:
    return f"{get_settings().base_url.rstrip('/')}/reset-password?token={raw}"


# ---------- background jobs (apni DB session; request session response ke baad band ho chuki hoti hai) ----------
def _send_verification(email: str) -> None:
    try:
        with SessionLocal() as db:
            user = service.get_user_by_email(db, email)
            if user is None or user.is_verified or not user.is_active:
                return
            raw = service.create_email_token(db, user, "verify", timedelta(hours=get_settings().verify_token_hours))
            db.commit()
        safe_send(email, "AliGuard: email verify karein",
                  f"Account verify karne ke liye ye link kholein (24 ghante valid):\n{_verify_link(raw)}\n\n"
                  "Agar aap ne signup nahi kiya to ye email ignore karein.")
    except Exception:
        log.exception("Verification email job fail")


def _send_reset(email: str, ip: str) -> None:
    try:
        with SessionLocal() as db:
            user = service.get_user_by_email(db, email)
            if user is None or not user.is_active:
                return
            raw = service.create_email_token(db, user, "reset", timedelta(minutes=get_settings().reset_token_minutes))
            service.audit(db, "password_reset_requested", user.id, ip)
            db.commit()
        safe_send(email, "AliGuard: password reset",
                  f"Password reset ke liye ye link kholein (jald expire hota hai, sirf ek bar chalta hai):\n"
                  f"{_reset_link(raw)}\n\nAgar aap ne request nahi ki to ye email ignore karein.")
    except Exception:
        log.exception("Reset email job fail")


def _check_new_password(password: str, email: str) -> None:
    errs = passwords.policy_errors(password, email)
    if not errs and passwords.is_breached(password):
        errs.append("Ye password pehle data leaks mein aa chuka hai, doosra chunein")
    if errs:
        raise HTTPException(422, "; ".join(errs))


# ---------- csrf / me ----------
@router.get("/csrf")
def csrf(request: Request, response: Response):
    issue_csrf_cookie(request, response)
    return {"ok": True}


@router.get("/me")
def me(auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, _ = auth
    return {
        "email": user.email, "is_verified": user.is_verified, "totp_enabled": user.totp_enabled,
        "billing": billing_service.summary(db, user.id),
        "gmail_connected": billing_service.has_active_gmail(db, user.id),
    }


# ---------- portal SSO handoff ----------
# aliguard-portal (marketing/signup portal) login ya purchase ke baad user ko yahan signed token
# ke sath bhejta hai. Portal ne khud email ki ownership verify ki hoti hai (apna signup/login ya
# Google OAuth), is route ka kaam sirf: (1) signature+expiry+nonce check (replay-proof),
# (2) usi email wala account yahan bhi bana/dhoond kar login karna, (3) agar koi service
# (plan) kharida gaya ho to Entitlement row daalna.
@router.get("/sso")
def sso_handoff(token: str, request: Request, response: Response,
                db: DbSession = Depends(get_db), r=Depends(get_redis)):
    s = get_settings()
    ip = client_ip(request)
    _limit(r, f"rl:sso:ip:{ip}", 20, 600)
    if not s.sso_shared_secret:
        raise HTTPException(404, "Not found")
    payload = sso_lib.verify_token(token)
    if payload is None:
        raise HTTPException(400, "Ye link ghalat ya expire ho chuka hai. Portal par dobara koshish karein.")
    if not payload.verified:
        # Portal ne email ownership verify nahi ki: is token par kisi (khaas kar existing) account mein login nahi
        raise HTTPException(400, "Portal par pehle apni email verify karein.")
    try:
        db.add(SsoNonce(nonce=payload.nonce))
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(400, "Ye link pehle istemal ho chuka hai.") from None

    user = service.get_user_by_email(db, payload.email)
    if user is None:
        # Portal ka token hi ownership proof hai (wahan email pehle se verified/OAuth se mila), isliye
        # yahan bhi verified bana dete hain. Password random: ye account yahan sirf SSO se login hoga.
        user = service.create_user(db, payload.email, hash_password(secrets.token_urlsafe(32)))
        user.is_verified = True
    elif not user.is_active:
        raise HTTPException(403, "Ye account band kar diya gaya hai.")
    elif not user.is_verified:
        user.is_verified = True

    if payload.service:
        exp_at = utcnow() + timedelta(days=30)
        existing = db.scalar(
            select(Entitlement).where(Entitlement.user_id == user.id, Entitlement.service == payload.service)
        )
        if existing:
            existing.expires_at = exp_at
        else:
            db.add(Entitlement(user_id=user.id, service=payload.service, expires_at=exp_at))

    if user.totp_enabled:
        # 2FA wale account ko SSO se 2FA bypass nahi karne dete: normal login (password + code) par bhejte hain
        service.audit(db, "sso_blocked_2fa", user.id, ip)
        db.commit()
        return RedirectResponse(f"{s.base_url.rstrip('/')}/login", status_code=302)

    # Purani session (agar browser mein koi aur account ki thi) revoke, phir nayi
    service.revoke_session_by_raw(db, request.cookies.get(SESSION_COOKIE))
    session_token = service.create_session(db, user, ip, request.headers.get("user-agent"))
    service.audit(db, "sso_login", user.id, ip)
    db.commit()

    # Gmail plan khareeda hai to dashboard seedha "Connect Gmail" (Google permission) shuru kar deta hai
    dest = "/dashboard?connect=gmail" if payload.service == "gmail" else "/dashboard"
    redirect = RedirectResponse(f"{s.base_url.rstrip('/')}{dest}", status_code=302)
    set_session_cookie(redirect, session_token, s.session_absolute_minutes)
    return redirect


# ---------- signup / verify ----------
@router.post("/signup", status_code=202, dependencies=[Depends(require_csrf)])
def signup(body: SignupBody, request: Request, bg: BackgroundTasks,
           db: DbSession = Depends(get_db), r=Depends(get_redis)):
    s = get_settings()
    _limit(r, f"rl:signup:ip:{client_ip(request)}", s.signup_ip_limit, 3600)
    _check_new_password(body.password, body.email)
    pw_hash = hash_password(body.password)  # hamesha hash: existing/new email ka timing ek jaisa
    email = service.normalize_email(body.email)
    created = False
    if service.get_user_by_email(db, email) is None:
        try:
            user = service.create_user(db, email, pw_hash)
            service.audit(db, "signup", user.id, client_ip(request))
            db.commit()
            created = True
        except IntegrityError:  # race: dusri request ne ek saath same email bana di
            db.rollback()
    if created:
        bg.add_task(_send_verification, email)
    else:
        bg.add_task(safe_send, email, "AliGuard: account pehle se maujood hai",
                    "Is email par AliGuard account pehle se hai. Login karein, ya password bhool gaye hon to "
                    f"{get_settings().base_url.rstrip('/')}/forgot-password se reset karein. "
                    "Agar ye aap nahi the to ignore karein.")
    return {"message": SIGNUP_MSG}


@router.post("/verify-email", dependencies=[Depends(require_csrf)])
def verify_email(body: TokenBody, request: Request, db: DbSession = Depends(get_db), r=Depends(get_redis)):
    _limit(r, f"rl:verify:ip:{client_ip(request)}", 20, 600)
    user = service.consume_email_token(db, body.token, "verify")
    if user is None:
        raise HTTPException(400, "Link ghalat ya expire ho chuka hai")
    user.is_verified = True
    service.audit(db, "email_verified", user.id, client_ip(request))
    db.commit()
    return {"message": "Email verify ho gayi. Ab login karein."}


@router.post("/resend-verification", status_code=202, dependencies=[Depends(require_csrf)])
def resend_verification(body: EmailBody, request: Request, bg: BackgroundTasks, r=Depends(get_redis)):
    s = get_settings()
    email = service.normalize_email(body.email)
    _limit(r, f"rl:resend:ip:{client_ip(request)}", s.forgot_limit, 3600)
    _limit(r, f"rl:resend:email:{sha256_hex(email)}", s.forgot_limit, 3600)
    bg.add_task(_send_verification, email)
    return {"message": SIGNUP_MSG}


# ---------- login / logout ----------
@router.post("/login", dependencies=[Depends(require_csrf)])
def login(body: LoginBody, request: Request, response: Response,
          db: DbSession = Depends(get_db), r=Depends(get_redis)):
    s = get_settings()
    ip = client_ip(request)
    email = service.normalize_email(body.email)
    _limit(r, f"rl:login:ip:{ip}", s.login_ip_limit, 600)
    _limit(r, f"rl:login:email:{sha256_hex(email)}", s.login_email_limit, 600)  # maujood na ho tab bhi
    out = service.attempt_login(db, email, body.password, ip, request.headers.get("user-agent"))
    if out.status == "fail":
        raise HTTPException(401, GENERIC_LOGIN_ERR)
    if out.status == "unverified":
        raise HTTPException(403, "Pehle apni email verify karein")
    # Session rotation: purani cookie wali session (agar thi) revoke, hamesha nayi id
    service.revoke_session_by_raw(db, request.cookies.get(SESSION_COOKIE))
    db.commit()
    if out.status == "mfa":
        set_session_cookie(response, out.session_token, s.mfa_pending_minutes)
        return {"status": "2fa_required"}
    set_session_cookie(response, out.session_token, s.session_absolute_minutes)
    return {"status": "ok"}


@router.post("/login/2fa", dependencies=[Depends(require_csrf)])
def login_2fa(body: MfaBody, request: Request, response: Response,
              db: DbSession = Depends(get_db), r=Depends(get_redis)):
    s = get_settings()
    ip = client_ip(request)
    _limit(r, f"rl:mfa:ip:{ip}", s.mfa_ip_limit, 600)
    pending = service.load_session(db, request.cookies.get(SESSION_COOKIE), stage="mfa_pending")
    if pending is None:
        clear_session_cookie(response)
        raise HTTPException(401, "Session khatam ho gayi, dobara login karein")
    user, sess = pending
    token = service.complete_mfa(db, user, sess, body.code, ip, request.headers.get("user-agent"))
    if token is None:
        raise HTTPException(401, "Code ghalat hai")
    set_session_cookie(response, token, s.session_absolute_minutes)
    return {"status": "ok"}


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(request: Request, response: Response, db: DbSession = Depends(get_db),
           auth=Depends(optional_user)):
    service.revoke_session_by_raw(db, request.cookies.get(SESSION_COOKIE))
    if auth:
        service.audit(db, "logout", auth[0].id, client_ip(request))
    db.commit()
    clear_session_cookie(response)
    return {"message": "Logout ho gaye"}


@router.post("/logout-all", dependencies=[Depends(require_csrf)])
def logout_all(request: Request, response: Response, db: DbSession = Depends(get_db),
               auth=Depends(current_user)):
    user, _ = auth
    service.revoke_all_sessions(db, user.id)
    service.audit(db, "logout_all", user.id, client_ip(request))
    db.commit()
    clear_session_cookie(response)
    return {"message": "Sab devices se logout ho gaye"}


# ---------- forgot / reset / change password ----------
@router.post("/forgot-password", status_code=202, dependencies=[Depends(require_csrf)])
def forgot_password(body: EmailBody, request: Request, bg: BackgroundTasks, r=Depends(get_redis)):
    s = get_settings()
    ip = client_ip(request)
    email = service.normalize_email(body.email)
    _limit(r, f"rl:forgot:ip:{ip}", s.forgot_limit, 3600)
    _limit(r, f"rl:forgot:email:{sha256_hex(email)}", s.forgot_limit, 3600)
    bg.add_task(_send_reset, email, ip)  # lookup/token background mein: response hamesha ek jaisa
    return {"message": FORGOT_MSG}


@router.post("/reset-password", dependencies=[Depends(require_csrf)])
def reset_password(body: ResetBody, request: Request, response: Response,
                   db: DbSession = Depends(get_db), r=Depends(get_redis)):
    ip = client_ip(request)
    _limit(r, f"rl:reset:ip:{ip}", 20, 600)
    # Policy pehle (token se independent), taake kamzor password par token zaya na ho
    _check_new_password(body.password, "")
    user = service.consume_email_token(db, body.token, "reset")
    if user is None:
        raise HTTPException(400, "Link ghalat ya expire ho chuka hai")
    service.set_password(db, user, body.password)
    user.is_verified = True  # email link khol kar ownership saabit hui
    service.revoke_all_sessions(db, user.id)
    service.audit(db, "password_reset", user.id, ip)
    db.commit()
    clear_session_cookie(response)
    return {"message": "Password badal gaya. Ab naye password se login karein."}


@router.post("/change-password", dependencies=[Depends(require_csrf)])
def change_password(body: ChangePasswordBody, request: Request, db: DbSession = Depends(get_db),
                    auth=Depends(current_user)):
    user, sess = auth
    ip = client_ip(request)
    if not verify_password(user.password_hash, body.current_password):
        service.audit(db, "password_change_failed", user.id, ip)
        db.commit()
        raise HTTPException(400, "Maujooda password ghalat hai")
    _check_new_password(body.new_password, user.email)
    service.set_password(db, user, body.new_password)
    service.revoke_all_sessions(db, user.id, except_id=sess.id)
    service.audit(db, "password_changed", user.id, ip)
    db.commit()
    return {"message": "Password badal gaya. Baqi devices logout ho gaye."}


# ---------- 2FA ----------
@router.post("/2fa/setup", dependencies=[Depends(require_csrf)])
def totp_setup(db: DbSession = Depends(get_db), auth=Depends(current_user)):
    user, _ = auth
    if user.totp_enabled:
        raise HTTPException(409, "2FA pehle se on hai")
    secret, qr = service.begin_totp_setup(db, user)
    return {"secret": secret, "qr_data_uri": qr}


@router.post("/2fa/enable", dependencies=[Depends(require_csrf)])
def totp_enable(body: MfaBody, request: Request, db: DbSession = Depends(get_db),
                auth=Depends(current_user), r=Depends(get_redis)):
    user, _ = auth
    _limit(r, f"rl:mfa:user:{user.id}", 10, 600)
    codes = service.enable_totp(db, user, body.code, client_ip(request))
    if codes is None:
        raise HTTPException(400, "Code ghalat hai ya setup shuru nahi hua")
    return {"recovery_codes": codes}


@router.post("/2fa/disable", dependencies=[Depends(require_csrf)])
def totp_disable(body: DisableTotpBody, request: Request, db: DbSession = Depends(get_db),
                 auth=Depends(current_user), r=Depends(get_redis)):
    user, _ = auth
    _limit(r, f"rl:mfa:user:{user.id}", 10, 600)
    if not user.totp_enabled or not service.disable_totp(db, user, body.password, body.code, client_ip(request)):
        raise HTTPException(400, "Password ya code ghalat hai")
    return {"message": "2FA band kar di gayi"}
