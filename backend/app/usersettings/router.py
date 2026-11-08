"""User-owned alert preferences, whitelist, Telegram linking and account data deletion."""
import logging
import re
import uuid
from email.utils import parseaddr

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app.alerts.link import create_link_code, link_url
from backend.app.auth.deps import clear_session_cookie, current_user, get_redis, require_csrf
from backend.app.billing import service as billing_service
from backend.app.billing.deps import require_plan
from backend.app.config import get_settings
from backend.app.db import get_db
from backend.app.gmail import google
from backend.app.models import (
    AlertSettings,
    AuditLog,
    EmailToken,
    Feedback,
    GmailAccount,
    RecoveryCode,
    Scan,
    Session,
    Subscription,
    Whitelist,
)
from backend.app.prefs import MIN_PHISHING, MIN_SUSPICIOUS, get_or_create_settings
from backend.app.security import decrypt_secret

log = logging.getLogger("aliguard.settings")
router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alerts_enabled: bool | None = None
    email_alerts: bool | None = None
    telegram_alerts: bool | None = None
    suspicious_threshold: int | None = Field(None, ge=0, le=100)
    phishing_threshold: int | None = Field(None, ge=1, le=100)

    @model_validator(mode="after")
    def validate_thresholds(self):
        if self.suspicious_threshold is not None and self.suspicious_threshold < MIN_SUSPICIOUS:
            raise ValueError(f"Suspicious threshold kam az kam {MIN_SUSPICIOUS} hona chahiye")
        if self.phishing_threshold is not None and self.phishing_threshold < MIN_PHISHING:
            raise ValueError(f"Phishing threshold kam az kam {MIN_PHISHING} hona chahiye")
        if (self.suspicious_threshold is not None and self.phishing_threshold is not None
                and self.phishing_threshold <= self.suspicious_threshold):
            raise ValueError("Phishing threshold, suspicious threshold se bara hona chahiye")
        return self


class WhitelistCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    value: str = Field(min_length=3, max_length=254)


def _settings_payload(db, user_id):
    row = get_or_create_settings(db, user_id)
    entries = db.scalars(select(Whitelist).where(Whitelist.user_id == user_id).order_by(Whitelist.created_at)).all()
    s = get_settings()
    return {
        "alerts_enabled": row.alerts_enabled, "email_alerts": row.email_alerts,
        "telegram_alerts": row.telegram_alerts, "telegram_linked": bool(row.telegram_chat_id),
        "telegram_configured": s.telegram_configured,
        "suspicious_threshold": row.suspicious_threshold, "phishing_threshold": row.phishing_threshold,
        "minimum_suspicious_threshold": MIN_SUSPICIOUS, "minimum_phishing_threshold": MIN_PHISHING,
        "whitelist": [
            {"id": str(x.id), "kind": x.kind, "value": x.value, "created_at": x.created_at.isoformat()}
            for x in entries
        ],
    }


@router.get("")
def get_settings_api(auth=Depends(require_plan), db: DbSession = Depends(get_db)):
    user, _ = auth
    return _settings_payload(db, user.id)


@router.patch("", dependencies=[Depends(require_csrf)])
def update_settings(body: SettingsUpdate, auth=Depends(require_plan), db: DbSession = Depends(get_db)):
    user, _ = auth
    plan = billing_service.plan_for_user(db, user.id)
    if body.telegram_alerts is True and not (plan and plan.telegram):
        raise HTTPException(402, "telegram_requires_paid_plan")
    row = get_or_create_settings(db, user.id)
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    new_suspicious = values.get("suspicious_threshold", row.suspicious_threshold)
    new_phishing = values.get("phishing_threshold", row.phishing_threshold)
    if new_phishing <= new_suspicious:
        raise HTTPException(422, "Phishing threshold, suspicious threshold se bara hona chahiye")
    if values.get("telegram_alerts") is True and not row.telegram_chat_id:
        raise HTTPException(409, "Pehle Telegram ko link karein")
    for key, value in values.items():
        setattr(row, key, value)
    db.commit()
    return _settings_payload(db, user.id)


@router.post("/whitelist", dependencies=[Depends(require_csrf)])
def add_whitelist(body: WhitelistCreate, auth=Depends(require_plan), db: DbSession = Depends(get_db)):
    user, _ = auth
    kind = body.kind.strip().lower()
    value = body.value.strip().lower()
    if kind == "sender":
        _, address = parseaddr(value)
        if not address or address != value or "@" not in address or len(address) > 254:
            raise HTTPException(422, "Valid sender email address dein")
        value = address
    elif kind == "domain":
        value = value.removeprefix("@")
        domain_pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
        if value.startswith(".") or value.endswith(".") or not re.fullmatch(domain_pattern, value):
            raise HTTPException(422, "Valid domain dein, misal: example.com")
    else:
        raise HTTPException(422, "Kind sender ya domain hona chahiye")
    row = Whitelist(user_id=user.id, kind=kind, value=value)
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Ye entry pehle se whitelist mein hai") from exc
    db.refresh(row)
    return {"id": str(row.id), "kind": row.kind, "value": row.value}


@router.delete("/whitelist/{entry_id}", dependencies=[Depends(require_csrf)])
def remove_whitelist(entry_id: uuid.UUID, auth=Depends(require_plan), db: DbSession = Depends(get_db)):
    user, _ = auth
    row = db.scalar(select(Whitelist).where(Whitelist.id == entry_id, Whitelist.user_id == user.id))
    if row is None:
        raise HTTPException(404, "Whitelist entry nahi mili")
    db.delete(row)
    db.commit()
    return {"status": "deleted"}


@router.post("/telegram/link", dependencies=[Depends(require_csrf)])
def telegram_link(auth=Depends(require_plan), r=Depends(get_redis), db: DbSession = Depends(get_db)):
    user, _ = auth
    plan = billing_service.plan_for_user(db, user.id)
    if not (plan and plan.telegram):
        raise HTTPException(402, "telegram_requires_paid_plan")
    s = get_settings()
    if not s.telegram_configured:
        raise HTTPException(503, "Telegram bot abhi configure nahi hai")
    try:
        code = create_link_code(r, user.id)
    except Exception as exc:
        raise HTTPException(503, "Telegram link abhi nahi ban sakta; baad mein try karein") from exc
    return {"url": link_url(code), "expires_in_seconds": s.telegram_link_ttl_seconds}


@router.delete("/telegram/link", dependencies=[Depends(require_csrf)])
def telegram_unlink(auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, _ = auth
    row = get_or_create_settings(db, user.id)
    row.telegram_chat_id = None
    row.telegram_alerts = False
    db.commit()
    return {"status": "unlinked"}


@router.delete("/data", dependencies=[Depends(require_csrf)])
def delete_my_data(request: Request, response: Response, confirm: str, auth=Depends(current_user),
                   db: DbSession = Depends(get_db), r=Depends(get_redis)):
    """Irreversible deletion; caller must send ?confirm=DELETE_MY_DATA and valid CSRF/session."""
    user, _session = auth
    if confirm != "DELETE_MY_DATA":
        raise HTTPException(400, "Deletion confirm missing hai")
    # Best-effort Google revocation; local credentials are deleted regardless of provider availability.
    accounts = db.scalars(select(GmailAccount).where(GmailAccount.user_id == user.id)).all()
    for acc in accounts:
        token = decrypt_secret(acc.refresh_token_encrypted) if acc.refresh_token_encrypted else None
        token = token or (decrypt_secret(acc.access_token_encrypted) if acc.access_token_encrypted else None)
        if token:
            try:
                google.revoke(token)
            except Exception as exc:
                log.warning("Google token revoke nakam hua during deletion: %s", type(exc).__name__)
    # Explicit child deletes also work on SQLite setups where FK cascades were not enabled.
    db.execute(delete(Feedback).where(Feedback.user_id == user.id))
    db.execute(delete(Scan).where(Scan.user_id == user.id))
    db.execute(delete(GmailAccount).where(GmailAccount.user_id == user.id))
    db.execute(delete(Whitelist).where(Whitelist.user_id == user.id))
    db.execute(delete(AlertSettings).where(AlertSettings.user_id == user.id))
    db.execute(delete(EmailToken).where(EmailToken.user_id == user.id))
    db.execute(delete(Session).where(Session.user_id == user.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    db.execute(delete(Subscription).where(Subscription.user_id == user.id))
    db.execute(delete(AuditLog).where(AuditLog.user_id == user.id))
    db.delete(user)
    db.commit()
    # Best-effort cleanup of user-keyed transient data. Never log values or token-bearing keys.
    try:
        for suffix in (f"rl:gmail:connect:{user.id}", f"rl:check:user:{user.id}",
                       f"alert:rate:{user.id}", f"alert:throttle:{user.id}"):
            r.delete(suffix)
        # Pending Telegram link codes contain only user IDs; remove matching codes before leaving Redis.
        for key in r.scan_iter(match="tg:link:*"):
            value = r.get(key)
            if value is not None and (value.decode() if isinstance(value, bytes) else str(value)) == str(user.id):
                r.delete(key)
    except Exception as exc:
        # Database deletion is already complete; Redis cleanup failure must not restore local data.
        log.warning("Redis cleanup nakam hua after account deletion: %s", type(exc).__name__)
    clear_session_cookie(response)
    response.delete_cookie("aliguard_csrf", path="/")
    return {"status": "deleted", "message": "Aap ka AliGuard account aur local data delete kar diya gaya."}
