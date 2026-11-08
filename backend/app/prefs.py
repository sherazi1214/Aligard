"""User ki alert settings. Row na ho to defaults maane jate hain (worker row nahi banata)."""
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app.models import AlertSettings, Whitelist
from engine.config import EngineConfig

# Engine ke apne thresholds kam az kam hain: user sirf upar kar sakta hai (kam alerts), neeche nahi
MIN_SUSPICIOUS = EngineConfig().suspicious_threshold
MIN_PHISHING = EngineConfig().phishing_threshold


@dataclass(frozen=True)
class Prefs:
    alerts_enabled: bool = True
    email_alerts: bool = True
    telegram_alerts: bool = False
    telegram_chat_id: str | None = None
    suspicious_threshold: int = MIN_SUSPICIOUS
    phishing_threshold: int = MIN_PHISHING


def load_prefs(db: DbSession, user_id: uuid.UUID) -> Prefs:
    row = db.scalar(
        select(AlertSettings).where(AlertSettings.user_id == user_id).execution_options(populate_existing=True)
    )
    if row is None:
        return Prefs()
    return Prefs(
        alerts_enabled=row.alerts_enabled, email_alerts=row.email_alerts, telegram_alerts=row.telegram_alerts,
        telegram_chat_id=row.telegram_chat_id, suspicious_threshold=row.suspicious_threshold,
        phishing_threshold=row.phishing_threshold,
    )


def get_or_create_settings(db: DbSession, user_id: uuid.UUID) -> AlertSettings:
    row = db.get(AlertSettings, user_id)
    if row is not None:
        return row
    row = AlertSettings(user_id=user_id)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # do requests ek sath: doosri ne bana di
        row = db.get(AlertSettings, user_id)
        if row is None:
            raise
    return row


def load_whitelist(db: DbSession, user_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = db.execute(select(Whitelist.kind, Whitelist.value).where(Whitelist.user_id == user_id)).all()
    return [(kind, value) for kind, value in rows]
