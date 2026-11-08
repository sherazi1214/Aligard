"""Data retention: Privacy Policy mein jo muddat likhi hai, wahi yahan enforce hoti hai (worker se chalta hai)."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session as DbSession

from backend.app.models import AuditLog, EmailToken, Feedback, Scan, Session, utcnow

log = logging.getLogger("aliguard.maintenance")


def purge_expired(db: DbSession, *, scan_days: int, audit_days: int) -> dict:
    now = utcnow()
    counts = {}
    if scan_days > 0:
        cutoff = now - timedelta(days=scan_days)
        old_ids = db.scalars(Scan.__table__.select().with_only_columns(Scan.id).where(Scan.created_at < cutoff)).all()
        if old_ids:
            # Explicit child delete: SQLite par FK cascade band ho sakti hai
            db.execute(delete(Feedback).where(Feedback.scan_id.in_(old_ids)))
        counts["scans"] = db.execute(delete(Scan).where(Scan.created_at < cutoff)).rowcount
    counts["email_tokens"] = db.execute(
        delete(EmailToken).where(EmailToken.expires_at < now - timedelta(days=7))
    ).rowcount
    counts["sessions"] = db.execute(
        delete(Session).where(Session.expires_at < now - timedelta(days=30))
    ).rowcount
    counts["sessions_revoked"] = db.execute(
        delete(Session).where(Session.revoked_at.is_not(None), Session.revoked_at < now - timedelta(days=30))
    ).rowcount
    if audit_days > 0:
        counts["audit_log"] = db.execute(
            delete(AuditLog).where(AuditLog.created_at < now - timedelta(days=audit_days))
        ).rowcount
    db.commit()
    log.info("Retention purge: %s", counts)
    return counts
