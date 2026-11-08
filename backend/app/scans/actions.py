"""Restore and feedback endpoints for the signed-in user's own scans."""
import re
import uuid
from email.utils import parseaddr

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app.auth.deps import require_csrf
from backend.app.billing.deps import require_gmail
from backend.app.db import get_db
from backend.app.gmail import api as gmail_api
from backend.app.gmail import google
from backend.app.gmail.tokens import NeedsReauth, access_token_for, mark_needs_reauth, refresh_access
from backend.app.models import Feedback, GmailAccount, Scan, utcnow

router = APIRouter(prefix="/api/scans", tags=["scan-actions"])


class FeedbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = "not_phishing"


@router.post("/{scan_id}/restore", dependencies=[Depends(require_csrf)])
def restore_scan(scan_id: uuid.UUID, request: Request, auth=Depends(require_gmail), db: DbSession = Depends(get_db)):
    user, _ = auth
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if scan is None:
        raise HTTPException(404, "Scan nahi mila")
    if scan.action_taken == "restored":
        return {"status": "restored", "scan_id": str(scan.id)}
    if scan.action_taken != "quarantined":
        raise HTTPException(409, "Sirf quarantine ki hui email restore ho sakti hai")
    account = db.scalar(select(GmailAccount).where(
        GmailAccount.id == scan.gmail_account_id, GmailAccount.user_id == user.id,
        GmailAccount.status != "disconnected",
    ))
    if account is None:
        raise HTTPException(409, "Gmail account disconnected hai")
    try:
        token = access_token_for(db, account)
        client = gmail_api.GmailClient(token)
        try:
            client.restore(scan.gmail_message_id)
        except gmail_api.GmailAuthError:
            token = refresh_access(db, account, refresher=google.refresh_access_token)
            gmail_api.GmailClient(token).restore(scan.gmail_message_id)
    except NeedsReauth as exc:
        mark_needs_reauth(db, account.id, exc.code)
        raise HTTPException(409, "Gmail dobara connect karein") from exc
    except gmail_api.GmailAuthError as exc:
        mark_needs_reauth(db, account.id, "gmail_unauthorized")
        raise HTTPException(409, "Gmail dobara connect karein") from exc
    except gmail_api.GmailNotFound as exc:
        raise HTTPException(404, "Gmail mein email nahi mili; shayad delete ho chuki hai") from exc
    except gmail_api.GmailError as exc:
        raise HTTPException(502, "Gmail restore nakam hua; baad mein dobara try karein") from exc
    scan.action_taken = "restored"
    scan.planned_action = "none"
    db.commit()
    return {"status": "restored", "scan_id": str(scan.id)}


@router.post("/{scan_id}/feedback", dependencies=[Depends(require_csrf)])
def submit_feedback(
    scan_id: uuid.UUID, body: FeedbackBody, auth=Depends(require_gmail), db: DbSession = Depends(get_db)
):
    user, _ = auth
    if body.kind != "not_phishing":
        raise HTTPException(422, "Feedback kind supported nahi")
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if scan is None:
        raise HTTPException(404, "Scan nahi mila")
    sender = scan.sender or ""
    _, address = parseaddr(sender)
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    domain = re.sub(r"[^a-z0-9.-]", "", domain)[:254]
    db.add(Feedback(user_id=user.id, scan_id=scan.id, kind="not_phishing", verdict=scan.verdict,
                    score=scan.score, model_version=scan.model_version, sender_domain=domain, created_at=utcnow()))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Is scan ke liye feedback pehle submit ho chuka hai") from None
    return {"status": "recorded", "scan_id": str(scan.id)}
