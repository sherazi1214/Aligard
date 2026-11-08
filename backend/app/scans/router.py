"""/api/scans/* : dashboard ka data. HAR query mein user_id filter; doosre user ka scan 404.
Sender/subject attacker-controlled hain: API JSON mein raw deti hai, UI sirf textContent se dikhati hai."""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from backend.app.billing.deps import require_gmail
from backend.app.db import get_db
from backend.app.models import Scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _like_escape(text: str) -> str:
    """User ka search text literal rahe: % aur _ wildcard na banen."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _summary(s: Scan) -> dict:
    return {
        "id": str(s.id),
        "account_id": str(s.gmail_account_id),
        "sender": s.sender,
        "subject": s.subject,
        "verdict": s.verdict,
        "score": s.score,
        "action_taken": s.action_taken,
        "created_at": s.created_at.isoformat(),
    }


def _detail(s: Scan) -> dict:
    d = _summary(s)
    d.update(
        reasons=s.reasons or [],
        layer_scores=s.layer_scores or {},
        urls=s.urls or [],  # sirf defanged
        model_version=s.model_version,
        postmortem=s.postmortem or None,
    )
    return d


@router.get("/stats")
def stats(auth=Depends(require_gmail), db: DbSession = Depends(get_db)):
    user, _ = auth
    rows = db.execute(
        select(Scan.verdict, func.count()).where(Scan.user_id == user.id).group_by(Scan.verdict)
    ).all()
    by_verdict = {verdict: count for verdict, count in rows}
    quarantined = db.scalar(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id, Scan.action_taken == "quarantined")
    ) or 0
    return {
        "scanned": sum(by_verdict.values()),
        "safe": by_verdict.get("SAFE", 0),
        "suspicious": by_verdict.get("SUSPICIOUS", 0),
        "phishing": by_verdict.get("PHISHING", 0),
        "quarantined": quarantined,
    }


@router.get("")
def list_scans(
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(20, ge=1, le=50),
    verdict: str | None = Query(None, pattern="^(SAFE|SUSPICIOUS|PHISHING)$"),
    q: str | None = Query(None, max_length=100),
    account_id: uuid.UUID | None = None,
    auth=Depends(require_gmail),
    db: DbSession = Depends(get_db),
):
    user, _ = auth
    conds = [Scan.user_id == user.id]
    if verdict:
        conds.append(Scan.verdict == verdict)
    if account_id:
        # account_id kisi aur user ka ho to user_id filter ki wajah se khali nateeja, leak nahi
        conds.append(Scan.gmail_account_id == account_id)
    term = (q or "").strip()
    if term:
        pattern = f"%{_like_escape(term)}%"
        conds.append(or_(Scan.sender.ilike(pattern, escape="\\"), Scan.subject.ilike(pattern, escape="\\")))
    total = db.scalar(select(func.count()).select_from(Scan).where(*conds)) or 0
    rows = db.scalars(
        select(Scan).where(*conds).order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset((page - 1) * page_size).limit(page_size)
    ).all()
    return {"items": [_summary(s) for s in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/{scan_id}")
def scan_detail(scan_id: uuid.UUID, auth=Depends(require_gmail), db: DbSession = Depends(get_db)):
    user, _ = auth
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if scan is None:
        raise HTTPException(404, "Scan nahi mila")
    return _detail(scan)
