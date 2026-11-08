"""Gating dependencies. Server-side enforce: UI chhupana kaafi nahi.
402 plan_required -> plan nahi chuna/payment nahi hui. 428 gmail_required -> koi active Gmail connected nahi."""
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from backend.app.auth.deps import current_user
from backend.app.billing import service
from backend.app.billing.plans import Plan
from backend.app.db import get_db


def require_plan(auth=Depends(current_user), db: DbSession = Depends(get_db)):
    user, sess = auth
    if service.plan_for_user(db, user.id) is None:
        raise HTTPException(402, "plan_required")
    return user, sess


def require_gmail(auth=Depends(require_plan), db: DbSession = Depends(get_db)):
    user, sess = auth
    if not service.has_active_gmail(db, user.id):
        raise HTTPException(428, "gmail_required")
    return user, sess


def plan_of(db: DbSession, user) -> Plan:
    plan = service.plan_for_user(db, user.id)
    if plan is None:
        raise HTTPException(402, "plan_required")
    return plan
