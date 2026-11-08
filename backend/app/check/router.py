"""POST /api/check : manual Link/Message check. Login + CSRF lazmi, per-user rate limit, body size limit.
Result store NAHI hota (privacy: user ka pasted text DB mein nahi jata)."""
import logging
from email.utils import parseaddr

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session as DbSession

from backend.app.auth.deps import get_redis, require_csrf
from backend.app.billing import service as billing_service
from backend.app.billing.deps import require_gmail
from backend.app.budget import budget_user
from backend.app.check.schemas import CheckBody
from backend.app.config import get_settings
from backend.app.db import get_db
from backend.app.engine_factory import analyze
from backend.app.ratelimit import allow
from engine import EmailInput

log = logging.getLogger("aliguard.check")
router = APIRouter(prefix="/api/check", tags=["check"])

TOO_MANY = "Bohat zyada checks. Thori der baad dobara try karein"


async def _read_body(request: Request, limit: int) -> bytes:
    """Body ko stream karte hue hadd lagao: bara body memory mein poora nahi aata."""
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise HTTPException(400, "Request ghalat hai")
        if int(declared) > limit:
            raise HTTPException(413, "Request bohat bari hai")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, "Request bohat bari hai")
        chunks.append(chunk)
    return b"".join(chunks)


def _build_email(body: CheckBody) -> EmailInput:
    if body.kind == "link":
        url = body.url if "://" in body.url else f"http://{body.url}"
        return EmailInput(text_body=url)
    name, addr = parseaddr(body.sender)
    return EmailInput(
        subject=body.subject, sender_name=name, sender_email=addr.lower(), text_body=body.text,
    )


def _public_result(result) -> dict:
    d = result.to_dict()
    d.pop("urls", None)  # sirf defanged URLs bahar jate hain
    return d


@router.post("", dependencies=[Depends(require_csrf)])
async def check(request: Request, auth=Depends(require_gmail), r=Depends(get_redis),
                db: DbSession = Depends(get_db)):
    user, _ = auth
    s = get_settings()
    plan = await run_in_threadpool(billing_service.plan_for_user, db, user.id)
    limit = min(s.check_user_limit, plan.check_limit) if plan else 0  # plan ki hadd (env sirf upar ka ceiling)
    if not await run_in_threadpool(allow, r, f"rl:check:user:{user.id}", limit, 600):
        raise HTTPException(429, TOO_MANY)
    raw = await _read_body(request, s.check_max_body_bytes)
    try:
        body = CheckBody.model_validate_json(raw)
    except ValidationError as exc:
        # Input wapas echo nahi karte, sirf field aur msg (main.py ke 422 handler jaisa)
        errors = [{"field": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": "Input ghalat hai", "errors": errors}, status_code=422)
    def _run():
        with budget_user(user.id):  # paid API calls is user ke daily quota mein ginti hain
            return analyze(_build_email(body))

    result = await run_in_threadpool(_run)
    return _public_result(result)
