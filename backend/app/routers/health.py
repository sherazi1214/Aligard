"""Health endpoints: server zinda hai? DB aur Redis theek hain?"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.app import db, redis_client
from backend.app.config import get_settings
from backend.app.worker import health as worker_health

router = APIRouter(tags=["health"])


@router.get("/health")
def liveness():
    """Sirf itna batata hai ke process chal raha hai (dependencies nahi dekhta)."""
    return {"status": "ok"}


@router.get("/health/ready")
def readiness():
    """DB + Redis dono check. Koi ek down ho to 503, taake hosting restart/alert kare."""
    checks = {"database": db.check_db(), "redis": redis_client.check_redis()}
    ok = all(checks.values())
    body = {"status": "ready" if ok else "degraded", "checks": checks}
    return JSONResponse(body, status_code=200 if ok else 503)


@router.get("/health/worker")
def worker_heartbeat():
    """Worker zinda hai? Uptime monitor yahan 503 par alert kare. Redis down ho to bhi 503 (status 'unknown')."""
    age = worker_health.age_seconds(redis_client.redis_client)
    max_age = get_settings().worker_heartbeat_max_age_seconds
    if age is None:
        return JSONResponse({"status": "unknown"}, status_code=503)
    ok = age <= max_age
    return JSONResponse({"status": "alive" if ok else "stale", "age_seconds": int(age)},
                        status_code=200 if ok else 503)
