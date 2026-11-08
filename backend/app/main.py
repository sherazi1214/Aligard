"""AliGuard backend - FastAPI entry point."""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.auth import deps as auth_deps
from backend.app.auth.router import router as auth_router
from backend.app.billing.router import router as billing_router
from backend.app.check.router import router as check_router
from backend.app.config import get_settings
from backend.app.db import engine
from backend.app.gmail.router import router as gmail_router
from backend.app.logging_config import configure_logging
from backend.app.observability import init_sentry
from backend.app.ratelimit import allow, client_ip
from backend.app.routers import health, pages
from backend.app.routers.pages import WEB_DIR
from backend.app.scans.actions import router as scan_actions_router
from backend.app.scans.router import router as scans_router
from backend.app.usersettings.router import router as settings_router

settings = get_settings()
configure_logging(settings.log_level, settings.effective_log_format)
init_sentry(settings, "web")
log = logging.getLogger("aliguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("AliGuard start (env=%s)", settings.app_env)
    yield
    engine.dispose()  # shutdown pe DB connections saaf
    log.info("AliGuard band")


app = FastAPI(
    title="AliGuard",
    version="0.4.0",
    lifespan=lifespan,
    # Production mein API docs band, attacker ko map na mile
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

# CORS: sirf apni frontend origins, "*" kabhi nahi (cookies login ke liye aage lazmi)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


# Strict CSP: sirf apni files, koi inline script/style nahi. data: sirf images (2FA QR) ke liye.
_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
_DOCS_PATHS = ("/docs", "/openapi.json")


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Default 422 user ka bheja hua input (password!) wapas echo karta hai; hum sirf field aur msg dete hain
    errors = [{"field": ".".join(str(p) for p in e["loc"][1:]), "msg": e["msg"]} for e in exc.errors()]
    return JSONResponse({"detail": "Input ghalat hai", "errors": errors}, status_code=422)


_UNLIMITED_PREFIXES = ("/health", "/static")  # monitoring aur static files global limit se bahar


@app.middleware("http")
async def access_log(request: Request, call_next):
    """Masked access log: sirf method/path/status/waqt. Query string kabhi nahi (verify/reset tokens hote hain)."""
    started = time.monotonic()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        path = request.url.path
        if not path.startswith(_UNLIMITED_PREFIXES):
            log.info("request", extra={
                "method": request.method, "path": path, "status": status,
                "ms": int((time.monotonic() - started) * 1000),
            })


@app.middleware("http")
async def global_rate_limit(request: Request, call_next):
    """Har page/API par per-IP backstop. Redis down ho to fail-open (breaker ratelimit.allow mein)."""
    limit = get_settings().global_rate_limit_per_minute  # har request par padho (config reload/tests)
    if limit > 0 and not request.url.path.startswith(_UNLIMITED_PREFIXES):
        r = app.dependency_overrides.get(auth_deps.get_redis, auth_deps.get_redis)()
        if not await run_in_threadpool(allow, r, f"rl:global:{client_ip(request)}", limit, 60):
            return JSONResponse({"detail": "Bohat zyada requests. Thori der baad try karein"},
                                status_code=429, headers={"Retry-After": "60"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path not in _DOCS_PATHS:  # dev mein Swagger UI ko CDN scripts chahiye
        response.headers["Content-Security-Policy"] = _CSP
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
app.include_router(health.router)
app.include_router(auth_router)
app.include_router(billing_router)
app.include_router(gmail_router)
app.include_router(scans_router)
app.include_router(scan_actions_router)
app.include_router(settings_router)
app.include_router(check_router)
app.include_router(pages.router)
