"""Optional Sentry. SENTRY_DSN khali ho to kuch nahi hota. Request body/cookies/headers/locals kabhi nahi jate."""
from __future__ import annotations

import logging

from backend.app.config import Settings
from backend.app.logging_config import mask

log = logging.getLogger("aliguard.observability")
_enabled = False


def scrub_event(event: dict, hint: dict | None = None) -> dict | None:
    request = event.get("request")
    if isinstance(request, dict):
        # Sirf method aur path rakhte hain: query string mein tokens hote hain, body/cookies mein user data
        event["request"] = {"method": request.get("method"), "url": str(request.get("url", "")).split("?")[0]}
    event.pop("user", None)
    if isinstance(event.get("message"), str):
        event["message"] = mask(event["message"])
    for exc in (event.get("exception") or {}).get("values", []) or []:
        if isinstance(exc.get("value"), str):
            exc["value"] = mask(exc["value"])
        for frame in (exc.get("stacktrace") or {}).get("frames", []) or []:
            frame.pop("vars", None)
    return event


def init_sentry(settings: Settings, component: str) -> bool:
    global _enabled
    if not settings.sentry_dsn:
        return False
    try:
        import sentry_sdk

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.app_env,
            send_default_pii=False,
            include_local_variables=False,
            max_request_body_size="never",
            traces_sample_rate=0.0,
            before_send=scrub_event,
            server_name="",
        )
        sentry_sdk.set_tag("component", component)
        _enabled = True
        log.info("Sentry enabled (component=%s)", component)
    except Exception:  # monitoring ki kharabi app ko na roke
        log.exception("Sentry init fail hua; app Sentry ke baghair chalegi")
        _enabled = False
    return _enabled


def capture_message(message: str) -> None:
    if not _enabled:
        return
    try:
        import sentry_sdk

        sentry_sdk.capture_message(mask(message), level="error")
    except Exception:
        log.debug("Sentry capture fail")
