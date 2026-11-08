"""Redis fixed-window rate limiter. Redis down ho to request allow (fail-open, log hota hai);
account lockout DB mein hai isliye brute force phir bhi rukta hai.

Circuit breaker: ek RedisError ke baad kuch seconds Redis ko try hi nahi karte, warna Redis blackhole hone par
har request socket timeout (2s) tak latak jati aur poori site slow ho jati."""
import logging
import time

import redis
from fastapi import Request

from backend.app.config import get_settings

log = logging.getLogger("aliguard.ratelimit")

BREAKER_SECONDS = 10.0
_down_until: dict[int, float] = {}  # id(redis client) -> monotonic time jab tak skip karna hai


def reset_breaker() -> None:
    _down_until.clear()


def allow(r: redis.Redis, key: str, limit: int, window_seconds: int) -> bool:
    if _down_until.get(id(r), 0.0) > time.monotonic():
        return True  # Redis abhi down hai; fail-open (cheez ghalat chalne se behtar hai ke site chalti rahe)
    try:
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds, nx=True)
        count = pipe.execute()[0]
        return int(count) <= limit
    except redis.RedisError:
        _down_until[id(r)] = time.monotonic() + BREAKER_SECONDS
        log.warning("Rate limiter: Redis available nahi, allow kiya (breaker %ss)", int(BREAKER_SECONDS))
        return True


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[-1].strip()[:45]  # sirf apne proxy ka lagaya hua aakhri hop
    return (request.client.host if request.client else "unknown")[:45]
