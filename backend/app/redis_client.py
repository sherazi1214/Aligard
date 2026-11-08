"""Redis connection (queue aur rate-limit ke liye, Phase 2/3 mein use hoga)."""
import logging

import redis

from backend.app.config import get_settings

log = logging.getLogger("aliguard.redis")

# Timeout lazmi: warna Redis down ho to request hamesha latak jayegi
redis_client = redis.Redis.from_url(
    get_settings().redis_url, socket_connect_timeout=2, socket_timeout=2
)


def check_redis() -> bool:
    try:
        return bool(redis_client.ping())
    except Exception:
        log.exception("Redis check fail")
        return False
