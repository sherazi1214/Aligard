"""Daily call budget for paid third-party APIs (OpenAI, VirusTotal): global + per-user, Redis counters.

Ye DOLLAR cap nahi, CALL-COUNT cap hai (cost = calls x provider price; apna provider-side spend limit bhi lagayein).
Redis down ho to paid call FAIL-CLOSED (bina counter ke paisa kharch nahi karte); engine degraded verdict deta hai."""
from __future__ import annotations

import contextlib
import contextvars
import logging
import math
from datetime import UTC, datetime

import redis

from backend.app import observability
from engine.reputation import ProviderError

log = logging.getLogger("aliguard.budget")
_current_user: contextvars.ContextVar[str | None] = contextvars.ContextVar("budget_user", default=None)


@contextlib.contextmanager
def budget_user(user_id):
    """Is block mein hone wale paid calls is user ke quota mein ginay jayenge."""
    token = _current_user.set(str(user_id) if user_id is not None else None)
    try:
        yield
    finally:
        _current_user.reset(token)


class BudgetGuard:
    def __init__(self, r: redis.Redis, service: str, daily_limit: int, user_daily_limit: int,
                 alarm_fraction: float = 0.8) -> None:
        self.r, self.service = r, service
        self.daily_limit, self.user_daily_limit, self.alarm_fraction = daily_limit, user_daily_limit, alarm_fraction

    def consume(self) -> None:
        """Ek paid call se pehle chalao. Hadd paar ho to ProviderError (engine us layer ko skip karta hai)."""
        day = datetime.now(UTC).strftime("%Y%m%d")
        user = _current_user.get()
        try:
            if user is not None and self.user_daily_limit > 0:
                ukey = f"budget:{self.service}:{day}:user:{user}"
                used = self._incr(ukey)
                if used > self.user_daily_limit:
                    raise ProviderError(f"{self.service}: per-user daily limit")
            used_total = self._incr(f"budget:{self.service}:{day}:global")
            if used_total > self.daily_limit:
                self._alarm(day, "100", used_total)
                raise ProviderError(f"{self.service}: global daily limit")
            if used_total >= math.ceil(self.daily_limit * self.alarm_fraction):
                self._alarm(day, str(int(self.alarm_fraction * 100)), used_total)
        except redis.RedisError as exc:
            raise ProviderError(f"{self.service}: budget store unavailable") from exc

    def _incr(self, key: str) -> int:
        pipe = self.r.pipeline()
        pipe.incr(key)
        pipe.expire(key, 172800, nx=True)
        return int(pipe.execute()[0])

    def _alarm(self, day: str, level: str, used: int) -> None:
        try:
            first = self.r.set(f"budget:alarm:{self.service}:{day}:{level}", "1", nx=True, ex=172800)
        except redis.RedisError:
            return
        if first:
            msg = f"BUDGET_ALARM service={self.service} level={level}% used={used}/{self.daily_limit}"
            log.error(msg)
            observability.capture_message(msg)


class BudgetedLLM:
    """OpenAIProvider ko budget guard ke andar lapetta hai (LLMProvider protocol)."""

    def __init__(self, inner, guard: BudgetGuard) -> None:
        self._inner, self._guard = inner, guard

    def classify(self, subject, sender_domain, body, urls):
        self._guard.consume()
        return self._inner.classify(subject, sender_domain, body, urls)
