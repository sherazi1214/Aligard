"""Worker heartbeat: scheduler har cycle Redis mein waqt likhta hai; /health/worker usay check karta hai."""
from __future__ import annotations

import logging
import time

log = logging.getLogger("aliguard.worker.health")
HEARTBEAT_KEY = "worker:heartbeat"


def beat(r) -> None:
    """Heartbeat likho. Kabhi exception nahi uchalta (worker is wajah se na ruke)."""
    try:
        r.set(HEARTBEAT_KEY, str(int(time.time())), ex=3600)
    except Exception as exc:
        log.warning("Heartbeat likhna fail hua: %s", type(exc).__name__)


def age_seconds(r) -> float | None:
    """Heartbeat kitna purana hai; None = nahi mila ya Redis available nahi."""
    try:
        raw = r.get(HEARTBEAT_KEY)
        if raw is None:
            return None
        return max(0.0, time.time() - int(raw))
    except Exception:
        return None
