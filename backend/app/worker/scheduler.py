"""Bounded worker scheduler. Run as a separate process: python -m backend.app.worker [--once]."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy import or_, select

from backend.app import redis_client as redis_module
from backend.app.billing.service import entitled_clause
from backend.app.config import get_settings
from backend.app.db import SessionLocal
from backend.app.maintenance import purge_expired
from backend.app.models import GmailAccount, Subscription, utcnow
from backend.app.worker import health
from backend.app.worker.scanner import scan_account

log = logging.getLogger("aliguard.worker.scheduler")


def run_once(*, force: bool = False, session_factory=SessionLocal, redis_conn=None) -> dict:
    """Run due accounts with bounded concurrency; `force=True` ignores next_run_at for operator use."""
    s = get_settings()
    now = utcnow()
    with session_factory() as db:
        conds = [GmailAccount.status == "active"]
        if not force:
            conds.append(or_(GmailAccount.next_run_at.is_(None), GmailAccount.next_run_at <= now))
        # Sirf un users ke inbox jin ka plan active hai (free ya paid-aur-adaa-shuda)
        ids = db.scalars(select(GmailAccount.id).join(Subscription, Subscription.user_id == GmailAccount.user_id)
                         .where(*conds, entitled_clause()).order_by(GmailAccount.created_at)
                         .limit(max(1, s.worker_concurrency * 20))).all()
    if not ids:
        return {"accounts_selected": 0, "results": []}

    def _run(account_id):
        with session_factory() as db:
            return scan_account(db, account_id, redis_conn=redis_conn, force=force)

    results = []
    with ThreadPoolExecutor(max_workers=max(1, s.worker_concurrency), thread_name_prefix="aliguard-scan") as pool:
        futures = {pool.submit(_run, account_id): account_id for account_id in ids}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                log.exception("Worker account fail hua account_id=%s", futures[future])
                results.append({"account_id": str(futures[future]), "status": "error", "error": type(exc).__name__})
    return {"accounts_selected": len(ids), "results": results}


def run_forever(stop: threading.Event | None = None) -> None:
    s = get_settings()
    stop = stop or threading.Event()
    telegram_thread = None
    if s.telegram_configured:
        try:
            from backend.app.alerts.link import poll_loop
            from backend.app.alerts.telegram import get_client
            from backend.app.redis_client import redis_client
            client = get_client()
            if client is not None:
                telegram_thread = threading.Thread(
                    target=poll_loop, args=(stop, SessionLocal, redis_client, client),
                    name="aliguard-telegram-poller", daemon=True,
                )
                telegram_thread.start()
        except Exception:
            log.exception("Telegram poller start nahi ho saka; email scanning phir bhi chalegi")
    log.info("AliGuard worker start; poll_seconds=%s concurrency=%s", s.worker_poll_seconds, s.worker_concurrency)
    last_maintenance = 0.0
    while not stop.is_set():
        started = time.monotonic()
        health.beat(redis_module.redis_client)  # cycle shuru: worker zinda hai
        if started - last_maintenance >= s.maintenance_interval_seconds:
            last_maintenance = started
            try:
                with SessionLocal() as db:
                    purge_expired(db, scan_days=s.scan_retention_days, audit_days=s.audit_retention_days)
            except Exception:
                log.exception("Retention purge fail hua; scanning phir bhi chalegi")
        try:
            summary = run_once()
            if summary["accounts_selected"]:
                statuses = {}
                for item in summary["results"]:
                    statuses[item.get("status", "unknown")] = statuses.get(item.get("status", "unknown"), 0) + 1
                log.info("Worker cycle complete: selected=%s statuses=%s", summary["accounts_selected"], statuses)
        except Exception:
            log.exception("Worker scheduler cycle fail hua")
        health.beat(redis_module.redis_client)  # cycle khatam
        elapsed = time.monotonic() - started
        stop.wait(max(1.0, s.worker_poll_seconds - elapsed))
