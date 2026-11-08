"""Alerts bhejna: email + Telegram. Usool:
- AT-MOST-ONCE: bhejne se PEHLE atomic claim (pending -> sending). Worker beech mein mar jaye to alert dobara nahi
  jata (kho sakta hai, double nahi). Jab ye pata ho ke KOI channel nahi pohncha to claim wapas 'pending' hota hai
  (max attempts tak), taake sirf wahi dobara try ho jo asal mein gaya hi nahi.
- Throttle (per user, ghante mein N) + dedupe (wahi sender+subject), Redis se. Redis down ho to fail-open (log),
  duplicate phir bhi DB claim se rukte hain.
- Telegram 403/400 (bot block) par Telegram link khud hat jata hai; email chalti rehti hai."""
import hashlib
import logging
import uuid

import redis
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from backend.app import mailer
from backend.app.alerts import format as fmt
from backend.app.alerts.telegram import BLOCKED, OK, TelegramClient
from backend.app.config import get_settings
from backend.app.models import AlertSettings, Scan, User
from backend.app.prefs import Prefs, load_prefs
from backend.app.ratelimit import allow

log = logging.getLogger("aliguard.alerts")


class AlertService:
    def __init__(self, redis_client, telegram: TelegramClient | None = None, send_mail=None):
        self.r = redis_client
        self.telegram = telegram
        self._send_mail = send_mail or mailer.send_email_checked

    # ------------------------------------------------------------ helpers
    def _once(self, key: str, ttl: int) -> bool:
        """True agar ye key pehli bar set hui (SET NX). Redis down ho to True (fail-open)."""
        try:
            return bool(self.r.set(key, "1", nx=True, ex=ttl))
        except redis.RedisError:
            log.warning("Alerts: Redis available nahi, dedupe/throttle skip")
            return True

    @staticmethod
    def _dashboard_url() -> str:
        return f"{get_settings().base_url.rstrip('/')}/dashboard"

    def _send(self, db: DbSession, user: User, prefs: Prefs, title: str, body: str) -> tuple[int, int]:
        """(retriable koshishein, kamyab). Telegram 'blocked' permanent hai: gina nahi jata, link hata diya jata hai."""
        attempted = ok = 0
        if prefs.email_alerts:
            attempted += 1
            try:
                if self._send_mail(user.email, title, body):
                    ok += 1
            except Exception:  # noqa: BLE001 - alert ka masla scanning ko nahi rokna chahiye
                log.exception("Email alert crash")
        if prefs.telegram_alerts and prefs.telegram_chat_id and self.telegram is not None:
            result = self.telegram.send_message(prefs.telegram_chat_id, f"{title}\n\n{body}")
            if result == OK:
                attempted += 1
                ok += 1
            elif result == BLOCKED:
                self._unlink_telegram(db, user.id)
            else:
                attempted += 1
        return attempted, ok

    @staticmethod
    def _unlink_telegram(db: DbSession, user_id: uuid.UUID) -> None:
        db.execute(
            update(AlertSettings).where(AlertSettings.user_id == user_id)
            .values(telegram_alerts=False, telegram_chat_id=None)
        )
        db.commit()
        log.warning("Telegram chat ne bot block/delete kiya: link hata diya gaya")

    @staticmethod
    def _set_state(db: DbSession, scan_id: uuid.UUID, state: str, attempts: int | None = None) -> None:
        values: dict = {"alert_state": state}
        if attempts is not None:
            values["alert_attempts"] = attempts
        db.execute(update(Scan).where(Scan.id == scan_id).values(**values))
        db.commit()

    # ------------------------------------------------------------ scan alert
    def dispatch_scan(self, db: DbSession, scan_id: uuid.UUID) -> str:
        """Ek scan ka alert. Return: sent | skipped | retry | failed | not_pending | missing."""
        s = get_settings()
        claim = db.execute(
            update(Scan).where(Scan.id == scan_id, Scan.alert_state == "pending").values(alert_state="sending")
        )
        db.commit()
        if claim.rowcount != 1:
            return "not_pending"  # kisi aur ne le liya, ya alert ki zaroorat hi nahi
        scan = db.scalar(select(Scan).where(Scan.id == scan_id).execution_options(populate_existing=True))
        user = db.get(User, scan.user_id) if scan is not None else None
        if scan is None or user is None:
            return "missing"
        prefs = load_prefs(db, user.id)
        has_channel = (prefs.email_alerts or (prefs.telegram_alerts and prefs.telegram_chat_id
                                              and self.telegram is not None))
        if not prefs.alerts_enabled or not has_channel:
            self._set_state(db, scan.id, "skipped")
            return "skipped"

        fingerprint = hashlib.sha256(f"{scan.sender.lower()}|{scan.subject}".encode()).hexdigest()[:32]
        dedupe_key = f"alert:dedupe:{user.id}:{fingerprint}"
        if not self._once(dedupe_key, s.alert_dedupe_seconds):
            self._set_state(db, scan.id, "skipped")  # wahi campaign dobara
            return "skipped"
        if not allow(self.r, f"alert:rate:{user.id}", s.alert_max_per_hour, 3600):
            if self._once(f"alert:throttle:{user.id}", 3600):  # ek ghante mein sirf ek "throttled" notice
                self._send(db, user, prefs, *fmt.build_throttle_notice(s.alert_max_per_hour, self._dashboard_url()))
            self._set_state(db, scan.id, "skipped")
            return "skipped"

        title, body = fmt.build_scan_alert(
            verdict=scan.verdict, score=scan.score, action_taken=scan.action_taken, sender=scan.sender,
            subject=scan.subject, reasons=scan.reasons or [], urls=scan.urls or [],
            dashboard_url=self._dashboard_url(),
        )
        attempted, ok = self._send(db, user, prefs, title, body)
        if ok > 0:
            self._set_state(db, scan.id, "sent")
            return "sent"
        if attempted == 0:
            self._set_state(db, scan.id, "skipped")  # sirf Telegram thi aur wo block nikli
            return "skipped"
        attempts = scan.alert_attempts + 1
        try:
            self.r.delete(dedupe_key)  # dobara koshish par dedupe rukawat na bane
        except redis.RedisError:
            pass
        if attempts >= s.alert_max_attempts:
            self._set_state(db, scan.id, "failed", attempts)
            log.error("Alert %s ke liye koshishein khatam", scan.id)
            return "failed"
        self._set_state(db, scan.id, "pending", attempts)
        return "retry"

    def dispatch_pending(self, db: DbSession, account_id: uuid.UUID, limit: int = 50) -> int:
        """Pichhle run/crash ke baqi pending alerts (is account ke). Kitne bheje gaye wo lautata hai."""
        ids = db.scalars(
            select(Scan.id).where(Scan.gmail_account_id == account_id, Scan.alert_state == "pending")
            .order_by(Scan.created_at).limit(limit)
        ).all()
        return sum(1 for sid in ids if self.dispatch_scan(db, sid) == "sent")

    # ------------------------------------------------------------ plain notice (reauth waghera)
    def notify_user(self, db: DbSession, user_id: uuid.UUID, title: str, body: str) -> bool:
        user = db.get(User, user_id)
        if user is None:
            return False
        prefs = load_prefs(db, user_id)
        if not prefs.alerts_enabled:
            return False
        _, ok = self._send(db, user, prefs, title, body)
        return ok > 0
