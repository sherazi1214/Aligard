"""Per-account Gmail scanner. Email body is parsed in memory only; never persisted or logged."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import timedelta

import redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from backend.app import redis_client as redis_module
from backend.app.alerts.format import build_reauth_notice
from backend.app.alerts.service import AlertService
from backend.app.alerts.telegram import get_client as get_telegram_client
from backend.app.budget import budget_user
from backend.app.config import get_settings
from backend.app.engine_factory import analyze
from backend.app.gmail import api as gmail_api
from backend.app.gmail import google
from backend.app.gmail.tokens import NeedsReauth, access_token_for, mark_needs_reauth, refresh_access
from backend.app.models import GmailAccount, Scan, utcnow
from backend.app.prefs import load_prefs, load_whitelist
from backend.app.worker.decision import (
    clean_text,
    decide_action,
    dmarc_passed,
    email_from_headers,
    format_sender,
    whitelist_hit,
)
from engine import EmailInput
from engine.parsing import from_raw_email

log = logging.getLogger("aliguard.worker.scanner")
_LOCK_PREFIX = "worker:account-lock:"


def _account_lock_key(account_id: uuid.UUID) -> str:
    return f"{_LOCK_PREFIX}{account_id}"


def _get_client(db: DbSession, account: GmailAccount) -> gmail_api.GmailClient:
    token = access_token_for(db, account)
    client = gmail_api.GmailClient(token)
    try:
        client.profile()
    except gmail_api.GmailAuthError:
        # Stale/revoked access token: refresh once and retry, never loop endlessly.
        token = refresh_access(db, account, refresher=google.refresh_access_token)
        client = gmail_api.GmailClient(token)
        client.profile()
    return client


def _message_input(client: gmail_api.GmailClient, message_id: str) -> EmailInput:
    try:
        raw = client.get_raw(message_id)
        return from_raw_email(raw)
    except gmail_api.GmailTooLarge:
        # Bari email ka body download/store nahi karte; sirf required headers analyze hote hain.
        return email_from_headers(client.get_headers(message_id))


_MAX_POSTMORTEM_BYTES = 24_000


def _safe_postmortem(pm) -> dict | None:
    """Engine postmortem pehle se defanged hai; yahan sirf size ki hadd (DB bloat/DoS se bachao)."""
    if not pm or not isinstance(pm, dict):
        return None
    import json
    try:
        if len(json.dumps(pm)) <= _MAX_POSTMORTEM_BYTES:
            return pm
        trimmed = {"version": pm.get("version", 1), "truncated": True,
                   "sandbox": pm.get("sandbox", [])[:1], "attachments": pm.get("attachments", [])[:3]}
        if len(json.dumps(trimmed)) <= _MAX_POSTMORTEM_BYTES:
            return trimmed
        return {"version": pm.get("version", 1), "truncated": True}
    except (TypeError, ValueError):
        return None


def _create_scan(db: DbSession, account: GmailAccount, message_id: str, email: EmailInput, redis_conn) -> Scan | None:
    existing = db.scalar(select(Scan).where(
        Scan.gmail_account_id == account.id, Scan.gmail_message_id == message_id
    ))
    if existing is not None:
        return existing

    with budget_user(account.user_id):
        result = analyze(email)
    verdict = result.verdict.value if hasattr(result.verdict, "value") else str(result.verdict)
    prefs = load_prefs(db, account.user_id)
    whitelist = load_whitelist(db, account.user_id)
    trusted = whitelist_hit(whitelist, email.sender_email) and dmarc_passed(email.headers, frozenset({"mx.google.com"}))
    if trusted:
        # Whitelist actions ko suppress karti hai sirf verified DMARC par; verdict evidence ko rewrite nahi karte.
        action = "none"
    else:
        action = decide_action(
            verdict, int(result.score), float(result.confidence),
            suspicious_threshold=prefs.suspicious_threshold,
            phishing_threshold=prefs.phishing_threshold,
            min_confidence=get_settings().quarantine_min_confidence,
        )

    sender = format_sender(email.sender_name, email.sender_email)
    # Engine defanged URLs only; do not store email body, raw links, or attachments.
    scan = Scan(
        user_id=account.user_id, gmail_account_id=account.id, gmail_message_id=message_id,
        sender=sender[:320], subject=clean_text(email.subject or "", 500),
        verdict=verdict, score=max(0, min(100, int(result.score))),
        reasons=[str(x)[:500] for x in (result.reasons or [])[:30]],
        layer_scores=result.layer_scores or {}, urls=(result.defanged_urls or [])[:100],
        action_taken="pending" if action != "none" else "none", planned_action=action,
        alert_state="pending" if verdict != "SAFE" else "none", alert_attempts=0,
        model_version=(result.model_version or "")[:64] or None,
        postmortem=_safe_postmortem(getattr(result, "postmortem", None)),
    )
    db.add(scan)
    try:
        db.commit()
        db.refresh(scan)
        return scan
    except IntegrityError:
        db.rollback()
        # Two worker processes can race; unique(account,message) guarantees one row.
        return db.scalar(select(Scan).where(
            Scan.gmail_account_id == account.id, Scan.gmail_message_id == message_id
        ))


def reconcile_account(db: DbSession, account: GmailAccount, client: gmail_api.GmailClient,
                      redis_conn=None) -> dict:
    """Finish Gmail actions/alerts that were committed but interrupted by a process crash."""
    done = failed = 0
    pending = db.scalars(select(Scan).where(
        Scan.gmail_account_id == account.id,
        Scan.action_taken == "pending",
        Scan.planned_action.in_(["label", "quarantine"]),
    ).order_by(Scan.created_at).limit(100)).all()
    for scan in pending:
        try:
            if scan.planned_action == "quarantine":
                client.quarantine(scan.gmail_message_id)
                scan.action_taken = "quarantined"
            else:
                client.label_suspicious(scan.gmail_message_id)
                scan.action_taken = "labeled"
            db.commit()
            done += 1
        except gmail_api.GmailNotFound:
            scan.action_taken = "failed"
            db.commit()
            failed += 1
        except gmail_api.GmailError:
            db.rollback()
            raise

    if redis_conn is not None:
        service = AlertService(redis_conn, telegram=get_telegram_client())
        # Dispatch individual pending alerts; service claims them atomically before sending.
        ids = db.scalars(select(Scan.id).where(
            Scan.gmail_account_id == account.id, Scan.alert_state == "pending"
        ).order_by(Scan.created_at).limit(50)).all()
        for scan_id in ids:
            try:
                service.dispatch_scan(db, scan_id)
            except Exception:  # alerts must not stop email scanning
                log.exception("Alert dispatch fail hua; scan_id=%s", scan_id)
    return {"actions_reconciled": done, "actions_failed": failed}


def _notify_reauth(redis_conn, db: DbSession, account_id: uuid.UUID) -> None:
    account = db.get(GmailAccount, account_id)
    if account is None:
        return
    try:
        service = AlertService(redis_conn, telegram=get_telegram_client())
        service.notify_user(db, account.user_id, *build_reauth_notice(account.google_email,
            f"{get_settings().base_url.rstrip('/')}/dashboard"))
    except Exception:
        log.exception("Re-auth notice bhejna fail hua account_id=%s", account_id)


def scan_account(db: DbSession, account_id: uuid.UUID, redis_conn=None, *, force: bool = False) -> dict:
    """Scan one account safely. Uses Redis lock to avoid overlapping workers for the same mailbox."""
    s = get_settings()
    r = redis_conn if redis_conn is not None else redis_module.redis_client
    lock_key = _account_lock_key(account_id)
    lock_token = str(uuid.uuid4())
    lock_ttl = max(60, int(s.worker_run_budget_seconds) + 30)
    try:
        acquired = bool(r.set(lock_key, lock_token, nx=True, ex=lock_ttl))
    except redis.RedisError as exc:
        # Fail closed: without the lock we cannot guarantee dedupe/action reconciliation safely.
        raise RuntimeError("worker_lock_unavailable") from exc
    if not acquired:
        return {"status": "locked", "account_id": str(account_id), "scanned": 0}

    started = time.monotonic()
    counts = {"status": "ok", "account_id": str(account_id), "scanned": 0, "actions_reconciled": 0}
    try:
        account = db.scalar(select(GmailAccount).where(
            GmailAccount.id == account_id, GmailAccount.status == "active"
        ))
        if account is None:
            return {"status": "inactive", "account_id": str(account_id), "scanned": 0}
        client = _get_client(db, account)
        # Reconcile persisted pending Gmail actions before fetching new messages.
        reconciled = reconcile_account(db, account, client, r)
        counts.update(reconciled)

        if not account.history_id:
            # Establish a bookmark BEFORE listing. If a message arrives during backfill, next history pass sees it.
            profile = client.profile()
            ids = client.list_inbox_ids(s.worker_initial_backfill) if s.worker_initial_backfill > 0 else []
            for message_id in ids:
                if time.monotonic() - started > s.worker_run_budget_seconds:
                    counts["status"] = "budget_exceeded"
                    return counts  # do not move bookmark until every listed message is processed
                try:
                    email = _message_input(client, message_id)
                    _create_scan(db, account, message_id, email, r)
                    counts["scanned"] += 1
                except gmail_api.GmailNotFound:
                    continue  # user deleted it during scan
            account.history_id = profile["history_id"]
        else:
            try:
                batch = client.history(account.history_id)
            except gmail_api.GmailHistoryExpired:
                profile = client.profile()
                ids = client.list_inbox_ids(s.worker_initial_backfill) if s.worker_initial_backfill > 0 else []
                for message_id in ids:
                    if time.monotonic() - started > s.worker_run_budget_seconds:
                        counts["status"] = "budget_exceeded"
                        return counts
                    try:
                        email = _message_input(client, message_id)
                        _create_scan(db, account, message_id, email, r)
                        counts["scanned"] += 1
                    except gmail_api.GmailNotFound:
                        continue
                account.history_id = profile["history_id"]
            else:
                selected = batch.items[:s.worker_max_messages_per_run]
                # Do not split a Gmail history record: multiple messages can share one history ID.
                if len(batch.items) > len(selected) and selected:
                    boundary = selected[-1][1]
                    for item in batch.items[len(selected):]:
                        if item[1] != boundary:
                            break
                        selected.append(item)
                # Commit the bookmark after each complete history record. If the time budget is hit,
                # the next process resumes from the last completed record instead of looping forever.
                groups = []
                for item in selected:
                    if not groups or groups[-1][0] != item[1]:
                        groups.append((item[1], []))
                    groups[-1][1].append(item[0])
                for history_record_id, message_ids in groups:
                    if time.monotonic() - started > s.worker_run_budget_seconds:
                        counts["status"] = "budget_exceeded"
                        return counts
                    for message_id in message_ids:
                        try:
                            email = _message_input(client, message_id)
                            _create_scan(db, account, message_id, email, r)
                            counts["scanned"] += 1
                        except gmail_api.GmailNotFound:
                            continue
                    account.history_id = history_record_id
                    db.commit()
                if len(selected) == len(batch.items) and batch.next_start:
                    account.history_id = batch.next_start

        account.last_run_at = utcnow()
        account.last_error = None
        account.consecutive_failures = 0
        account.next_run_at = utcnow() + timedelta(seconds=s.worker_account_interval_seconds)
        db.commit()
        # Newly created scans' actions/alerts are now reconciled in this same run.
        reconciled = reconcile_account(db, account, client, r)
        counts["actions_reconciled"] = counts.get("actions_reconciled", 0) + reconciled["actions_reconciled"]
        return counts
    except NeedsReauth as exc:
        db.rollback()
        changed = mark_needs_reauth(db, account_id, exc.code)
        if changed:
            _notify_reauth(r, db, account_id)
        counts["status"] = "needs_reauth"
        return counts
    except gmail_api.GmailAuthError:
        db.rollback()
        changed = mark_needs_reauth(db, account_id, "gmail_unauthorized")
        if changed:
            _notify_reauth(r, db, account_id)
        counts["status"] = "needs_reauth"
        return counts
    except Exception as exc:
        db.rollback()
        log.warning("Account scan fail hua account_id=%s error=%s", account_id, type(exc).__name__)
        account = db.get(GmailAccount, account_id)
        if account is not None and account.status == "active":
            failures = int(account.consecutive_failures or 0) + 1
            delay = min(s.worker_backoff_max_seconds, s.worker_backoff_base_seconds * (2 ** min(failures - 1, 12)))
            account.consecutive_failures = failures
            account.last_error = str(getattr(exc, "code", "worker_error"))[:64]
            account.next_run_at = utcnow() + timedelta(seconds=delay)
            db.commit()
        counts["status"] = "error"
        counts["error"] = type(exc).__name__
        return counts
    finally:
        try:
            # Compare-and-delete so we never release another worker's lock.
            r.eval("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
                   1, lock_key, lock_token)
        except Exception as exc:
            # TTL bounds a stale lock if Redis is temporarily unavailable.
            log.debug("Worker lock release defer hua: %s", type(exc).__name__)
