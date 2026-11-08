"""Telegram /start se chat link karna.

Flow: dashboard 'Telegram link karein' -> server ek random code banata hai (Redis mein sirf uska hash, 10 min,
single-use) -> user t.me/<bot>?start=<code> kholta hai -> worker ka poller /start <code> dekhta hai -> chat_id
us user ki settings mein. Code sirf usi ke paas hai jis ne dashboard se maanga, isliye koi aur apni chat kisi
doosre ke account se nahi jor sakta. Sirf private chat (group nahi)."""
import hashlib
import logging
import re
import secrets
import threading
import time
import uuid

import redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend.app.alerts.telegram import TelegramClient
from backend.app.config import get_settings
from backend.app.models import AlertSettings, User
from backend.app.prefs import get_or_create_settings

log = logging.getLogger("aliguard.telegram.link")

_CODE_RE = re.compile(r"[A-Za-z0-9_-]{20,64}")
_LINK_PREFIX = "tg:link:"
_OFFSET_KEY = "tg:offset"
_LOCK_KEY = "worker:telegram:poller"

HELP = "AliGuard dashboard ki Settings se 'Telegram link karein' dabayein, phir wahan ka link yahan kholein."


def _code_key(code: str) -> str:
    return _LINK_PREFIX + hashlib.sha256(code.encode()).hexdigest()  # raw code Redis mein nahi


def create_link_code(r, user_id: uuid.UUID) -> str:
    """RedisError bahar jata hai (router 503 deta hai: fail-closed)."""
    code = secrets.token_urlsafe(24)
    r.set(_code_key(code), str(user_id), ex=get_settings().telegram_link_ttl_seconds)
    return code


def link_url(code: str) -> str:
    return f"https://t.me/{get_settings().telegram_bot_username}?start={code}"


def handle_update(db, r, client: TelegramClient, update: dict) -> str:
    """Return: linked | invalid | conflict | ignored."""
    msg = update.get("message")
    chat = msg.get("chat") if isinstance(msg, dict) else None
    if not isinstance(chat, dict) or chat.get("type") != "private" or not isinstance(chat.get("id"), int):
        return "ignored"
    text = msg.get("text")
    parts = text.strip().split(maxsplit=1) if isinstance(text, str) else []
    if not parts or parts[0].split("@")[0] != "/start":
        return "ignored"  # random baat-cheet ka jawab nahi (bot par spam se API calls na barhein)
    chat_id = str(chat["id"])
    code = parts[1].strip() if len(parts) > 1 else ""
    if not _CODE_RE.fullmatch(code):
        client.send_message(chat_id, HELP)
        return "invalid"
    try:
        raw = r.getdel(_code_key(code))  # single-use: ek hi bar kaam karega
    except redis.RedisError:
        log.warning("Telegram link: Redis available nahi")
        return "invalid"
    try:
        user_id = uuid.UUID(raw.decode() if isinstance(raw, bytes) else str(raw)) if raw else None
    except ValueError:
        user_id = None
    user = db.get(User, user_id) if user_id else None
    if user is None:
        client.send_message(chat_id, "Ye link expire ho chuka ya ghalat hai. Dashboard se naya link banayein.")
        return "invalid"
    taken = db.scalar(
        select(AlertSettings.user_id).where(AlertSettings.telegram_chat_id == chat_id,
                                            AlertSettings.user_id != user_id)
    )
    if taken is not None:
        client.send_message(chat_id, "Ye chat pehle se kisi aur AliGuard account se jur chuki hai.")
        return "conflict"
    row = get_or_create_settings(db, user_id)
    row.telegram_chat_id = chat_id
    row.telegram_alerts = True
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        client.send_message(chat_id, "Ye chat pehle se kisi aur AliGuard account se jur chuki hai.")
        return "conflict"
    client.send_message(chat_id, "AliGuard alerts ab is chat mein aayenge.")
    return "linked"


def _hold_lock(r, token: str) -> bool:
    """Sirf ek worker getUpdates chalaye (warna Telegram 409 Conflict deta hai)."""
    if r.set(_LOCK_KEY, token, nx=True, ex=60):
        return True
    current = r.get(_LOCK_KEY)
    if current is not None and current.decode() == token:
        r.expire(_LOCK_KEY, 60)
        return True
    return False


def poll_loop(stop: threading.Event, session_factory, r, client: TelegramClient) -> None:
    """Chalta rehta hai; koi bhi error is thread ko marta nahi (log + sleep + dobara)."""
    token = secrets.token_hex(8)
    timeout = get_settings().telegram_poll_timeout_seconds
    while not stop.is_set():
        started = time.monotonic()
        try:
            if not _hold_lock(r, token):
                stop.wait(10)
                continue
            raw_offset = r.get(_OFFSET_KEY)
            offset = int(raw_offset) if raw_offset is not None else None
            updates = client.get_updates(offset, timeout)
            for upd in updates:
                try:
                    with session_factory() as db:
                        handle_update(db, r, client, upd)
                except Exception:  # noqa: BLE001 - ek kharab update baqi ko na rokay
                    log.exception("Telegram update handle nahi hua")
                if isinstance(upd.get("update_id"), int):
                    offset = upd["update_id"] + 1
                    r.set(_OFFSET_KEY, offset, ex=30 * 86400)
        except Exception:  # noqa: BLE001
            log.exception("Telegram poller error")
            stop.wait(5)
            continue
        if time.monotonic() - started < 1.0:
            stop.wait(3)  # error par foran wapas aane se hot loop na bane
