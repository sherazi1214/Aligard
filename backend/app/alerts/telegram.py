"""Telegram Bot API (sirf plain text). Bot token URL mein jata hai, isliye:
- koi bhi log line URL ya exception ka text nahi likhti (sirf type/status)
- httpx ka INFO logger (jo poora URL likhta hai) WARNING par rakha gaya hai."""
import logging
import time

import httpx

from backend.app.config import get_settings

log = logging.getLogger("aliguard.telegram")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

OK, BLOCKED, RETRY = "ok", "blocked", "retry"
_API = "https://api.telegram.org"
_MAX_TEXT = 4000


class TelegramClient:
    def __init__(self, token: str, transport: httpx.BaseTransport | None = None):
        self._token = token
        self._transport = transport

    def _post(self, method: str, payload: dict, timeout: float) -> httpx.Response:
        with httpx.Client(timeout=timeout, transport=self._transport) as client:
            return client.post(f"{_API}/bot{self._token}/{method}", json=payload)

    def send_message(self, chat_id: str, text: str) -> str:
        """OK | BLOCKED (user ne bot block kiya / chat nahi mili: dobara koshish bekar) | RETRY (baad mein)."""
        payload = {"chat_id": chat_id, "text": text[:_MAX_TEXT], "disable_web_page_preview": True}
        for attempt in range(2):
            try:
                resp = self._post("sendMessage", payload, 10.0)
            except httpx.HTTPError as exc:
                log.warning("Telegram network error %s", type(exc).__name__)
                time.sleep(0.5)
                continue
            if resp.status_code == 200:
                return OK
            if resp.status_code in (400, 403):  # 403: bot blocked; 400: chat not found
                log.warning("Telegram ne chat reject ki: status=%s", resp.status_code)
                return BLOCKED
            wait = 0.0
            if resp.status_code == 429:
                try:
                    wait = float(resp.json().get("parameters", {}).get("retry_after", 1))
                except (ValueError, AttributeError, TypeError):
                    wait = 1.0
            log.warning("Telegram status=%s (try %s)", resp.status_code, attempt + 1)
            if attempt == 0:
                time.sleep(min(max(wait, 0.5), 10.0))
        return RETRY

    def get_updates(self, offset: int | None, timeout_seconds: int) -> list[dict]:
        """Long polling. Network/HTTP error par khali list (caller sleep karke dobara chalayega)."""
        payload: dict = {"timeout": timeout_seconds, "allowed_updates": ["message"]}
        if offset is not None:
            payload["offset"] = offset
        try:
            resp = self._post("getUpdates", payload, timeout_seconds + 10.0)
        except httpx.HTTPError as exc:
            log.warning("Telegram getUpdates network error %s", type(exc).__name__)
            return []
        if resp.status_code != 200:
            log.warning("Telegram getUpdates status=%s", resp.status_code)
            return []
        try:
            data = resp.json()
        except ValueError:
            return []
        result = data.get("result") if isinstance(data, dict) else None
        return [u for u in result if isinstance(u, dict)] if isinstance(result, list) else []


def get_client() -> TelegramClient | None:
    s = get_settings()
    return TelegramClient(s.telegram_bot_token) if s.telegram_configured else None
