"""Gmail REST API (messages / history / labels). Sirf apni mailbox ("me"), sirf zaroori calls.

Usool:
- Har call pe timeout + retry/backoff (429, 5xx, network, rate-limit wali 403).
  Retry-After maana jata hai (cap ke saath).
- Response ki size par hadd (bari email poori memory mein nahi aati).
- Token, email body ya URL kabhi log nahi hota (sirf status code / short code).
- Email sirf PARHI jati hai (format=raw); koi link/attachment khola ya chalaya nahi jata.
- Tests mein `transport=httpx.MockTransport(...)` se asli Gmail ke baghair chalta hai.
"""
import base64
import binascii
import json
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from backend.app.config import get_settings

log = logging.getLogger("aliguard.gmail.api")
# Telegram/HTTP libraries ka INFO log poora URL likhta hai; hum kabhi URL log nahi karna chahte
logging.getLogger("httpx").setLevel(logging.WARNING)

API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
INBOX = "INBOX"
LABEL_SUSPICIOUS = "AliGuard/Suspicious"
LABEL_QUARANTINE = "AliGuard/Quarantine"

_ID_RE = re.compile(r"[0-9A-Za-z_-]{1,64}")
_RATE_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded", "quotaExceeded"}
_MAX_RETRY_AFTER = 30.0
_MAX_SMALL_BODY = 2_000_000
_MAX_HISTORY_PAGES = 10


class GmailError(Exception):
    """Gmail se baat nakam. `code` sirf short label hai, user ko tafseel nahi dikhti."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class GmailAuthError(GmailError):
    """401: access token expire/revoke. Caller ek bar refresh karke dobara koshish kar sakta hai."""


class GmailPermissionError(GmailError):
    """403 (rate limit nahi): scope/permission masla."""


class GmailNotFound(GmailError):
    """404: message/label nahi mila (user ne delete kar diya hoga)."""


class GmailHistoryExpired(GmailError):
    """startHistoryId bohat purana (Gmail ~1 hafte ki history rakhta hai)."""


class GmailTooLarge(GmailError):
    """Response hamari hadd se bara."""


class GmailTransient(GmailError):
    """Retries ke baad bhi 429/5xx/network. Baad mein dobara try karna chahiye."""


class GmailBadRequest(GmailError):
    """Baqi 4xx."""


@dataclass
class HistoryBatch:
    """items: [(message_id, history_record_id)] history ke order mein (dedupe ke baad)."""

    items: list[tuple[str, str]] = field(default_factory=list)
    next_start: str | None = None  # sab items process ho jayen to history_id yahan le jao


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise GmailBadRequest("bad_id")
    return value


def _read_capped(resp: httpx.Response, limit: int) -> bytes:
    declared = resp.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise GmailTooLarge("too_large")
    buf = bytearray()
    for chunk in resp.iter_bytes():
        buf += chunk
        if len(buf) > limit:
            raise GmailTooLarge("too_large")
    return bytes(buf)


def _error_reason(body: bytes) -> str:
    try:
        err = json.loads(body.decode("utf-8", "replace")).get("error", {})
        if isinstance(err, dict):
            errors = err.get("errors")
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                return str(errors[0].get("reason", ""))[:40]
            return str(err.get("status", ""))[:40]
    except (ValueError, AttributeError):
        pass
    return ""


def _retry_after(resp_headers) -> float:
    raw = resp_headers.get("retry-after", "")
    try:
        return max(0.0, min(float(raw), _MAX_RETRY_AFTER))
    except (TypeError, ValueError):
        return 0.0


class GmailClient:
    def __init__(self, access_token: str, transport: httpx.BaseTransport | None = None):
        self._token = access_token
        self._transport = transport
        self._labels: dict[str, str] | None = None  # lowercase naam -> id (ek client ki umr tak cache)

    # ------------------------------------------------------------ HTTP core
    def _call(self, method: str, path: str, *, params=None, body=None, max_bytes: int = _MAX_SMALL_BODY) -> dict:
        s = get_settings()
        attempts = max(1, s.google_http_retries)
        last = "gmail_unreachable"
        endpoint = path.split("/")[1] if path.startswith("/") else path  # sirf naam (messages/history), id nahi
        for attempt in range(attempts):
            wait = 0.0
            try:
                with httpx.Client(timeout=s.google_http_timeout_seconds, transport=self._transport) as client:
                    with client.stream(
                        method, f"{API_BASE}{path}", params=params, json=body,
                        headers={"Authorization": f"Bearer {self._token}"},
                    ) as resp:
                        status = resp.status_code
                        raw = _read_capped(resp, max_bytes)
                        wait = _retry_after(resp.headers)
            except httpx.HTTPError as exc:
                log.warning("Gmail network error %s (try %s)", type(exc).__name__, attempt + 1)
                last = "network"
            else:
                if 200 <= status < 300:
                    return self._json(raw)
                reason = _error_reason(raw)
                if status == 401:
                    raise GmailAuthError("unauthorized")
                if status == 404:
                    raise GmailNotFound("not_found")
                if status == 429 or status >= 500 or (status == 403 and reason in _RATE_REASONS):
                    log.warning("Gmail %s %s: status=%s reason=%s (try %s)", method, endpoint, status, reason,
                                attempt + 1)
                    last = f"http_{status}"
                elif status == 403:
                    raise GmailPermissionError(reason or "forbidden")
                else:
                    raise GmailBadRequest(f"http_{status}")
            if attempt < attempts - 1:
                time.sleep(max(wait, min(0.5 * 2**attempt, 8.0)))  # exponential backoff
        raise GmailTransient(last)

    @staticmethod
    def _json(raw: bytes) -> dict:
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            raise GmailError("bad_response") from exc
        if not isinstance(data, dict):
            raise GmailError("bad_response")
        return data

    # ------------------------------------------------------------ read
    def profile(self) -> dict:
        data = self._call("GET", "/profile")
        hid = data.get("historyId")
        if hid is None:
            raise GmailError("bad_response")
        return {"email": str(data.get("emailAddress", "")).lower(), "history_id": str(hid)}

    def list_inbox_ids(self, max_results: int) -> list[str]:
        """Inbox ki sab se nayi emails (naya pehle)."""
        data = self._call("GET", "/messages", params={"labelIds": INBOX, "maxResults": max(1, min(max_results, 100))})
        return [m["id"] for m in data.get("messages", []) if isinstance(m, dict) and isinstance(m.get("id"), str)
                and _ID_RE.fullmatch(m["id"])]

    def history(self, start_history_id: str) -> HistoryBatch:
        """start_history_id ke baad INBOX mein aayi nayi emails. Bohat purana ho to GmailHistoryExpired."""
        _check_id(start_history_id)
        items: dict[str, str] = {}
        page: str | None = None
        latest: str | None = None
        last_record: str | None = None
        complete = False
        for _ in range(_MAX_HISTORY_PAGES):
            params = {"startHistoryId": start_history_id, "historyTypes": "messageAdded", "labelId": INBOX,
                      "maxResults": 100}
            if page:
                params["pageToken"] = page
            try:
                data = self._call("GET", "/history", params=params)
            except GmailNotFound as exc:
                raise GmailHistoryExpired("history_expired") from exc
            for rec in data.get("history", []):
                if not isinstance(rec, dict):
                    continue
                rec_id = str(rec.get("id", ""))
                last_record = rec_id or last_record
                for added in rec.get("messagesAdded", []):
                    msg = added.get("message") if isinstance(added, dict) else None
                    mid = msg.get("id") if isinstance(msg, dict) else None
                    if isinstance(mid, str) and _ID_RE.fullmatch(mid) and mid not in items:
                        items[mid] = rec_id or start_history_id
            if data.get("historyId") is not None:
                latest = str(data["historyId"])
            page = data.get("nextPageToken") if isinstance(data.get("nextPageToken"), str) else None
            if not page:
                complete = True
                break
        # Pages khatam na hon to sirf wahin tak badho jahan tak dekha (baqi agle run mein, kuch gum nahi hota)
        next_start = latest if complete else (last_record or start_history_id)
        return HistoryBatch(items=list(items.items()), next_start=next_start)

    def get_raw(self, message_id: str) -> bytes:
        """Poori RFC822 email (read-only). Bohat bari ho to GmailTooLarge."""
        data = self._call("GET", f"/messages/{quote(_check_id(message_id))}", params={"format": "raw"},
                          max_bytes=get_settings().gmail_max_message_bytes)
        raw = data.get("raw")
        if not isinstance(raw, str):
            raise GmailError("bad_response")
        try:
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except (binascii.Error, ValueError) as exc:
            raise GmailError("bad_response") from exc

    def get_headers(self, message_id: str) -> list[tuple[str, str]]:
        """Sirf zaroori headers (bari email ka fallback)."""
        data = self._call(
            "GET", f"/messages/{quote(_check_id(message_id))}",
            params={"format": "metadata",
                    "metadataHeaders": ["From", "Reply-To", "Subject", "Authentication-Results"]},
        )
        headers = data.get("payload", {}).get("headers", []) if isinstance(data.get("payload"), dict) else []
        return [(str(h.get("name", "")), str(h.get("value", ""))) for h in headers if isinstance(h, dict)]

    # ------------------------------------------------------------ labels
    def _load_labels(self, force: bool = False) -> dict[str, str]:
        if self._labels is None or force:
            data = self._call("GET", "/labels")
            self._labels = {
                str(lb["name"]).lower(): str(lb["id"]) for lb in data.get("labels", [])
                if isinstance(lb, dict) and "name" in lb and "id" in lb
            }
        return self._labels

    def find_label(self, name: str) -> str | None:
        return self._load_labels().get(name.lower())

    def ensure_label(self, name: str) -> str:
        existing = self.find_label(name)
        if existing:
            return existing
        try:
            data = self._call("POST", "/labels", body={
                "name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show",
            })
        except GmailBadRequest:
            # Race: kisi ne abhi abhi bana diya (409). Dobara dekho.
            found = self._load_labels(force=True).get(name.lower())
            if found:
                return found
            raise
        label_id = data.get("id")
        if not isinstance(label_id, str):
            raise GmailError("bad_response")
        self._load_labels()[name.lower()] = label_id
        return label_id

    # ------------------------------------------------------------ write
    def modify(self, message_id: str, add: list[str], remove: list[str]) -> None:
        """Labels badlo. Idempotent hai: dobara chalane se koi nuqsan nahi."""
        self._call("POST", f"/messages/{quote(_check_id(message_id))}/modify",
                   body={"addLabelIds": add, "removeLabelIds": remove})

    def label_suspicious(self, message_id: str) -> None:
        self.modify(message_id, add=[self.ensure_label(LABEL_SUSPICIOUS)], remove=[])

    def quarantine(self, message_id: str) -> None:
        """AliGuard/Quarantine label lagao aur INBOX se hatao. Trash/delete NAHI."""
        self.modify(message_id, add=[self.ensure_label(LABEL_QUARANTINE)], remove=[INBOX])

    def restore(self, message_id: str) -> None:
        """Inbox wapas, hamare labels hata do (jo labels maujood hi nahi unhein banate nahi)."""
        remove = [i for i in (self.find_label(LABEL_QUARANTINE), self.find_label(LABEL_SUSPICIOUS)) if i]
        self.modify(message_id, add=[INBOX], remove=remove)
