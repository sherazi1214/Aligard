"""Layer 0: raw email -> EmailInput, aur HTML se text + links nikalna."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from engine.models import EmailInput
from engine.urls import extract_urls

log = logging.getLogger("engine.parsing")
MAX_RAW_BYTES = 10_000_000
MAX_LINKS = 200


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, anchor text)
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            if len(self.links) < MAX_LINKS:
                self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def parse_html(html: str) -> tuple[str, list[tuple[str, str]]]:
    """(visible text, [(href, anchor_text)]). Kharab HTML par bhi crash nahi."""
    if not html:
        return "", []
    ex = _Extractor()
    try:
        ex.feed(html)
        ex.close()
    except Exception:  # noqa: BLE001 - HTMLParser kabhi kabhi ajeeb input par girta hai
        log.warning("HTML parse adhoora raha")
    return " ".join(" ".join(ex.text).split()), ex.links


@dataclass
class Content:
    """Analysis ke liye taiyar content."""

    text: str  # subject ke baghair visible body
    urls: list[str] = field(default_factory=list)
    anchors: list[tuple[str, str]] = field(default_factory=list)


def build_content(email: EmailInput, max_chars: int = 200_000) -> Content:
    html_text, anchors = parse_html(email.html_body[:max_chars])
    text = (email.text_body[:max_chars] or html_text)[:max_chars]
    urls: dict[str, None] = {}
    for href, _ in anchors:
        if href.lower().startswith(("http://", "https://", "www.")):
            urls[href.strip()] = None
    for u in extract_urls(email.text_body[:max_chars]) + extract_urls(html_text) + extract_urls(
        email.subject
    ):
        urls[u] = None
    return Content(text=text, urls=list(urls)[:100], anchors=anchors)


def _safe_str(value) -> str:
    try:
        return str(value) if value is not None else ""
    except Exception:  # noqa: BLE001 - kharab header encoding
        return ""


MAX_BINARY_PART = 5_000_000
MAX_BINARY_PARTS = 10


def _collect_binary(email: EmailInput, part, filename: str, ctype: str) -> None:
    """Attachment/inline image ke bytes (analysis ke liye). Kharab part par chup-chaap skip."""
    try:
        data = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return
    if not data or len(data) > MAX_BINARY_PART:
        return
    name = filename or f"inline.{ctype.split('/')[-1][:5]}"
    if ctype.startswith("image/"):
        if len(email.image_files) < MAX_BINARY_PARTS:
            email.image_files.append((name, data))
    if filename and len(email.attachment_files) < MAX_BINARY_PARTS:
        email.attachment_files.append((name, data))


def from_raw_email(raw: bytes) -> EmailInput:
    """RFC822 bytes se EmailInput. Garbage input par bhi khali/aadha result, exception nahi."""
    email = EmailInput()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw[:MAX_RAW_BYTES])
    except Exception:  # noqa: BLE001
        log.warning("Raw email parse nahi hui")
        return email
    email.headers = [(_safe_str(k), _safe_str(v)) for k, v in msg.items()]
    email.subject = _safe_str(msg.get("subject"))
    email.sender_name, email.sender_email = parseaddr(_safe_str(msg.get("from")))
    email.sender_email = email.sender_email.lower()
    email.reply_to = parseaddr(_safe_str(msg.get("reply-to")))[1].lower()
    plain: list[str] = []
    html: list[str] = []
    for part in msg.walk():
        try:
            filename = part.get_filename()
            ctype = part.get_content_type()
            if filename or ctype.startswith("image/"):
                _collect_binary(email, part, _safe_str(filename or ""), ctype)
            if filename:
                email.attachments.append(_safe_str(filename))
                continue
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                body = part.get_content()
            except Exception:  # noqa: BLE001 - ajeeb charset
                payload = part.get_payload(decode=True) or b""
                body = payload.decode("utf-8", "replace")
            (plain if ctype == "text/plain" else html).append(_safe_str(body))
        except Exception:  # noqa: BLE001, S112
            continue
    email.text_body = "\n".join(plain)
    email.html_body = "\n".join(html)
    return email
