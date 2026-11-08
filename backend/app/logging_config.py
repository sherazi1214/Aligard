"""Structured (JSON) logging with secret/PII masking. Logs mein password, token, email address ya
database/redis URL ka password kabhi nahi jana chahiye; yahan har final log line mask hoti hai."""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime

# Order matters: pehle key=value / Bearer, phir email, phir lambe random tokens.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(postgres(?:ql)?(?:\+\w+)?|rediss?|amqp)://[^\s'\"]+"), r"\1://[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|refresh_token|access_token|"
        r"code|state|dsn)(\s*[=:]\s*)([^\s&,;\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    # 32+ char random-looking strings (UUID nahi, wo debugging ke liye rakhe jate hain)
    (re.compile(r"\b(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)[A-Za-z0-9_-]{32,}\b"), "[REDACTED]"),
]

_STD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}


def mask(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": mask(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _STD_ATTRS and not key.startswith("_"):
                data[key] = mask(value) if isinstance(value, str) else value
        if record.exc_info:
            data["exc"] = mask(self.formatException(record.exc_info))
        return json.dumps(data, ensure_ascii=False, default=str)


class MaskedTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return mask(super().format(record))


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(MaskedTextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    # Uvicorn ka access log query string (verify/reset tokens!) likhta hai; apna masked access log use hota hai.
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False
    access.disabled = True
