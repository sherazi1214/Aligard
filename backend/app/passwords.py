"""Password policy + HaveIBeenPwned k-anonymity breach check."""
import hashlib
import logging
import time

import httpx

from backend.app.config import get_settings

log = logging.getLogger("aliguard.passwords")

MIN_LEN = 12
MAX_LEN = 128  # Argon2 par lambi input se DoS na ho

# Chhoti si common list; asal ilaaj HIBP breach check hai
_COMMON = {
    "password", "password1", "password123", "123456789012", "qwertyuiopas", "qwerty123456",
    "iloveyou1234", "admin1234567", "welcome12345", "letmein12345", "changeme1234",
    "pakistan1234", "pakistan12345", "123456789abc", "abcdefghijkl", "aliguard12345",
}


def policy_errors(password: str, email: str = "") -> list[str]:
    errs = []
    if len(password) < MIN_LEN:
        errs.append(f"Password kam az kam {MIN_LEN} characters ka ho")
    if len(password) > MAX_LEN:
        errs.append(f"Password {MAX_LEN} characters se lamba nahi ho sakta")
    low = password.lower()
    if low in _COMMON or len(set(password)) <= 3:
        errs.append("Ye password bohat aam / andaza lagane wala hai")
    local = email.split("@")[0].lower()
    if len(local) >= 4 and local in low:
        errs.append("Password mein apna email naam na rakhein")
    return errs


def is_breached(password: str) -> bool:
    """HIBP range API: sirf SHA-1 ke pehle 5 chars bahar jate hain. Network fail ho to False
    (fail-open, log hota hai) taake HIBP down hone par signup band na ho."""
    if not get_settings().hibp_enabled:
        return False
    digest = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()  # noqa: S324
    prefix, suffix = digest[:5], digest[5:]
    for attempt in range(3):
        try:
            r = httpx.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true", "User-Agent": "AliGuard"},
                timeout=3.0,
            )
            r.raise_for_status()
            for line in r.text.splitlines():
                h, _, count = line.partition(":")
                if h.strip() == suffix and count.strip() not in ("", "0"):
                    return True
            return False
        except httpx.HTTPError as exc:
            log.warning("HIBP check fail (attempt %d): %s", attempt + 1, type(exc).__name__)
            time.sleep(0.3 * 2**attempt)
    return False
