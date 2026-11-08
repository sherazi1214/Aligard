"""Portal (aliguard-portal) se one-time signed handoff token.

Portal apne taur par signup/login (ya Google OAuth) se email verify karta hai, phir is token
ke zariye bata deta hai "ye email asli hai, is user ko yahan bhi login kar do". Hum khud
password nahi dekhte -- sirf HMAC signature (shared secret) aur short expiry par bharosa
karte hain. Replay se bachne ke liye token ka nonce DB mein (sso_nonces) ek hi bar consume
ho sakta hai -- dekhiye auth/router.py ka /sso route.
"""
import base64
import hmac
import json
import time
from dataclasses import dataclass

from backend.app.config import get_settings


@dataclass
class SsoPayload:
    email: str
    service: str  # khali string = sirf login, koi plan activate nahi karna
    nonce: str
    exp: int
    verified: bool = False  # portal ne email ownership verify ki hai (Google ya email link)


def _sign(raw: bytes) -> str:
    key = get_settings().sso_shared_secret.encode()
    return hmac.new(key, raw, "sha256").hexdigest()


def verify_token(token: str) -> SsoPayload | None:
    """Signature + format + expiry check karta hai. Nonce consume (replay-proof) caller DB mein karta hai."""
    secret = get_settings().sso_shared_secret
    if not secret or not token or len(token) > 2000 or "." not in token:
        return None
    body_b64, _, sig = token.partition(".")
    if not hmac.compare_digest(_sign(body_b64.encode()), sig):
        return None
    try:
        padded = body_b64 + "=" * (-len(body_b64) % 4)
        raw = base64.urlsafe_b64decode(padded)
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    email, service, nonce, exp = data.get("email"), data.get("service", ""), data.get("nonce"), data.get("exp")
    if not (isinstance(email, str) and 3 <= len(email) <= 254 and isinstance(service, str)
            and isinstance(nonce, str) and 10 <= len(nonce) <= 64 and isinstance(exp, int)):
        return None
    if exp < int(time.time()):
        return None
    return SsoPayload(email=email.strip().lower(), service=service, nonce=nonce, exp=exp,
                      verified=data.get("verified") is True)
