"""Gmail access token ka intezam: encrypted store se uthao, expire ho to refresh token se naya lo.
Web (restore) aur worker dono yahi use karte hain. Tokens kabhi log nahi hote."""
import logging
from collections.abc import Callable
from datetime import timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session as DbSession

from backend.app.gmail import google
from backend.app.models import GmailAccount, utcnow
from backend.app.security import decrypt_secret, encrypt_secret

log = logging.getLogger("aliguard.gmail.tokens")
_EXPIRY_MARGIN = timedelta(seconds=90)


class NeedsReauth(Exception):
    """User ko Gmail dobara connect karna hoga (refresh token bekar ya decrypt nahi hota)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def refresh_access(db: DbSession, acc: GmailAccount, refresher: Callable[[str], dict] | None = None) -> str:
    """Refresh token se naya access token (hamesha network call). Transient fail par GoogleError uthta hai."""
    if not acc.refresh_token_encrypted:
        raise NeedsReauth("no_refresh_token")
    refresh = decrypt_secret(acc.refresh_token_encrypted)
    if not refresh:
        # ENCRYPTION_KEY badal gayi ya data kharab: purane tokens kabhi decrypt nahi honge
        raise NeedsReauth("token_undecryptable")
    try:
        data = (refresher or google.refresh_access_token)(refresh)
    except google.GoogleError as exc:
        if exc.code == "invalid_grant":
            raise NeedsReauth("invalid_grant") from exc
        raise
    try:
        expires_in = int(data.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600
    expires_in = max(60, min(expires_in, 86400))
    access = data["access_token"]
    acc.access_token_encrypted = encrypt_secret(access)
    acc.access_expires_at = utcnow() + timedelta(seconds=expires_in)
    if isinstance(data.get("refresh_token"), str) and data["refresh_token"]:
        acc.refresh_token_encrypted = encrypt_secret(data["refresh_token"])  # Google kabhi naya bhi deta hai
    db.commit()
    return access


def access_token_for(db: DbSession, acc: GmailAccount, refresher: Callable[[str], dict] | None = None) -> str:
    """Valid access token: pehle store wala (agar 90s se zyada baqi), warna refresh."""
    if acc.access_token_encrypted and acc.access_expires_at and acc.access_expires_at - utcnow() > _EXPIRY_MARGIN:
        token = decrypt_secret(acc.access_token_encrypted)
        if token:
            return token
    return refresh_access(db, acc, refresher)


def mark_needs_reauth(db: DbSession, account_id, code: str) -> bool:
    """Sirf 'active' account ko needs_reauth karo (user ne beech mein disconnect kiya ho to usay mat chhedo).
    True lautata hai agar status asal mein badla (taake notice ek hi bar jaye)."""
    res = db.execute(
        update(GmailAccount)
        .where(GmailAccount.id == account_id, GmailAccount.status == "active")
        .values(status="needs_reauth", last_error=code[:64], next_run_at=None)
    )
    db.commit()
    return res.rowcount == 1
