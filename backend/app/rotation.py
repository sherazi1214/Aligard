"""Encryption key rotation: sab encrypted secrets ko naye primary ENCRYPTION_KEY se dobara encrypt karo."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from backend.app.models import GmailAccount, User
from backend.app.security import decrypt_secret, encrypt_secret

log = logging.getLogger("aliguard.rotation")


def reencrypt_all(db: DbSession, *, dry_run: bool = False) -> dict:
    """Return counts. Jo value decrypt na ho (kisi na-maloom key se) usay chhua nahi jata, sirf gina jata hai."""
    counts = {"rotated": 0, "undecryptable": 0}

    def _redo(value: str | None) -> str | None:
        if not value:
            return value
        plain = decrypt_secret(value)
        if plain is None:
            counts["undecryptable"] += 1
            return value
        counts["rotated"] += 1
        return encrypt_secret(plain)

    for user in db.scalars(select(User).where(User.totp_secret_encrypted.is_not(None))):
        new = _redo(user.totp_secret_encrypted)
        if not dry_run:
            user.totp_secret_encrypted = new
    for acc in db.scalars(select(GmailAccount)):
        new_refresh = _redo(acc.refresh_token_encrypted)
        new_access = _redo(acc.access_token_encrypted)
        if not dry_run:
            acc.refresh_token_encrypted, acc.access_token_encrypted = new_refresh, new_access
    if dry_run:
        db.rollback()
    else:
        db.commit()
    log.info("Key rotation: %s (dry_run=%s)", counts, dry_run)
    return counts
