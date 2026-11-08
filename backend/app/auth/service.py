"""Auth ka asal logic (HTTP se alag, taake test aur reuse aasan ho).
Passwords/tokens/secrets kabhi log nahi hote."""
import base64
import hmac
import io
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

import pyotp
import qrcode
import qrcode.image.svg
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from backend.app.config import get_settings
from backend.app.models import AuditLog, EmailToken, RecoveryCode, Session, User, utcnow
from backend.app.security import (
    DUMMY_HASH,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    needs_rehash,
    new_token,
    sha256_hex,
    verify_password,
)

TOTP_INTERVAL = 30
_TOTP_RE = re.compile(r"\d{6}")
_RECOVERY_RE = re.compile(r"[a-z0-9]{5}-[a-z0-9]{5}")
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def normalize_email(email: str) -> str:
    return email.strip().lower()


def audit(db: DbSession, event: str, user_id=None, ip: str | None = None) -> None:
    db.add(AuditLog(user_id=user_id, event=event, ip=ip))


def get_user_by_email(db: DbSession, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == normalize_email(email)))


# ---------- email tokens (verify / reset) ----------
def create_email_token(db: DbSession, user: User, purpose: str, ttl: timedelta) -> str:
    """Raw token sirf email mein jata hai, DB mein sirf hash. Purane unused tokens invalid."""
    now = utcnow()
    db.execute(
        update(EmailToken)
        .where(EmailToken.user_id == user.id, EmailToken.purpose == purpose, EmailToken.used_at.is_(None))
        .values(used_at=now)
    )
    raw = new_token()
    db.add(EmailToken(user_id=user.id, token_hash=sha256_hex(raw), purpose=purpose, expires_at=now + ttl))
    return raw


def consume_email_token(db: DbSession, raw: str, purpose: str) -> User | None:
    """Atomic single-use: UPDATE ... WHERE used_at IS NULL, rowcount 1 ho tabhi kamyab."""
    now = utcnow()
    tok = db.scalar(
        select(EmailToken).where(EmailToken.token_hash == sha256_hex(raw), EmailToken.purpose == purpose)
    )
    if tok is None or tok.used_at is not None or tok.expires_at <= now:
        return None
    res = db.execute(
        update(EmailToken).where(EmailToken.id == tok.id, EmailToken.used_at.is_(None)).values(used_at=now)
    )
    if res.rowcount != 1:
        return None
    return db.get(User, tok.user_id)


# ---------- sessions ----------
def create_session(db: DbSession, user: User, ip: str, ua: str | None, stage: str = "active") -> str:
    s = get_settings()
    minutes = s.session_absolute_minutes if stage == "active" else s.mfa_pending_minutes
    raw = new_token()
    now = utcnow()
    db.add(
        Session(
            user_id=user.id,
            session_hash=sha256_hex(raw),
            stage=stage,
            ip=ip,
            user_agent=(ua or "")[:255] or None,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(minutes=minutes),
        )
    )
    return raw


def load_session(db: DbSession, raw: str | None, stage: str = "active") -> tuple[User, Session] | None:
    """Cookie se valid session: revoke/expiry/idle/stage sab check."""
    if not raw or len(raw) > 128:
        return None
    sess = db.scalar(select(Session).where(Session.session_hash == sha256_hex(raw)))
    if sess is None or sess.revoked_at is not None or sess.stage != stage:
        return None
    now = utcnow()
    idle = timedelta(minutes=get_settings().session_idle_minutes)
    if sess.expires_at <= now or (stage == "active" and now - sess.last_seen_at > idle):
        return None
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        return None
    if now - sess.last_seen_at > timedelta(seconds=60):  # har request par write nahi
        sess.last_seen_at = now
        db.commit()
    return user, sess


def revoke_session_by_raw(db: DbSession, raw: str | None) -> None:
    if raw:
        db.execute(
            update(Session)
            .where(Session.session_hash == sha256_hex(raw), Session.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )


def revoke_all_sessions(db: DbSession, user_id, except_id=None) -> None:
    q = update(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    if except_id is not None:
        q = q.where(Session.id != except_id)
    db.execute(q.values(revoked_at=utcnow()))


# ---------- signup / verify ----------
def create_user(db: DbSession, email: str, password_hash: str) -> User:
    user = User(email=normalize_email(email), password_hash=password_hash)
    db.add(user)
    db.flush()
    return user


# ---------- login ----------
@dataclass
class LoginOutcome:
    status: str  # ok | mfa | fail | unverified
    session_token: str | None = None


def _lock_duration(count: int) -> timedelta | None:
    s = get_settings()
    if count < s.lockout_threshold:
        return None
    minutes = min(s.lockout_base_minutes * 2 ** (count - s.lockout_threshold), s.lockout_max_minutes)
    return timedelta(minutes=minutes)


def attempt_login(db: DbSession, email: str, password: str, ip: str, ua: str | None) -> LoginOutcome:
    user = get_user_by_email(db, email)
    now = utcnow()
    locked = user is not None and user.locked_until is not None and user.locked_until > now
    if user is None or not user.is_active or locked:
        # Dummy hash: timing se pata na chale ke account hai ya nahi / locked hai
        verify_password(DUMMY_HASH, password)
        audit(db, "login_failed", user.id if user else None, ip)
        db.commit()
        return LoginOutcome("fail")

    if not verify_password(user.password_hash, password):
        user.failed_login_count += 1
        dur = _lock_duration(user.failed_login_count)
        if dur:
            user.locked_until = now + dur
            audit(db, "account_locked", user.id, ip)
        audit(db, "login_failed", user.id, ip)
        db.commit()
        return LoginOutcome("fail")

    if not user.is_verified:
        audit(db, "login_unverified", user.id, ip)
        db.commit()
        return LoginOutcome("unverified")

    user.failed_login_count = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    if user.totp_enabled:
        token = create_session(db, user, ip, ua, stage="mfa_pending")
        audit(db, "login_password_ok_mfa_pending", user.id, ip)
        db.commit()
        return LoginOutcome("mfa", token)
    token = create_session(db, user, ip, ua)
    audit(db, "login_success", user.id, ip)
    db.commit()
    return LoginOutcome("ok", token)


# ---------- 2FA ----------
def _totp_match(user: User, code: str) -> int | None:
    """Sahi code ka time-step lautata hai (replay rokne ke liye), warna None. +-1 step tolerance."""
    secret = decrypt_secret(user.totp_secret_encrypted or "")
    if not secret:
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    current = int(utcnow().timestamp() // TOTP_INTERVAL)
    for step in (current - 1, current, current + 1):
        expected = totp.at(step * TOTP_INTERVAL)
        if hmac.compare_digest(expected, code) and step > user.totp_last_step:
            return step
    return None


def _use_recovery_code(db: DbSession, user: User, code: str) -> bool:
    h = sha256_hex(code.lower())
    rc = db.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.code_hash == h, RecoveryCode.used_at.is_(None)
        )
    )
    if rc is None:
        return False
    res = db.execute(
        update(RecoveryCode).where(RecoveryCode.id == rc.id, RecoveryCode.used_at.is_(None)).values(used_at=utcnow())
    )
    return res.rowcount == 1


def check_second_factor(db: DbSession, user: User, code: str) -> bool:
    """TOTP (6 digits) ya recovery code (xxxxx-xxxxx). Caller commit karta hai."""
    code = code.strip()
    if _TOTP_RE.fullmatch(code):
        step = _totp_match(user, code)
        if step is None:
            return False
        user.totp_last_step = step
        return True
    if _RECOVERY_RE.fullmatch(code.lower()):
        return _use_recovery_code(db, user, code)
    return False


def complete_mfa(db: DbSession, user: User, pending: Session, code: str, ip: str, ua: str | None) -> str | None:
    """Kamyab ho to naya active session token (rotation), warna None. N galat tries par pending session khatam."""
    if check_second_factor(db, user, code):
        pending.revoked_at = utcnow()
        token = create_session(db, user, ip, ua)
        audit(db, "login_success_2fa", user.id, ip)
        db.commit()
        return token
    pending.mfa_attempts += 1
    if pending.mfa_attempts >= get_settings().mfa_max_attempts:
        pending.revoked_at = utcnow()
    audit(db, "2fa_failed", user.id, ip)
    db.commit()
    return None


def begin_totp_setup(db: DbSession, user: User) -> tuple[str, str]:
    """(base32 secret, QR data-URI). Secret encrypted store hota hai, abhi enabled nahi."""
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = False
    uri = pyotp.TOTP(secret, interval=TOTP_INTERVAL).provisioning_uri(name=user.email, issuer_name="AliGuard")
    buf = io.BytesIO()
    qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(buf)
    data_uri = "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
    db.commit()
    return secret, data_uri


def generate_recovery_codes(db: DbSession, user: User, count: int = 10) -> list[str]:
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
    codes = []
    for _ in range(count):
        c = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        c = f"{c[:5]}-{c[5:]}"
        codes.append(c)
        db.add(RecoveryCode(user_id=user.id, code_hash=sha256_hex(c)))
    return codes


def enable_totp(db: DbSession, user: User, code: str, ip: str) -> list[str] | None:
    if not user.totp_secret_encrypted or user.totp_enabled or not _TOTP_RE.fullmatch(code.strip()):
        return None
    step = _totp_match(user, code.strip())
    if step is None:
        return None
    user.totp_enabled = True
    user.totp_last_step = step
    codes = generate_recovery_codes(db, user)
    audit(db, "2fa_enabled", user.id, ip)
    db.commit()
    return codes


def disable_totp(db: DbSession, user: User, password: str, code: str, ip: str) -> bool:
    if not verify_password(user.password_hash, password) or not check_second_factor(db, user, code):
        db.rollback()
        return False
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_last_step = 0
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
    audit(db, "2fa_disabled", user.id, ip)
    db.commit()
    return True


# ---------- password change / reset ----------
def set_password(db: DbSession, user: User, new_password: str) -> None:
    user.password_hash = hash_password(new_password)
    user.failed_login_count = 0
    user.locked_until = None
