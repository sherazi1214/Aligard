"""Phase 2: users, email_tokens, sessions, recovery_codes, audit_log.
Phase 3A: gmail_accounts, scans, whitelist, alerts_settings.
Phase 3B: gmail_accounts/scans mein worker ke columns, feedback."""
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from backend.app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Hamesha timezone-aware UTC. SQLite naive datetime lota deta hai, usay yahan theek karte hain."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)  # hamesha lowercase
    password_hash: Mapped[str] = mapped_column(String(255))
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)  # TOTP replay rokne ke liye
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class EmailToken(Base):
    __tablename__ = "email_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sirf SHA-256 hash
    purpose: Mapped[str] = mapped_column(String(16))  # verify | reset
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    session_hash: Mapped[str] = mapped_column(String(64), unique=True)
    stage: Mapped[str] = mapped_column(String(16), default="active")  # active | mfa_pending
    mfa_attempts: Mapped[int] = mapped_column(Integer, default=0)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_user_created", "user_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event: Mapped[str] = mapped_column(String(48))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class GmailAccount(Base):
    """Connected Gmail. Tokens Fernet se encrypted; disconnect par tokens NULL ho jate hain."""

    __tablename__ = "gmail_accounts"
    __table_args__ = (UniqueConstraint("user_id", "google_email", name="uq_gmail_user_email"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    google_email: Mapped[str] = mapped_column(String(254))  # hamesha lowercase
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    scopes: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | disconnected | needs_reauth
    history_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # Gmail history ka bookmark
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)  # worker heartbeat (kamyab run)
    last_error: Mapped[str | None] = mapped_column(String(64), nullable=True)  # sirf short code, tafseel nahi
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)  # exponential backoff ke liye
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)  # is se pehle worker nahi chalega
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Scan(Base):
    """Ek email ka nateeja. Email body kabhi store nahi hoti. Sender/subject attacker-controlled hain."""

    __tablename__ = "scans"
    __table_args__ = (
        # Gmail message id mailbox ke andar unique hota hai, isliye (account, message) par dedupe
        UniqueConstraint("gmail_account_id", "gmail_message_id", name="uq_scan_account_message"),
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_user_verdict", "user_id", "verdict"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    gmail_account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("gmail_accounts.id", ondelete="CASCADE"))
    gmail_message_id: Mapped[str] = mapped_column(String(64))
    sender: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(String(500), default="")
    verdict: Mapped[str] = mapped_column(String(12))  # SAFE | SUSPICIOUS | PHISHING
    score: Mapped[int] = mapped_column(Integer, default=0)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    layer_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    urls: Mapped[list] = mapped_column(JSON, default=list)  # sirf DEFANGED (hxxps://evil[.]com)
    # none | pending (action tay hua par Gmail par lagna baqi) | labeled | quarantined | restored | failed
    action_taken: Mapped[str] = mapped_column(String(16), default="none")
    planned_action: Mapped[str] = mapped_column(String(12), default="none")  # none | label | quarantine
    # none | pending | sending | sent | skipped | failed. "sending" crash ke baad bhi dobara nahi bheja jata
    alert_state: Mapped[str] = mapped_column(String(12), default="none")
    alert_attempts: Mapped[int] = mapped_column(Integer, default=0)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Defanged postmortem (sandbox/attachments/domains/QR). Raw URL, page text, screenshot kabhi store nahi.
    postmortem: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Whitelist(Base):
    __tablename__ = "whitelist"
    __table_args__ = (UniqueConstraint("user_id", "kind", "value", name="uq_whitelist_entry"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # sender | domain
    value: Mapped[str] = mapped_column(String(254))  # lowercase
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AlertSettings(Base):
    """Har user ki ek row (settings page se badalti hai). Row na ho to defaults maane jate hain."""

    __tablename__ = "alerts_settings"
    # Ek Telegram chat sirf ek account se jur sakti hai (NULL kai ho sakte hain)
    __table_args__ = (Index("ux_alerts_telegram_chat", "telegram_chat_id", unique=True),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    email_alerts: Mapped[bool] = mapped_column(Boolean, default=True)
    telegram_alerts: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    suspicious_threshold: Mapped[int] = mapped_column(Integer, default=35)
    phishing_threshold: Mapped[int] = mapped_column(Integer, default=70)


class Entitlement(Base):
    """Portal (aliguard-portal) se khareeda gaya plan. SSO handoff route (/api/auth/sso) ye banata hai."""

    __tablename__ = "entitlements"
    __table_args__ = (UniqueConstraint("user_id", "service", name="uq_entitlement_user_service"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    service: Mapped[str] = mapped_column(String(32))  # gmail | whatsapp | website (portal ki SERVICES list se)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SsoNonce(Base):
    """Portal se aaye signed handoff token ka nonce. Ek bar consume hote hi row ban jati hai,
    dobara wahi nonce aaye to UNIQUE constraint par fail hoga (replay rok di jati hai)."""

    __tablename__ = "sso_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Feedback(Base):
    """User ka 'Not phishing / Restore' feedback. Email body kabhi nahi, sirf nateeje ka summary."""

    __tablename__ = "feedback"
    __table_args__ = (UniqueConstraint("scan_id", "kind", name="uq_feedback_scan_kind"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))  # not_phishing
    verdict: Mapped[str] = mapped_column(String(12))  # us waqt engine ka verdict
    score: Mapped[int] = mapped_column(Integer, default=0)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sender_domain: Mapped[str] = mapped_column(String(254), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Subscription(Base):
    """Har user ka ek plan (free | pro | business). Paid plan SIRF verified provider webhook (ya server-side
    Stripe lookup) se active hota hai, kabhi browser ke kehne par nahi. Card data yahan kabhi nahi aata."""

    __tablename__ = "subscriptions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    plan: Mapped[str] = mapped_column(String(16))  # free | pro | business
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | past_due | canceled | incomplete
    provider: Mapped[str] = mapped_column(String(16), default="none")  # none | stripe | mock
    provider_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    current_period_end: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    last_event_ts: Mapped[int] = mapped_column(BigInteger, default=0)  # out-of-order purane webhook ignore
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class PaymentEvent(Base):
    """Processed webhook event ids (idempotency: Stripe ek event kai bar bhej sakta hai)."""

    __tablename__ = "payment_events"

    event_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    type: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
