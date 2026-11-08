"""gmail_accounts, scans, whitelist, alerts_settings (Phase 3A)

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_DT = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "gmail_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("google_email", sa.String(254), nullable=False),
        sa.Column("refresh_token_encrypted", sa.Text(), nullable=True),
        sa.Column("access_token_encrypted", sa.Text(), nullable=True),
        sa.Column("access_expires_at", _DT, nullable=True),
        sa.Column("scopes", sa.String(500), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("history_id", sa.String(32), nullable=True),
        sa.Column("last_run_at", _DT, nullable=True),
        sa.Column("last_error", sa.String(64), nullable=True),
        sa.Column("created_at", _DT, nullable=False),
        sa.UniqueConstraint("user_id", "google_email", name="uq_gmail_user_email"),
    )
    op.create_index("ix_gmail_accounts_user_id", "gmail_accounts", ["user_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "gmail_account_id", sa.Uuid(), sa.ForeignKey("gmail_accounts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("gmail_message_id", sa.String(64), nullable=False),
        sa.Column("sender", sa.String(320), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("verdict", sa.String(12), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("layer_scores", sa.JSON(), nullable=False),
        sa.Column("urls", sa.JSON(), nullable=False),
        sa.Column("action_taken", sa.String(16), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("created_at", _DT, nullable=False),
        sa.UniqueConstraint("gmail_account_id", "gmail_message_id", name="uq_scan_account_message"),
    )
    op.create_index("ix_scans_user_created", "scans", ["user_id", "created_at"])
    op.create_index("ix_scans_user_verdict", "scans", ["user_id", "verdict"])

    op.create_table(
        "whitelist",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("value", sa.String(254), nullable=False),
        sa.Column("created_at", _DT, nullable=False),
        sa.UniqueConstraint("user_id", "kind", "value", name="uq_whitelist_entry"),
    )
    op.create_index("ix_whitelist_user_id", "whitelist", ["user_id"])

    op.create_table(
        "alerts_settings",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("alerts_enabled", sa.Boolean(), nullable=False),
        sa.Column("email_alerts", sa.Boolean(), nullable=False),
        sa.Column("telegram_alerts", sa.Boolean(), nullable=False),
        sa.Column("telegram_chat_id", sa.String(32), nullable=True),
        sa.Column("suspicious_threshold", sa.Integer(), nullable=False),
        sa.Column("phishing_threshold", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alerts_settings")
    op.drop_table("whitelist")
    op.drop_table("scans")
    op.drop_table("gmail_accounts")
