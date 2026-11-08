"""worker columns (gmail_accounts, scans), feedback table, telegram chat unique index (Phase 3B)

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_DT = sa.DateTime(timezone=True)


def upgrade() -> None:
    # NOT NULL columns ke liye server_default: purani rows bhi bhar jayen (SQLite/Postgres dono par)
    op.add_column("gmail_accounts", sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("gmail_accounts", sa.Column("next_run_at", _DT, nullable=True))

    op.add_column("scans", sa.Column("planned_action", sa.String(12), nullable=False, server_default="none"))
    op.add_column("scans", sa.Column("alert_state", sa.String(12), nullable=False, server_default="none"))
    op.add_column("scans", sa.Column("alert_attempts", sa.Integer(), nullable=False, server_default="0"))

    op.create_index("ux_alerts_telegram_chat", "alerts_settings", ["telegram_chat_id"], unique=True)

    op.create_table(
        "feedback",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("verdict", sa.String(12), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("sender_domain", sa.String(254), nullable=False),
        sa.Column("created_at", _DT, nullable=False),
        sa.UniqueConstraint("scan_id", "kind", name="uq_feedback_scan_kind"),
    )
    op.create_index("ix_feedback_user_id", "feedback", ["user_id"])


def downgrade() -> None:
    op.drop_table("feedback")
    op.drop_index("ux_alerts_telegram_chat", table_name="alerts_settings")
    op.drop_column("scans", "alert_attempts")
    op.drop_column("scans", "alert_state")
    op.drop_column("scans", "planned_action")
    op.drop_column("gmail_accounts", "next_run_at")
    op.drop_column("gmail_accounts", "consecutive_failures")
