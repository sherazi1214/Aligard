"""subscriptions + payment_events (plans / payments)

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

_DT = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "subscriptions",
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("plan", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("provider_customer_id", sa.String(64), nullable=True),
        sa.Column("provider_subscription_id", sa.String(64), nullable=True),
        sa.Column("current_period_end", _DT, nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_event_ts", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", _DT, nullable=False),
        sa.Column("updated_at", _DT, nullable=False),
    )
    op.create_index("ix_subscriptions_provider_subscription_id", "subscriptions", ["provider_subscription_id"])
    op.create_table(
        "payment_events",
        sa.Column("event_id", sa.String(96), primary_key=True),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("created_at", _DT, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("payment_events")
    op.drop_index("ix_subscriptions_provider_subscription_id", table_name="subscriptions")
    op.drop_table("subscriptions")
