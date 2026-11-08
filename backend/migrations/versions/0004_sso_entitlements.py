"""entitlements + sso_nonces (portal handoff, Phase 5)

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_DT = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "entitlements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("expires_at", _DT, nullable=False),
        sa.Column("created_at", _DT, nullable=False),
        sa.UniqueConstraint("user_id", "service", name="uq_entitlement_user_service"),
    )
    op.create_index("ix_entitlements_user_id", "entitlements", ["user_id"])

    op.create_table(
        "sso_nonces",
        sa.Column("nonce", sa.String(64), primary_key=True),
        sa.Column("created_at", _DT, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sso_nonces")
    op.drop_index("ix_entitlements_user_id", table_name="entitlements")
    op.drop_table("entitlements")
