"""create dynamic credentials table

Revision ID: 0009_create_dynamic_credentials
Revises: 0008_audit_hash_chain
Create Date: 2026-07-10
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0009_create_dynamic_credentials"
down_revision = "0008_audit_hash_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dynamic_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_dynamic_credentials_username"),
        "dynamic_credentials",
        ["username"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_dynamic_credentials_username"),
        table_name="dynamic_credentials",
    )
    op.drop_table("dynamic_credentials")
