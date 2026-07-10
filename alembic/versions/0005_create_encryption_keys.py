"""create encryption keys table

Revision ID: 0005_create_encryption_keys
Revises: 0004_create_audit_log
Create Date: 2026-07-06
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0005_create_encryption_keys"
down_revision = "0004_create_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "encryption_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("encrypted_kek", sa.LargeBinary(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_encryption_keys_version"),
        "encryption_keys",
        ["version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_encryption_keys_version"),
        table_name="encryption_keys",
    )
    op.drop_table("encryption_keys")
