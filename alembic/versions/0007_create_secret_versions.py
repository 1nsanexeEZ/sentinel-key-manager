"""create secret versions table

Revision ID: 0007_create_secret_versions
Revises: 0006_encrypt_secrets
Create Date: 2026-07-08
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0007_create_secret_versions"
down_revision = "0006_encrypt_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secret_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("secret_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_dek", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["secret_id"], ["secrets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("secret_id", "version", name="uq_secret_version"),
    )
    op.create_index(
        op.f("ix_secret_versions_secret_id"),
        "secret_versions",
        ["secret_id"],
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_secret_versions_secret_id"),
        table_name="secret_versions",
    )
    op.drop_table("secret_versions")
