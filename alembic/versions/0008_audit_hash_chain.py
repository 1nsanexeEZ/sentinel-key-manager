"""add hash chain columns to audit log

Revision ID: 0008_audit_hash_chain
Revises: 0007_create_secret_versions
Create Date: 2026-07-09
"""

import sqlalchemy as sa

from alembic import op

revision = "0008_audit_hash_chain"
down_revision = "0007_create_secret_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_log",
        sa.Column("prev_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "audit_log",
        sa.Column(
            "record_hash", sa.String(length=64), nullable=False, server_default=""
        ),
    )


def downgrade() -> None:
    op.drop_column("audit_log", "record_hash")
    op.drop_column("audit_log", "prev_hash")
