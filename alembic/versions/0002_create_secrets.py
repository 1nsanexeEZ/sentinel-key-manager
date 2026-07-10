"""create secrets table

Revision ID: 0002_create_secrets
Revises: 0001_create_users
Create Date: 2026-07-01
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0002_create_secrets"
down_revision = "0001_create_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("path", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_secrets_path"), "secrets", ["path"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_secrets_path"), table_name="secrets")
    op.drop_table("secrets")
