"""add user role and policies table

Revision ID: 0003_add_role_and_policies
Revises: 0002_create_secrets
Create Date: 2026-07-03
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0003_add_role_and_policies"
down_revision = "0002_create_secrets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "role",
            sa.String(length=32),
            server_default="reader",
            nullable=False,
        ),
    )
    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("path_glob", sa.String(length=255), nullable=False),
        sa.Column("can_read", sa.Boolean(), nullable=False),
        sa.Column("can_write", sa.Boolean(), nullable=False),
        sa.Column("can_delete", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_policies_role"), "policies", ["role"])


def downgrade() -> None:
    op.drop_index(op.f("ix_policies_role"), table_name="policies")
    op.drop_table("policies")
    op.drop_column("users", "role")
