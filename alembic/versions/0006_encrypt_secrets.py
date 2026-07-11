"""replace plaintext secret value with envelope-encrypted columns

Revision ID: 0006_encrypt_secrets
Revises: 0005_create_encryption_keys
Create Date: 2026-07-07
"""

import sqlalchemy as sa

from alembic import op

revision = "0006_encrypt_secrets"
down_revision = "0005_create_encryption_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("secrets", "value")
    op.add_column("secrets", sa.Column("ciphertext", sa.LargeBinary(), nullable=False))
    op.add_column(
        "secrets", sa.Column("encrypted_dek", sa.LargeBinary(), nullable=False)
    )
    op.add_column("secrets", sa.Column("key_version", sa.Integer(), nullable=False))


def downgrade() -> None:
    op.drop_column("secrets", "key_version")
    op.drop_column("secrets", "encrypted_dek")
    op.drop_column("secrets", "ciphertext")
    op.add_column("secrets", sa.Column("value", sa.Text(), nullable=False))
