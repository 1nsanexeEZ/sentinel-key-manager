import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.infrastructure.database import Base


class SecretVersion(Base):
    """An immutable historical snapshot of a secret's encrypted value."""

    __tablename__ = "secret_versions"
    __table_args__ = (
        UniqueConstraint("secret_id", "version", name="uq_secret_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    secret_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("secrets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
