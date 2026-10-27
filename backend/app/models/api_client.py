"""
api_client.py

ApiClient: one row per program allowed to call the API with its own key
(the Gmail extension, a script, an SME's own system). The dashboard does
not use these; it gets a session cookie instead (app/core/security.py).

Only the SHA-256 hash of a key is stored. The keys are 256-bit random
values, so a fast hash is enough (a slow password hash such as bcrypt is
for low-entropy, human-chosen secrets). key_prefix is the first characters
of the key, kept so a person can tell keys apart in `manage_api_keys.py list`
without the database ever holding a usable key.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ApiClient(Base):
    __tablename__ = "api_clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    def __repr__(self) -> str:
        return f"<ApiClient id={self.id} name={self.name} prefix={self.key_prefix} active={self.is_active}>"
