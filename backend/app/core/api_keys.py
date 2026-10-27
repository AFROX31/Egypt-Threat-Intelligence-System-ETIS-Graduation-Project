"""
api_keys.py

Per-client API keys for programs that call the API directly (the Gmail
extension, scripts, an SME's own systems). Each client has its own key, so
one leaked key can be revoked without touching anyone else, and its use is
visible (last_used_at). Keys are shown once, when created, and only their
SHA-256 hash is stored (see app/models/api_client.py).

Managed from the command line with backend/manage_api_keys.py.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.api_client import ApiClient

KEY_PREFIX = "etis_"
# Shown in listings so keys can be told apart: "etis_" plus 6 random characters.
DISPLAY_PREFIX_CHARS = len(KEY_PREFIX) + 6
# last_used_at is a hint for spotting unused keys, not an audit log, so it is
# written at most this often instead of on every request.
LAST_USED_RESOLUTION = timedelta(minutes=5)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """'etis_' + 43 URL-safe characters (256 random bits)."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def create_api_client(db: Session, name: str) -> tuple[ApiClient, str]:
    """Create a client and return it with its key. The key is not stored
    anywhere, so this is the only time it can be shown."""
    name = name.strip()
    if not name:
        raise ValueError("A client name is required.")
    if db.scalar(select(ApiClient).where(ApiClient.name == name)) is not None:
        raise ValueError(f"A client named {name!r} already exists.")
    key = generate_api_key()
    client = ApiClient(name=name, key_prefix=key[:DISPLAY_PREFIX_CHARS], key_hash=hash_api_key(key))
    db.add(client)
    db.commit()
    db.refresh(client)
    return client, key


def revoke_api_client(db: Session, name: str) -> ApiClient:
    client = db.scalar(select(ApiClient).where(ApiClient.name == name))
    if client is None:
        raise ValueError(f"No client named {name!r}.")
    if client.revoked_at is None:
        client.revoked_at = _utcnow()
        db.commit()
    return client


def list_api_clients(db: Session) -> list[ApiClient]:
    return list(db.scalars(select(ApiClient).order_by(ApiClient.created_at, ApiClient.id)))


def find_active_client(db: Session, key: str) -> ApiClient | None:
    """The active client this key belongs to, or None. Looked up by hash, so
    the comparison never handles the stored secret itself."""
    if not key.startswith(KEY_PREFIX):
        return None
    client = db.scalar(select(ApiClient).where(ApiClient.key_hash == hash_api_key(key)))
    if client is None or client.revoked_at is not None:
        return None
    now = _utcnow()
    if client.last_used_at is None or now - client.last_used_at >= LAST_USED_RESOLUTION:
        client.last_used_at = now
        try:
            db.commit()
        except Exception:  # a failed bookkeeping write must not refuse a valid key
            db.rollback()
    return client
