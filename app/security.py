"""비밀번호 해시, 세션, API 키, 계정 잠금."""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from config import settings
from db import as_aware, utcnow

_ph = PasswordHasher()

SESSION_TTL = dt.timedelta(hours=12)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def session_expiry() -> dt.datetime:
    return utcnow() + SESSION_TTL


def hash_api_key(raw: str) -> str:
    """API 키는 복원 불필요하므로 SHA-256으로 저장."""
    return hashlib.sha256(raw.encode()).hexdigest()


def is_locked(locked_until: dt.datetime | None) -> bool:
    if locked_until is None:
        return False
    return as_aware(locked_until) > utcnow()


def lock_until() -> dt.datetime:
    return utcnow() + dt.timedelta(minutes=settings.LOCKOUT_MINUTES)
