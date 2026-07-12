"""Authentication and role-based access control.

Local accounts with PBKDF2-hashed passwords and stateless JWT session tokens.
Two roles: ``analyst`` (chat) and ``admin`` (chat + metrics/administration).
The seeded accounts are for demo/dev only — wire in a real user store and SSO
for production (see the roadmap).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from .config import config

_PBKDF2_ROUNDS = 200_000


@dataclass(frozen=True)
class User:
    username: str
    role: str  # "analyst" | "admin"


def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return salt.hex() + "$" + dk.hex()


def _make_credential(password: str) -> str:
    return _hash_password(password, os.urandom(16))


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$", 1)
    except ValueError:
        return False
    candidate = _hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, stored)


# Seeded demo accounts. Passwords equal usernames; change before any real use.
_USERS: dict[str, dict[str, Any]] = {
    "analyst": {"role": "analyst", "credential": _make_credential("analyst")},
    "admin": {"role": "admin", "credential": _make_credential("admin")},
}


class AuthError(Exception):
    """Raised on failed authentication or authorization."""


def authenticate(username: str, password: str) -> User:
    record = _USERS.get(username)
    if record is None or not _verify_password(password, record["credential"]):
        raise AuthError("invalid username or password")
    return User(username=username, role=record["role"])


def issue_token(user: User, ttl_hours: int = 12) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ttl_hours)).timestamp()),
    }
    return jwt.encode(payload, config.secret_key, algorithm="HS256")


def verify_token(token: str) -> User:
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError as exc:  # expired, bad signature, malformed
        raise AuthError(f"invalid token: {exc}") from exc
    return User(username=payload["sub"], role=payload.get("role", "analyst"))


def require_role(user: User, role: str) -> None:
    """Raise AuthError unless the user has (at least) the given role."""
    hierarchy = {"analyst": 1, "admin": 2}
    if hierarchy.get(user.role, 0) < hierarchy.get(role, 99):
        raise AuthError(f"role '{role}' required")
