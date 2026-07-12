"""Tests for auth, JWT and RBAC."""

from __future__ import annotations

import pytest

from backend.auth import (
    AuthError,
    User,
    authenticate,
    issue_token,
    require_role,
    verify_token,
)


def test_authenticate_success():
    user = authenticate("admin", "admin")
    assert user.username == "admin" and user.role == "admin"


def test_authenticate_wrong_password():
    with pytest.raises(AuthError):
        authenticate("analyst", "wrong")


def test_authenticate_unknown_user():
    with pytest.raises(AuthError):
        authenticate("ghost", "x")


def test_token_round_trip():
    user = User("analyst", "analyst")
    token = issue_token(user)
    decoded = verify_token(token)
    assert decoded.username == "analyst" and decoded.role == "analyst"


def test_verify_rejects_tampered_token():
    token = issue_token(User("analyst", "analyst"))
    with pytest.raises(AuthError):
        verify_token(token + "tampered")


def test_require_role_hierarchy():
    admin = User("admin", "admin")
    analyst = User("analyst", "analyst")
    require_role(admin, "analyst")  # admin >= analyst: ok
    require_role(admin, "admin")  # ok
    require_role(analyst, "analyst")  # ok
    with pytest.raises(AuthError):
        require_role(analyst, "admin")
