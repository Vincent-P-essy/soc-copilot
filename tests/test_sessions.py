"""Tests for the in-memory session store."""

from __future__ import annotations

import time

from backend.sessions import _InMemoryStore


def test_append_and_history_ordering():
    s = _InMemoryStore(ttl=100)
    s.append("k", {"role": "user", "content": "hi"})
    s.append("k", {"role": "assistant", "content": "hello"})
    hist = s.get("k")
    assert [t["role"] for t in hist] == ["user", "assistant"]


def test_history_is_isolated_per_key():
    s = _InMemoryStore(ttl=100)
    s.append("a", {"role": "user", "content": "x"})
    assert s.get("b") == []


def test_clear_removes_history():
    s = _InMemoryStore(ttl=100)
    s.append("k", {"role": "user", "content": "x"})
    s.clear("k")
    assert s.get("k") == []


def test_ttl_expiry():
    s = _InMemoryStore(ttl=1)
    s.append("k", {"role": "user", "content": "x"})
    assert s.get("k")
    time.sleep(1.1)
    assert s.get("k") == []


def test_history_is_bounded():
    s = _InMemoryStore(ttl=100)
    for i in range(100):
        s.append("k", {"role": "user", "content": str(i)})
    assert len(s.get("k")) <= 40
