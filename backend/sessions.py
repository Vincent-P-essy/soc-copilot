"""Conversation memory.

A session holds the recent turn history for one analyst conversation. Redis is
used when ``REDIS_URL`` is set (history survives restarts and expires after a
TTL); otherwise an in-process store is used so local dev and tests need no
external service. Both backends share the same interface.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from .config import config

_MAX_TURNS = 40  # keep memory bounded regardless of TTL


class _InMemoryStore:
    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._data: dict[str, tuple[float, list[dict[str, str]]]] = {}
        self._lock = threading.Lock()

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [k for k, (exp, _) in self._data.items() if exp < now]
        for k in expired:
            del self._data[k]

    def get(self, key: str) -> list[dict[str, str]]:
        with self._lock:
            self._evict_expired()
            entry = self._data.get(key)
            return list(entry[1]) if entry else []

    def append(self, key: str, turn: dict[str, str]) -> None:
        with self._lock:
            self._evict_expired()
            _, history = self._data.get(key, (0.0, []))
            history = [*history, turn][-_MAX_TURNS:]
            self._data[key] = (time.time() + self._ttl, history)

    def clear(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class _RedisStore:  # pragma: no cover - exercised only when Redis is available
    def __init__(self, url: str, ttl: int) -> None:
        import redis

        self._r = redis.Redis.from_url(url, decode_responses=True)
        self._ttl = ttl

    def _key(self, key: str) -> str:
        return f"soc:session:{key}"

    def get(self, key: str) -> list[dict[str, str]]:
        raw = self._r.get(self._key(key))
        return json.loads(raw) if raw else []

    def append(self, key: str, turn: dict[str, str]) -> None:
        history = self.get(key)
        history = [*history, turn][-_MAX_TURNS:]
        self._r.set(self._key(key), json.dumps(history), ex=self._ttl)

    def clear(self, key: str) -> None:
        self._r.delete(self._key(key))


class SessionStore:
    """Facade selecting a Redis or in-memory backend based on config."""

    def __init__(self) -> None:
        ttl = config.session_ttl_seconds
        backend: Any
        if config.redis_url:
            try:
                backend = _RedisStore(config.redis_url, ttl)
                backend.get("__healthcheck__")  # fail fast if Redis is unreachable
            except Exception:
                backend = _InMemoryStore(ttl)
        else:
            backend = _InMemoryStore(ttl)
        self._backend = backend

    @property
    def backend_name(self) -> str:
        return type(self._backend).__name__

    def history(self, session_id: str) -> list[dict[str, str]]:
        return self._backend.get(session_id)

    def record(self, session_id: str, role: str, content: str) -> None:
        self._backend.append(session_id, {"role": role, "content": content})

    def clear(self, session_id: str) -> None:
        self._backend.clear(session_id)


store = SessionStore()
