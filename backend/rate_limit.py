"""Per-user token-bucket rate limiting.

Thread-safe, in-process, and dependency-free. Each user gets a bucket that
refills at ``rate_per_minute`` tokens per 60 seconds and holds at most that many
tokens, allowing short bursts while bounding sustained request rate.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .config import config


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, rate_per_minute: int | None = None) -> None:
        self.rate = rate_per_minute or config.rate_limit_per_minute
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Consume one token for ``key``; return False if the bucket is empty."""
        now = time.monotonic()
        refill_per_sec = self.rate / 60.0
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(tokens=self.rate - 1, updated=now)
                return True
            elapsed = now - bucket.updated
            bucket.tokens = min(self.rate, bucket.tokens + elapsed * refill_per_sec)
            bucket.updated = now
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True
            return False


limiter = RateLimiter()
