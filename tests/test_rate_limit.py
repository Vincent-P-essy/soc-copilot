"""Tests for the token-bucket rate limiter."""

from __future__ import annotations

import time

from backend.rate_limit import RateLimiter


def test_allows_up_to_capacity_then_blocks():
    rl = RateLimiter(rate_per_minute=3)
    assert rl.allow("u") is True
    assert rl.allow("u") is True
    assert rl.allow("u") is True
    assert rl.allow("u") is False  # bucket empty


def test_buckets_are_per_key():
    rl = RateLimiter(rate_per_minute=1)
    assert rl.allow("a") is True
    assert rl.allow("b") is True  # separate bucket
    assert rl.allow("a") is False


def test_bucket_refills_over_time():
    rl = RateLimiter(rate_per_minute=60)  # 1 token/sec
    assert rl.allow("u") is True
    for _ in range(59):
        rl.allow("u")
    assert rl.allow("u") is False
    time.sleep(1.1)  # ~1 token refilled
    assert rl.allow("u") is True
