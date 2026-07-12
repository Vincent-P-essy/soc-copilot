"""Prometheus metrics.

Exposes request volume, per-tool usage, agent latency and active-session count
on ``/metrics`` for scraping. Kept in one module so collectors are singletons.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REQUESTS = Counter(
    "soc_requests_total",
    "Total chat requests handled by the agent.",
    ["planner", "status"],
)

TOOL_CALLS = Counter(
    "soc_tool_calls_total",
    "Number of times each tool was invoked.",
    ["tool"],
)

LATENCY = Histogram(
    "soc_agent_latency_seconds",
    "End-to-end agent latency per request.",
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)

ACTIVE_SESSIONS = Gauge(
    "soc_active_sessions",
    "Currently connected chat sessions.",
)


def render() -> tuple[bytes, str]:
    """Return the metrics payload and its content type."""
    return generate_latest(), CONTENT_TYPE_LATEST
