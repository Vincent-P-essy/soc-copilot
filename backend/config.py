"""Environment-driven configuration.

Every knob is read from the process environment so the same image runs
unchanged across dev, CI and production. Sensible, safe defaults let the app
boot with zero configuration (no LLM key, no Redis) for local use and tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    secret_key: str = os.getenv("SECRET_KEY", "dev-insecure-change-me")
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    model: str = os.getenv("SOC_COPILOT_MODEL", "claude-opus-4-8")
    redis_url: str | None = os.getenv("REDIS_URL") or None
    session_ttl_seconds: int = int(os.getenv("SESSION_TTL_SECONDS", "86400"))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    max_agent_steps: int = int(os.getenv("MAX_AGENT_STEPS", "6"))
    port: int = int(os.getenv("PORT", "8000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def llm_enabled(self) -> bool:
        """True when a real LLM planner can be used."""
        return self.anthropic_api_key is not None


config = Config()
