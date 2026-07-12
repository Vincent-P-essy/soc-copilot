"""ReAct agent core.

Owns one triage run: it drives the configured planner, collects the visible
reasoning steps, times the run and returns a structured response. The web layer
streams each step to the UI as it is emitted.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .llm import AgentStep, build_planner

StepCallback = Callable[[AgentStep], None]


@dataclass
class AgentResponse:
    answer: str
    steps: list[AgentStep] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    latency_ms: int = 0
    planner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "steps": [s.to_dict() for s in self.steps],
            "sources": self.sources,
            "tools_used": self.tools_used,
            "latency_ms": self.latency_ms,
            "planner": self.planner,
        }


class Agent:
    """Thin orchestration layer over a planner."""

    def __init__(self) -> None:
        self._planner = build_planner()

    @property
    def planner_name(self) -> str:
        return self._planner.name

    def handle(
        self,
        user_message: str,
        history: list[dict[str, str]] | None = None,
        on_step: StepCallback | None = None,
    ) -> AgentResponse:
        history = history or []
        steps: list[AgentStep] = []

        def emit(step: AgentStep) -> None:
            # Skip no-op steps (used internally to keep the planner loop simple).
            if not step.action and not step.observation and not step.thought:
                return
            steps.append(step)
            if on_step is not None:
                on_step(step)

        start = time.perf_counter()
        answer = self._planner.run(user_message, history, emit)
        latency_ms = int((time.perf_counter() - start) * 1000)

        sources: list[str] = []
        tools_used: list[str] = []
        for s in steps:
            sources.extend(s.sources)
            if s.action:
                tools_used.append(s.action)

        return AgentResponse(
            answer=answer,
            steps=steps,
            sources=list(dict.fromkeys(sources)),
            tools_used=list(dict.fromkeys(tools_used)),
            latency_ms=latency_ms,
            planner=self._planner.name,
        )
