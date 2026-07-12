"""Tool abstraction shared by every SOC Copilot tool.

A tool is a small, typed, side-effect-free function over grounded data. Each
one declares a JSON-schema-style parameter spec (consumed both by the LLM
planner and by input validation) and returns a :class:`ToolResult` that always
carries the citations backing its output.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def phrase_in(phrase: str, text: str) -> bool:
    """Whole-word/phrase containment.

    Avoids the substring false positives that plague naive ``in`` matching
    (e.g. the keyword ``rce`` matching inside ``force``). ``phrase`` matches
    when it appears in ``text`` bounded by non-alphanumeric characters.
    """
    phrase = phrase.strip().lower()
    if not phrase:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text.lower()) is not None


@lru_cache(maxsize=None)
def load_dataset(name: str) -> dict[str, Any]:
    """Load and cache a JSON dataset from ``backend/data``."""
    with (DATA_DIR / f"{name}.json").open(encoding="utf-8") as fh:
        return json.load(fh)


@dataclass
class ToolResult:
    """Structured tool output.

    ``ok`` signals success; ``data`` is the machine-readable payload;
    ``summary`` is a one-line human string the synthesizer can quote; and
    ``sources`` records exactly which records/systems backed the answer so the
    final response can cite them.
    """

    ok: bool
    summary: str
    data: Any = None
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolParam:
    name: str
    type: str
    description: str
    required: bool = False


class Tool:
    """Base class for a callable, self-describing tool."""

    name: str = "tool"
    description: str = ""
    params: list[ToolParam] = []

    def run(self, **kwargs: Any) -> ToolResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- introspection -----------------------------------------------------
    def schema(self) -> dict[str, Any]:
        """Anthropic tool-schema-shaped description of this tool."""
        properties = {
            p.name: {"type": p.type, "description": p.description} for p in self.params
        }
        required = [p.name for p in self.params if p.required]
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def validate(self, args: dict[str, Any]) -> str | None:
        """Return an error string if required args are missing, else None."""
        for p in self.params:
            if p.required and not args.get(p.name):
                return f"missing required argument '{p.name}'"
        return None
