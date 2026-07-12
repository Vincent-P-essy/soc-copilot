"""Tool registry.

Exposes the six SOC tools as a name->instance mapping plus helpers the agent
core and the LLM planner use to discover and dispatch tools.
"""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolParam, ToolResult
from .correlate_events import CorrelateEventsTool
from .geoip_enrich import GeoIPEnrichTool
from .lookup_cve import LookupCVETool
from .mitre_lookup import MitreLookupTool
from .search_incidents import SearchIncidentsTool
from .suggest_playbook import SuggestPlaybookTool

_TOOLS: list[Tool] = [
    SearchIncidentsTool(),
    LookupCVETool(),
    CorrelateEventsTool(),
    MitreLookupTool(),
    GeoIPEnrichTool(),
    SuggestPlaybookTool(),
]

REGISTRY: dict[str, Tool] = {t.name: t for t in _TOOLS}


def get_tool(name: str) -> Tool | None:
    return REGISTRY.get(name)


def all_schemas() -> list[dict[str, Any]]:
    """Anthropic-shaped tool schemas for the LLM planner."""
    return [t.schema() for t in _TOOLS]


def dispatch(name: str, args: dict[str, Any]) -> ToolResult:
    """Validate and execute a tool by name."""
    tool = get_tool(name)
    if tool is None:
        return ToolResult(ok=False, summary=f"Unknown tool '{name}'.")
    err = tool.validate(args)
    if err:
        return ToolResult(ok=False, summary=f"Invalid call to {name}: {err}.")
    return tool.run(**args)


__all__ = [
    "REGISTRY",
    "Tool",
    "ToolParam",
    "ToolResult",
    "all_schemas",
    "dispatch",
    "get_tool",
]
