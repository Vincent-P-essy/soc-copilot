"""search_incidents — find historical incidents by IOC or free text."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset


def _iocs_flat(incident: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for group in incident.get("iocs", {}).values():
        values.extend(str(v).lower() for v in group)
    return values


class SearchIncidentsTool(Tool):
    name = "search_incidents"
    description = (
        "Search the incident store for prior incidents matching an IOC "
        "(IP, hash, domain or user) or free-text query, optionally within the "
        "last N days. Use it to check whether an indicator has been seen before."
    )
    params = [
        ToolParam("ioc", "string", "Indicator to match: IP, file hash, domain or username."),
        ToolParam("query", "string", "Free-text search over incident titles and summaries."),
        ToolParam("days", "integer", "Only return incidents created within the last N days."),
    ]

    def run(self, ioc: str = "", query: str = "", days: int | None = None, **_: Any) -> ToolResult:
        incidents = load_dataset("incidents")["incidents"]
        ioc_l = (ioc or "").strip().lower()
        query_l = (query or "").strip().lower()
        cutoff = None
        if days:
            cutoff = datetime.now(UTC) - timedelta(days=int(days))

        matches: list[dict[str, Any]] = []
        for inc in incidents:
            if cutoff is not None:
                created = datetime.fromisoformat(inc["created"].replace("Z", "+00:00"))
                if created < cutoff:
                    continue
            hay_iocs = _iocs_flat(inc)
            text = f"{inc['title']} {inc['summary']}".lower()
            # If an IOC was given, require it in the incident's indicators or text.
            ioc_missing = ioc_l and not any(ioc_l in v or v in ioc_l for v in hay_iocs)
            if ioc_missing and ioc_l not in text:
                continue
            if query_l and query_l not in text:
                continue
            if not ioc_l and not query_l:
                continue
            matches.append(inc)

        if not matches:
            crit = ioc or query or "(no criteria)"
            return ToolResult(
                ok=True,
                summary=f"No prior incidents matched '{crit}'.",
                data={"count": 0, "incidents": []},
                sources=["incidents:none"],
            )

        matches.sort(key=lambda i: i["created"], reverse=True)
        lines = [f"{m['id']} ({m['severity']}, {m['status']}): {m['title']}" for m in matches]
        return ToolResult(
            ok=True,
            summary=f"Found {len(matches)} related incident(s): " + "; ".join(lines),
            data={"count": len(matches), "incidents": matches},
            sources=[f"incident:{m['id']}" for m in matches],
        )
