"""correlate_events — find incidents that share indicators with a seed IOC.

Stands in for a threat-correlation engine: given one indicator, it walks the
incident store, collects incidents that reference it, and surfaces the *other*
indicators those incidents contain — revealing infrastructure reuse and
campaign linkage (e.g. the same /24 doing both scanning and SQLi).
"""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset


def _all_iocs(incident: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for group in incident.get("iocs", {}).values():
        out.update(str(v) for v in group)
    return out


class CorrelateEventsTool(Tool):
    name = "correlate_events"
    description = (
        "Correlate a seed indicator across the incident store to reveal linked "
        "infrastructure and likely campaigns. Returns the incidents that share "
        "the indicator and the additional indicators (IPs, domains, hashes, "
        "users, techniques) connected to it."
    )
    params = [ToolParam("ioc", "string", "Seed indicator to pivot on.", required=True)]

    def run(self, ioc: str = "", **_: Any) -> ToolResult:
        seed = (ioc or "").strip()
        if not seed:
            return ToolResult(ok=False, summary="No seed indicator provided.")
        seed_l = seed.lower()
        incidents = load_dataset("incidents")["incidents"]

        linked = [
            inc
            for inc in incidents
            if any(seed_l in v.lower() or v.lower() in seed_l for v in _all_iocs(inc))
        ]
        if not linked:
            return ToolResult(
                ok=True,
                summary=f"No correlated incidents for '{seed}'.",
                data={"seed": seed, "incidents": [], "related_iocs": [], "techniques": []},
                sources=["correlate:none"],
            )

        related: set[str] = set()
        techniques: set[str] = set()
        for inc in linked:
            related.update(_all_iocs(inc))
            techniques.add(inc["technique"])
        related.discard(seed)

        summary = (
            f"'{seed}' correlates across {len(linked)} incident(s) "
            f"({', '.join(i['id'] for i in linked)}); "
            f"linked indicators: {', '.join(sorted(related)) or 'none'}; "
            f"techniques: {', '.join(sorted(techniques))}."
        )
        return ToolResult(
            ok=True,
            summary=summary,
            data={
                "seed": seed,
                "incidents": linked,
                "related_iocs": sorted(related),
                "techniques": sorted(techniques),
            },
            sources=[f"incident:{i['id']}" for i in linked],
        )
