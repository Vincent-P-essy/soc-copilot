"""mitre_lookup — map behaviour to MITRE ATT&CK techniques."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset, phrase_in


class MitreLookupTool(Tool):
    name = "mitre_lookup"
    description = (
        "Map an observed behaviour to MITRE ATT&CK. Accepts a technique id "
        "(e.g. T1110.001) or a free-text description ('brute force', "
        "'port scan', 'c2 beacon') and returns the matching technique(s) with "
        "tactic, description and mitigations."
    )
    params = [
        ToolParam("technique_id", "string", "Exact ATT&CK technique id, e.g. T1190."),
        ToolParam("query", "string", "Free-text behaviour to map, e.g. 'brute force'."),
    ]

    def run(self, technique_id: str = "", query: str = "", **_: Any) -> ToolResult:
        techniques = load_dataset("mitre_attack")["techniques"]
        tid = (technique_id or "").strip().upper()
        q = (query or "").strip().lower()

        found: list[dict[str, Any]] = []
        if tid:
            found = [t for t in techniques if t["id"].upper() == tid]
        elif q:
            scored: list[tuple[int, dict[str, Any]]] = []
            for t in techniques:
                score = sum(1 for kw in t["keywords"] if phrase_in(kw, q) or phrase_in(q, kw))
                if phrase_in(q, t["name"]):
                    score += 2
                if score:
                    scored.append((score, t))
            scored.sort(key=lambda x: x[0], reverse=True)
            found = [t for _, t in scored[:3]]

        if not found:
            crit = technique_id or query or "(no criteria)"
            return ToolResult(
                ok=True,
                summary=f"No ATT&CK technique matched '{crit}'.",
                data={"count": 0, "techniques": []},
                sources=["mitre:none"],
            )

        lines = [f"{t['id']} {t['name']} ({t['tactic']})" for t in found]
        return ToolResult(
            ok=True,
            summary=f"Mapped to {len(found)} technique(s): " + "; ".join(lines),
            data={"count": len(found), "techniques": found},
            sources=[f"mitre:{t['id']}" for t in found],
        )
