"""suggest_playbook — recommend an IR playbook for a technique or situation."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolParam, ToolResult, load_dataset, phrase_in


class SuggestPlaybookTool(Tool):
    name = "suggest_playbook"
    description = (
        "Recommend an incident-response playbook. Match by ATT&CK technique id "
        "(e.g. T1110.001) or by free-text situation ('brute force', 'phishing', "
        "'ransomware'). Returns the best-matching playbook with ordered analyst "
        "steps."
    )
    params = [
        ToolParam("technique_id", "string", "ATT&CK technique id to map to a playbook."),
        ToolParam("query", "string", "Free-text description of the situation."),
    ]

    def run(self, technique_id: str = "", query: str = "", **_: Any) -> ToolResult:
        playbooks = load_dataset("playbooks")["playbooks"]
        tid = (technique_id or "").strip().upper()
        q = (query or "").strip().lower()

        best: dict[str, Any] | None = None
        best_score = 0
        for pb in playbooks:
            score = 0
            if tid and tid in [t.upper() for t in pb["techniques"]]:
                score += 5
            if q:
                score += sum(1 for kw in pb["keywords"] if phrase_in(kw, q) or phrase_in(q, kw))
                if phrase_in(q, pb["name"]):
                    score += 2
            if score > best_score:
                best, best_score = pb, score

        if best is None:
            crit = technique_id or query or "(no criteria)"
            return ToolResult(
                ok=True,
                summary=f"No playbook matched '{crit}'.",
                data={"playbook": None},
                sources=["playbook:none"],
            )

        steps = "; ".join(f"{i}. {s}" for i, s in enumerate(best["steps"], 1))
        return ToolResult(
            ok=True,
            summary=f"Playbook {best['id']} — {best['name']}: {steps}",
            data={"playbook": best},
            sources=[f"playbook:{best['id']}"],
        )
