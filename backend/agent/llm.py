"""LLM planner abstraction.

Two interchangeable planners drive the ReAct loop:

* :class:`AnthropicPlanner` uses Claude with native tool use. It is selected
  automatically when ``ANTHROPIC_API_KEY`` is set.
* :class:`DeterministicPlanner` is a rule-based planner that extracts indicators
  from the analyst's message, calls the relevant tools and synthesises a
  templated answer. It needs no API key, so the app, its tests and the demo all
  run offline.

Both share the same contract: ``run(user_message, history, emit)`` executes the
loop, calls ``emit`` for every :class:`AgentStep`, and returns the final answer
text. The set of steps is what the UI renders as visible reasoning.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import config
from .prompts import SYSTEM_PROMPT
from .tools import all_schemas, dispatch

EmitFn = Callable[["AgentStep"], None]

# --- indicator extraction --------------------------------------------------
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)

# behaviour keyword -> canonical query passed to mitre_lookup / suggest_playbook
_BEHAVIOURS = {
    "brute force": ["brute force", "brute-force", "bruteforce", "password guess", "failed login", "failed logon", "401"],
    "password spray": ["password spray", "spraying"],
    "port scan": ["port scan", "portscan", "nmap", "scanning", "sweep", "recon"],
    "sql injection": ["sql injection", "sqli", "sqlmap", "union select"],
    "path traversal": ["path traversal", "directory traversal", "../"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "phishing": ["phishing", "phish", "credential harvest", "spearphish"],
    "c2 beacon": ["beacon", "c2", "command and control", "callback", "cobalt strike"],
    "ransomware": ["ransomware", "encrypted files", "ransom note"],
    "exfiltration": ["exfiltration", "data exfil", "large upload"],
}
_SERVICE_HINTS = {
    "ssh": ["ssh", "sshd", "openssh", "port 22"],
    "http": ["http", "web", "apache", "nginx", "log4j", "iis", "port 80", "port 443"],
    "vpn": ["vpn", "globalprotect", "pan-os", "anyconnect"],
}


@dataclass
class AgentStep:
    """One visible step of the ReAct loop."""

    thought: str = ""
    action: str | None = None
    action_input: dict[str, Any] = field(default_factory=dict)
    observation: str | None = None
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation,
            "sources": self.sources,
        }


# --- deterministic planner -------------------------------------------------
class DeterministicPlanner:
    """Rule-based planner used when no LLM key is configured."""

    name = "deterministic"

    def _extract(self, text: str) -> dict[str, Any]:
        low = text.lower()
        # A domain regex also matches IPs; filter those out.
        ips = _IP_RE.findall(text)
        domains = [d for d in _DOMAIN_RE.findall(text) if not _IP_RE.fullmatch(d)]
        return {
            "ips": list(dict.fromkeys(ips)),
            "hashes": list(dict.fromkeys(_HASH_RE.findall(text))),
            "cves": list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(text))),
            "domains": list(dict.fromkeys(domains)),
            "behaviours": [name for name, kws in _BEHAVIOURS.items() if any(k in low for k in kws)],
            "services": [svc for svc, kws in _SERVICE_HINTS.items() if any(k in low for k in kws)],
        }

    def run(self, user_message: str, history: list[dict[str, str]], emit: EmitFn) -> str:
        found = self._extract(user_message)
        steps: list[AgentStep] = []

        def do(thought: str, tool: str, args: dict[str, Any]) -> AgentStep:
            result = dispatch(tool, args)
            step = AgentStep(
                thought=thought,
                action=tool,
                action_input=args,
                observation=result.summary,
                sources=result.sources,
            )
            emit(step)
            steps.append(step)
            return step

        # 1) Enrich and pivot on the primary IP.
        primary_ip = found["ips"][0] if found["ips"] else None
        if primary_ip:
            do(f"'{primary_ip}' is a network indicator; enrich it for geo and reputation.",
               "geoip_enrich", {"ip": primary_ip})
            do(f"Check whether {primary_ip} appears in prior incidents.",
               "search_incidents", {"ioc": primary_ip})
            do(f"Correlate {primary_ip} to reveal linked infrastructure and campaigns.",
               "correlate_events", {"ioc": primary_ip})

        # 2) Pivot on a file hash if present.
        for h in found["hashes"][:1]:
            do("A file hash is present; search incidents for prior sightings.",
               "search_incidents", {"ioc": h})

        # 3) Look up any explicit CVE.
        for cve in found["cves"][:1]:
            do(f"Resolve the referenced vulnerability {cve}.",
               "lookup_cve", {"cve_id": cve})

        # 4) Map behaviour to ATT&CK and choose a playbook.
        behaviour = found["behaviours"][0] if found["behaviours"] else None
        if behaviour:
            do(f"Map the observed '{behaviour}' behaviour to MITRE ATT&CK.",
               "mitre_lookup", {"query": behaviour})

        # 5) Assess exposure for hinted services.
        for svc in found["services"][:1]:
            do(f"Assess whether exposed {svc} has an exploitable vulnerability.",
               "lookup_cve", {"service": svc})

        # 6) Recommend a response playbook.
        if behaviour:
            do(f"Recommend an IR playbook for the '{behaviour}' scenario.",
               "suggest_playbook", {"query": behaviour})
        elif found["domains"]:
            do("A domain indicator suggests phishing; recommend the phishing playbook.",
               "suggest_playbook", {"query": "phishing"})

        if not steps:
            # No indicators or behaviours recognised — ask a grounded clarifier.
            answer = (
                "I couldn't extract a concrete indicator (IP, hash, domain, CVE) or a known "
                "attack pattern from that. Share the source/destination IPs, any file hashes "
                "or domains, and a one-line description of what you're seeing (e.g. 'repeated "
                "failed SSH logins'), and I'll enrich and correlate it."
            )
            emit(AgentStep(thought="No actionable indicator found.", observation=answer))
            return answer

        return synthesize(user_message, steps)


# --- Anthropic planner -----------------------------------------------------
class AnthropicPlanner:
    """LLM planner using Claude with native tool use."""

    name = "anthropic"

    def __init__(self) -> None:
        import anthropic  # imported lazily so the dependency is optional at runtime

        self._client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self._model = config.model

    def run(self, user_message: str, history: list[dict[str, str]], emit: EmitFn) -> str:
        messages: list[dict[str, Any]] = []
        for turn in history[-6:]:
            messages.append({"role": turn["role"], "content": turn["content"]})
        messages.append({"role": "user", "content": user_message})

        tools = all_schemas()
        collected_sources: list[str] = []
        final_text = ""

        for _ in range(config.max_agent_steps):
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=messages,
            )
            # Pull any leading text as the "thought" for this turn.
            thought = " ".join(
                b.text for b in resp.content if getattr(b, "type", None) == "text"
            ).strip()
            tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]

            if resp.stop_reason != "tool_use" or not tool_uses:
                final_text = thought or final_text
                if thought and not tool_uses:
                    emit(AgentStep(thought="", observation=None))  # no-op keeps types simple
                break

            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for tu in tool_uses:
                result = dispatch(tu.name, dict(tu.input))
                collected_sources.extend(result.sources)
                emit(
                    AgentStep(
                        thought=thought,
                        action=tu.name,
                        action_input=dict(tu.input),
                        observation=result.summary,
                        sources=result.sources,
                    )
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": result.summary,
                    }
                )
                thought = ""  # subsequent tools in the same turn share no preamble
            messages.append({"role": "user", "content": tool_results})

        if collected_sources and "Sources:" not in final_text:
            uniq = list(dict.fromkeys(collected_sources))
            final_text = f"{final_text}\n\nSources: {', '.join(uniq)}"
        return final_text.strip() or "I wasn't able to complete the analysis."


# --- shared deterministic synthesizer --------------------------------------
def synthesize(user_message: str, steps: list[AgentStep]) -> str:
    """Build a templated final answer from collected observations."""
    obs = {s.action: s for s in steps if s.action}
    all_sources: list[str] = []
    for s in steps:
        all_sources.extend(s.sources)
    uniq_sources = list(dict.fromkeys(all_sources))

    synthesis_bits: list[str] = []
    if "geoip_enrich" in obs:
        synthesis_bits.append(obs["geoip_enrich"].observation or "")
    if "search_incidents" in obs and "No prior" not in (obs["search_incidents"].observation or ""):
        synthesis_bits.append(obs["search_incidents"].observation or "")
    if "correlate_events" in obs and "No correlated" not in (obs["correlate_events"].observation or ""):
        synthesis_bits.append(obs["correlate_events"].observation or "")
    if "mitre_lookup" in obs:
        synthesis_bits.append(obs["mitre_lookup"].observation or "")
    if "lookup_cve" in obs and "No CVE" not in (obs["lookup_cve"].observation or ""):
        synthesis_bits.append(obs["lookup_cve"].observation or "")

    synthesis = " ".join(b for b in synthesis_bits if b) or "Gathered available context."

    # Recommendation comes from the playbook if we have one.
    recommendation_lines: list[str] = []
    playbook_ref = ""
    if "suggest_playbook" in obs and obs["suggest_playbook"].observation:
        pb_summary = obs["suggest_playbook"].observation
        # summary form: "Playbook IR-XYZ — Name: 1. step; 2. step; ..."
        head, _, body = pb_summary.partition(":")
        playbook_ref = head.replace("Playbook ", "").strip()
        for part in body.split(";"):
            part = part.strip()
            if part:
                recommendation_lines.append(part)

    lines = [f"Synthesis: {synthesis}", ""]
    if recommendation_lines:
        lines.append("Recommendation:")
        lines.extend(f"  {p}" for p in recommendation_lines)
        lines.append("")
    if playbook_ref:
        lines.append(f"Playbook: {playbook_ref}")
    lines.append(f"Sources: {', '.join(uniq_sources)}")
    return "\n".join(lines).strip()


# --- factory ---------------------------------------------------------------
def build_planner() -> DeterministicPlanner | AnthropicPlanner:
    """Pick the LLM planner when a key is present, else the deterministic one."""
    if config.llm_enabled:
        try:
            return AnthropicPlanner()
        except Exception:  # pragma: no cover - defensive: fall back if SDK/init fails
            return DeterministicPlanner()
    return DeterministicPlanner()
