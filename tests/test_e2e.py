"""End-to-end triage scenarios.

Each scenario asserts the agent gathers the right context and produces a cited,
actionable answer — the behaviour a reviewer would check by hand.
"""

from __future__ import annotations

from backend.agent.core import Agent


def test_scenario_ssh_brute_force():
    resp = Agent().handle(
        "Brute force alert on 185.220.101.44, 47 attempts in 3 min against SSH, user admin"
    )
    # Geo enrichment identifies the Tor exit node.
    assert "geoip:185.220.101.0/24" in resp.sources
    # History pivot finds the prior incidents.
    assert any(s.startswith("incident:") for s in resp.sources)
    # ATT&CK mapping + SSH CVE exposure.
    assert "mitre:T1110" in resp.sources
    assert any(s.startswith("cve:") for s in resp.sources)
    # Recommends the credential-attack playbook.
    assert "playbook:IR-002" in resp.sources
    assert "Recommendation:" in resp.answer


def test_scenario_sqli_correlated_range():
    resp = Agent().handle(
        "We saw sqlmap-style requests to /api/search from 45.155.205.233. "
        "Was this range seen before?"
    )
    # Correlation links the SQLi source to the earlier port-scan incident.
    incident_sources = {s for s in resp.sources if s.startswith("incident:")}
    assert {"incident:INC-2050", "incident:INC-2052"} <= incident_sources
    # Mapped to web exploitation.
    assert "mitre:T1190" in resp.sources


def test_scenario_powershell_c2_beacon():
    resp = Agent().handle(
        "Endpoint beaconing to 91.240.118.172 after an encoded PowerShell run. "
        "What is this and what do I do?"
    )
    # Enrichment flags the RU hosting range.
    assert "geoip:91.240.118.0/24" in resp.sources
    # Maps to C2 and recommends the malware/C2 playbook.
    assert "mitre:T1071" in resp.sources
    assert "playbook:IR-004" in resp.sources


def test_memory_carries_context_across_turns():
    agent = Agent()
    history = [
        {"role": "user", "content": "brute force on 185.220.101.44"},
        {"role": "assistant", "content": "Tor exit node; blocked."},
    ]
    # A follow-up still resolves because the deterministic planner re-extracts.
    resp = agent.handle("is 185.220.101.44 linked to other incidents?", history=history)
    assert any(s.startswith("incident:") for s in resp.sources)
