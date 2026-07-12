"""Tests for the ReAct agent core and both planners."""

from __future__ import annotations

from backend.agent.core import Agent
from backend.agent.llm import AnthropicPlanner, DeterministicPlanner, build_planner


def test_build_planner_defaults_to_deterministic_without_key(monkeypatch):
    # Config is frozen, so swap the whole config object build_planner reads.
    from backend.agent import llm

    class _Cfg:
        llm_enabled = False

    monkeypatch.setattr(llm, "config", _Cfg())
    assert isinstance(build_planner(), DeterministicPlanner)


def test_deterministic_extracts_indicators():
    p = DeterministicPlanner()
    found = p._extract(
        "brute force on 185.220.101.44 targeting SSH, hash "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, "
        "see CVE-2024-6387 and domain secure-invoice-portal.com"
    )
    assert "185.220.101.44" in found["ips"]
    assert "CVE-2024-6387" in found["cves"]
    assert "secure-invoice-portal.com" in found["domains"]
    assert "brute force" in found["behaviours"]
    assert "ssh" in found["services"]
    assert len(found["hashes"]) == 1


def test_agent_runs_full_loop_and_cites_sources():
    agent = Agent()
    resp = agent.handle("brute force on 185.220.101.44 against SSH, user admin")
    assert resp.planner == "deterministic"
    assert "geoip_enrich" in resp.tools_used
    assert "suggest_playbook" in resp.tools_used
    assert any(s.startswith("geoip:") for s in resp.sources)
    assert any(s.startswith("playbook:") for s in resp.sources)
    assert "Recommendation:" in resp.answer
    assert resp.latency_ms >= 0


def test_agent_asks_for_clarification_when_no_indicator():
    agent = Agent()
    resp = agent.handle("hi, can you help me?")
    assert resp.tools_used == []
    assert "indicator" in resp.answer.lower()


def test_steps_are_emitted_in_order():
    agent = Agent()
    seen = []
    agent.handle(
        "port scan sweep from 45.155.205.233",
        on_step=lambda s: seen.append(s.action),
    )
    assert seen[0] == "geoip_enrich"
    assert "mitre_lookup" in seen


def test_anthropic_planner_uses_mocked_client(monkeypatch):
    """The Anthropic planner drives the tool-use loop against a fake client."""

    class _Block:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class _Resp:
        def __init__(self, content, stop_reason):
            self.content = content
            self.stop_reason = stop_reason

    calls = {"n": 0}

    class _Messages:
        def create(self, **_):
            calls["n"] += 1
            if calls["n"] == 1:
                return _Resp(
                    [
                        _Block(type="text", text="Let me enrich the IP."),
                        _Block(type="tool_use", id="tu1", name="geoip_enrich",
                               input={"ip": "185.220.101.44"}),
                    ],
                    stop_reason="tool_use",
                )
            return _Resp([_Block(type="text", text="It's a Tor exit node. Block it.")],
                         stop_reason="end_turn")

    class _Client:
        def __init__(self, **_):
            self.messages = _Messages()

    # Construct without __init__ so no real Anthropic client is created.
    planner = AnthropicPlanner.__new__(AnthropicPlanner)
    planner._client = _Client()
    planner._model = "claude-opus-4-8"

    steps = []
    answer = planner.run("brute force on 185.220.101.44", [], steps.append)
    assert any(s.action == "geoip_enrich" for s in steps)
    assert "Tor exit node" in answer
    assert "Sources:" in answer  # collected from the executed tool
