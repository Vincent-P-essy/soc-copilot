"""HTTP surface tests + WebSocket message-handler tests (fake socket)."""

from __future__ import annotations

import json

import pytest

from backend.agent.core import Agent
from backend.app import _handle_message, create_app
from backend.auth import User


@pytest.fixture
def client():
    return create_app().test_client()


def test_healthz(client):
    data = client.get("/healthz").get_json()
    assert data["status"] == "ok"
    assert data["planner"] == "deterministic"


def test_login_and_me(client):
    r = client.post("/api/login", json={"username": "analyst", "password": "analyst"})
    assert r.status_code == 200
    token = r.get_json()["token"]
    me = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert me.get_json()["username"] == "analyst"


def test_login_rejects_bad_credentials(client):
    r = client.post("/api/login", json={"username": "analyst", "password": "no"})
    assert r.status_code == 401


def test_me_requires_token(client):
    assert client.get("/api/me").status_code == 401


def test_metrics_exposed(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"soc_requests_total" in r.data


class FakeWS:
    """Minimal WebSocket stand-in that records outgoing frames."""

    def __init__(self):
        self.sent: list[dict] = []

    def send(self, raw: str) -> None:
        self.sent.append(json.loads(raw))


def test_handle_message_streams_steps_then_answer():
    ws = FakeWS()
    user = User("analyst", "analyst")
    agent = Agent()
    _handle_message(ws, user, {"text": "brute force on 185.220.101.44 SSH"}, agent)

    types = [f["type"] for f in ws.sent]
    assert "step" in types
    assert types[-1] == "answer"
    answer = ws.sent[-1]
    assert "geoip_enrich" in answer["tools_used"]
    assert answer["sources"]


def test_handle_message_rejects_empty():
    ws = FakeWS()
    _handle_message(ws, User("analyst", "analyst"), {"text": "  "}, Agent())
    assert ws.sent[-1]["type"] == "error"


def test_handle_message_rate_limited(monkeypatch):
    ws = FakeWS()
    monkeypatch.setattr("backend.app.limiter.allow", lambda key: False)
    _handle_message(ws, User("analyst", "analyst"), {"text": "brute force on 1.2.3.4"}, Agent())
    assert ws.sent[-1] == {"type": "error", "error": "rate_limited"}
