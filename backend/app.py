"""Flask API gateway + WebSocket chat handler.

Wires the agent, auth, rate limiting, session memory and metrics behind a small
HTTP/WebSocket surface and serves the vanilla-JS frontend.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_sock import Sock

from . import metrics
from .agent.core import Agent
from .auth import AuthError, authenticate, issue_token, verify_token
from .config import config
from .rate_limit import limiter
from .sessions import store

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
log = logging.getLogger("soc-copilot")


def _log(event: str, **fields: object) -> None:
    log.info(json.dumps({"event": event, **fields}))


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    sock = Sock(app)
    agent = Agent()
    _log("startup", planner=agent.planner_name, memory=store.backend_name)

    # -- static frontend ---------------------------------------------------
    @app.get("/")
    def index() -> object:
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename: str) -> object:
        return send_from_directory(FRONTEND_DIR, filename)

    # -- health / metrics --------------------------------------------------
    @app.get("/healthz")
    def healthz() -> object:
        return jsonify(
            status="ok",
            planner=agent.planner_name,
            memory=store.backend_name,
            llm_enabled=config.llm_enabled,
        )

    @app.get("/metrics")
    def metrics_endpoint() -> object:
        payload, content_type = metrics.render()
        return app.response_class(payload, mimetype=content_type)

    # -- auth --------------------------------------------------------------
    @app.post("/api/login")
    def login() -> object:
        body = request.get_json(silent=True) or {}
        try:
            user = authenticate(body.get("username", ""), body.get("password", ""))
        except AuthError as exc:
            return jsonify(error=str(exc)), 401
        token = issue_token(user)
        _log("login", user=user.username, role=user.role)
        return jsonify(token=token, username=user.username, role=user.role)

    @app.get("/api/me")
    def me() -> object:
        user = _bearer_user()
        if user is None:
            return jsonify(error="unauthorized"), 401
        return jsonify(username=user.username, role=user.role)

    def _bearer_user():
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        try:
            return verify_token(header[7:])
        except AuthError:
            return None

    # -- websocket chat ----------------------------------------------------
    @sock.route("/ws")
    def chat(ws) -> None:  # noqa: ANN001 - flask-sock passes a Server object
        # First frame must authenticate.
        try:
            first = json.loads(ws.receive())
        except (TypeError, ValueError):
            ws.send(json.dumps({"type": "error", "error": "expected auth frame"}))
            return
        try:
            user = verify_token(first.get("token", ""))
        except AuthError as exc:
            ws.send(json.dumps({"type": "error", "error": str(exc)}))
            return

        ws.send(
            json.dumps(
                {
                    "type": "ready",
                    "username": user.username,
                    "role": user.role,
                    "planner": agent.planner_name,
                }
            )
        )
        metrics.ACTIVE_SESSIONS.inc()
        try:
            while True:
                raw = ws.receive()
                if raw is None:
                    break
                try:
                    msg = json.loads(raw)
                except ValueError:
                    ws.send(json.dumps({"type": "error", "error": "invalid json"}))
                    continue
                if msg.get("type") == "reset":
                    store.clear(msg.get("session_id", user.username))
                    ws.send(json.dumps({"type": "reset_ok"}))
                    continue
                if msg.get("type") != "message":
                    continue
                _handle_message(ws, user, msg, agent)
        finally:
            metrics.ACTIVE_SESSIONS.dec()

    return app


def _handle_message(ws, user, msg, agent: Agent) -> None:  # noqa: ANN001
    text = (msg.get("text") or "").strip()
    session_id = msg.get("session_id") or user.username
    if not text:
        ws.send(json.dumps({"type": "error", "error": "empty message"}))
        return

    if not limiter.allow(user.username):
        metrics.REQUESTS.labels(planner=agent.planner_name, status="rate_limited").inc()
        ws.send(json.dumps({"type": "error", "error": "rate_limited"}))
        return

    request_id = str(uuid.uuid4())[:8]
    history = store.history(session_id)

    def on_step(step) -> None:  # noqa: ANN001
        if step.action:
            metrics.TOOL_CALLS.labels(tool=step.action).inc()
        payload = {"type": "step", "request_id": request_id, **step.to_dict()}
        ws.send(json.dumps(payload))

    try:
        with metrics.LATENCY.time():
            resp = agent.handle(text, history=history, on_step=on_step)
    except Exception as exc:  # pragma: no cover - defensive
        metrics.REQUESTS.labels(planner=agent.planner_name, status="error").inc()
        _log("agent_error", request_id=request_id, error=str(exc))
        ws.send(json.dumps({"type": "error", "error": "internal error"}))
        return

    store.record(session_id, "user", text)
    store.record(session_id, "assistant", resp.answer)
    metrics.REQUESTS.labels(planner=agent.planner_name, status="ok").inc()
    _log(
        "answer",
        request_id=request_id,
        user=user.username,
        tools=resp.tools_used,
        latency_ms=resp.latency_ms,
    )
    ws.send(
        json.dumps(
            {
                "type": "answer",
                "request_id": request_id,
                **resp.to_dict(),
            }
        )
    )


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.port, threaded=True)
