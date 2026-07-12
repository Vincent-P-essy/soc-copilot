"use strict";

/**
 * SOC Copilot frontend — a dependency-free WebSocket chat client.
 * Handles auth, opens the /ws channel, renders the streamed ReAct trace, and
 * shows the final cited answer with per-request metadata.
 */

const state = {
  token: null,
  role: null,
  username: null,
  sessionId: "sess-" + Math.random().toString(36).slice(2, 10),
  ws: null,
  activeTrace: null, // DOM node for the in-flight reasoning trace
};

const $ = (sel) => document.querySelector(sel);

// ---- Auth -----------------------------------------------------------------
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("#username").value.trim();
  const password = $("#password").value;
  $("#login-error").textContent = "";
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "login failed");
    state.token = data.token;
    state.role = data.role;
    state.username = data.username;
    enterChat();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

function enterChat() {
  $("#login").classList.add("hidden");
  $("#chat").classList.remove("hidden");
  $("#user-badge").textContent = `${state.username} · ${state.role}`;
  connect();
}

// ---- WebSocket ------------------------------------------------------------
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;
  ws.addEventListener("open", () => ws.send(JSON.stringify({ token: state.token })));
  ws.addEventListener("message", (ev) => handleEvent(JSON.parse(ev.data)));
  ws.addEventListener("close", () => {
    $("#planner-badge").textContent = "disconnected";
  });
}

function handleEvent(msg) {
  switch (msg.type) {
    case "ready":
      $("#planner-badge").textContent = `planner: ${msg.planner}`;
      break;
    case "step":
      renderStep(msg);
      break;
    case "answer":
      renderAnswer(msg);
      break;
    case "reset_ok":
      appendSystem("Conversation memory cleared.");
      break;
    case "error":
      renderError(msg.error);
      break;
  }
}

// ---- Sending --------------------------------------------------------------
function send() {
  const input = $("#input");
  const text = input.value.trim();
  if (!text || state.ws?.readyState !== WebSocket.OPEN) return;
  appendUser(text);
  startTrace();
  state.ws.send(JSON.stringify({ type: "message", text, session_id: state.sessionId }));
  input.value = "";
  autosize(input);
}

$("#send-btn").addEventListener("click", send);
$("#input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    send();
  }
});
$("#input").addEventListener("input", (e) => autosize(e.target));
$("#reset-btn").addEventListener("click", () => {
  state.ws?.send(JSON.stringify({ type: "reset", session_id: state.sessionId }));
});
$("#logout-btn").addEventListener("click", () => location.reload());

document.addEventListener("click", (e) => {
  const li = e.target.closest("[data-example]");
  if (li) {
    $("#input").value = li.dataset.example;
    send();
  }
});

// ---- Rendering ------------------------------------------------------------
const messages = () => $("#messages");
const scroll = () => (messages().scrollTop = messages().scrollHeight);

function appendUser(text) {
  const el = document.createElement("div");
  el.className = "msg user";
  el.innerHTML = `<div class="bubble"></div>`;
  el.querySelector(".bubble").textContent = text;
  messages().appendChild(el);
  scroll();
}

function appendSystem(text) {
  const el = document.createElement("div");
  el.className = "msg system";
  el.innerHTML = `<p></p>`;
  el.querySelector("p").textContent = text;
  messages().appendChild(el);
  scroll();
}

function startTrace() {
  const el = document.createElement("div");
  el.className = "msg agent";
  el.innerHTML = `
    <div class="trace">
      <div class="trace-head"><span>reasoning</span><span class="typing"><span class="dot">●</span><span class="dot">●</span><span class="dot">●</span></span></div>
    </div>`;
  messages().appendChild(el);
  state.activeTrace = el.querySelector(".trace");
  scroll();
}

function renderStep(step) {
  if (!state.activeTrace) startTrace();
  const div = document.createElement("div");
  div.className = "step";
  const parts = [];
  if (step.thought) parts.push(`<div class="thought">${escapeHtml(step.thought)}</div>`);
  if (step.action) {
    const args = Object.entries(step.action_input || {})
      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
      .join(", ");
    parts.push(`<div><span class="action">${escapeHtml(step.action)}</span><span class="args">(${escapeHtml(args)})</span></div>`);
  }
  if (step.observation) parts.push(`<div class="obs">↳ ${escapeHtml(step.observation)}</div>`);
  div.innerHTML = parts.join("");
  state.activeTrace.appendChild(div);
  scroll();
}

function renderAnswer(msg) {
  // Stop the typing indicator on the trace.
  const typing = state.activeTrace?.querySelector(".typing");
  if (typing) typing.remove();

  const el = document.createElement("div");
  el.className = "msg agent";
  const sources = (msg.sources || []).map((s) => `<span class="chip">${escapeHtml(s)}</span>`).join(" ");
  el.innerHTML = `
    <div class="answer"></div>
    <div class="meta">
      <span>⏱ ${msg.latency_ms} ms</span>
      <span>🛠 ${(msg.tools_used || []).length} tools</span>
      <span>${sources}</span>
    </div>`;
  el.querySelector(".answer").textContent = msg.answer;
  messages().appendChild(el);
  state.activeTrace = null;
  scroll();
}

function renderError(error) {
  const typing = state.activeTrace?.querySelector(".typing");
  if (typing) typing.remove();
  state.activeTrace = null;
  const label = error === "rate_limited" ? "Rate limit reached — slow down a moment." : `Error: ${error}`;
  appendSystem(label);
}

// ---- utils ----------------------------------------------------------------
function autosize(ta) {
  ta.style.height = "auto";
  ta.style.height = Math.min(ta.scrollHeight, 140) + "px";
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
