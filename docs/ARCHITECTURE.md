# Architecture & Design Notes

This document explains the *why* behind SOC Copilot's structure — the decisions a
reviewer would want defended.

## 1. Why a ReAct agent instead of a fixed pipeline

A fixed enrichment pipeline (always geo-IP → always CVE → always playbook) is
simpler, but it wastes calls and produces irrelevant context. A phishing report
has no IP to enrich; a port-scan alert has no CVE to look up. ReAct lets the
agent choose only the tools that fit the alert, and the visible
`Thought → Action → Observation` trace makes that choice auditable — an analyst
can see *why* each tool ran, which is essential for trust in a security tool.

The trade-off is non-determinism when an LLM drives the loop. We bound it with:
- a hard `max_agent_steps` cap (no infinite loops),
- tools that are pure functions over grounded data (no side effects), and
- a deterministic planner that produces identical output for identical input,
  used for tests and offline demos.

## 2. The LLM abstraction

Both planners implement one contract:

```python
def run(user_message: str, history: list[dict], emit: Callable[[AgentStep], None]) -> str
```

- `AnthropicPlanner` uses Claude with native tool use. Claude sees the six tool
  schemas, decides which to call, and we execute them locally and feed results
  back — the standard tool-use loop.
- `DeterministicPlanner` extracts indicators with regexes, maps behaviour
  keywords to tools, executes them, and synthesises a templated answer.

Selection is automatic: if `ANTHROPIC_API_KEY` is set we use Claude, otherwise the
deterministic planner. This is what lets the whole project — app, tests, CI,
live demo — run with **zero secrets and zero network**, while still being a real
LLM agent when a key is present. The contract is also the extension point for
adding an OpenAI/vLLM planner later without touching the agent core or tools.

## 3. Grounding: how we prevent hallucinated IOCs

The cardinal risk of an LLM in a SOC is a confidently wrong indicator — a made-up
CVE number or a fabricated "this IP is malicious." We mitigate this structurally,
not just with prompt wording:

- Every fact the agent can state comes from a **tool** reading a **dataset**.
- Every `ToolResult` carries a `sources` list (e.g. `cve:CVE-2024-6387`,
  `incident:INC-2041`). The final answer aggregates and displays these, so any
  claim is traceable to a record.
- The system prompt explicitly forbids asserting anything a tool did not return.

Swapping the JSON datasets for live backends (NVD API, TheHive, OpenCTI) is a
tool-internal change — the grounding contract and the citations stay identical.

## 4. Session memory

Conversation history is keyed per session with a 24h TTL. Redis is used in
production so history survives restarts and multiple app instances share it; an
in-process store is the automatic fallback for single-instance dev. Memory is
bounded (`_MAX_TURNS`) independently of the TTL so a long-lived session can't grow
without limit. The agent only ever reads the last handful of turns, keeping
prompt size (and cost) predictable.

## 5. Multi-user, roles and rate limiting

- **Auth**: local accounts with PBKDF2-hashed passwords and stateless HS256 JWTs.
  Stateless tokens mean no server-side session table to scale.
- **RBAC**: `analyst` (chat) and `admin` (chat + administration). `require_role`
  enforces a simple hierarchy.
- **Rate limiting**: a per-user token bucket bounds sustained request rate while
  allowing short bursts — cheap protection against a runaway client or abuse.

## 6. Observability

Prometheus metrics (`/metrics`) expose request volume by planner/outcome, per-tool
usage counts, an end-to-end latency histogram, and the active-session gauge.
Combined with the structured JSON logs (one event per login/answer/error), this
answers the operational questions the brief asked for: requests/day, most-used
tools, and median/p95 response time. The Prometheus service in
`docker-compose.yml` scrapes the app out of the box.

## 7. What would change for production

- Replace seeded accounts with a real user store + OIDC SSO.
- Back the tools with live systems behind the same interface.
- Move rate-limit state to Redis so it is shared across instances.
- Add per-answer feedback capture to build an evaluation set and measure the
  agent's precision over time.
