# originguard

Deterministic origin checks for AI agent tool calls. A value may reach a
state-changing tool only if it traces to:

- **the user**: typed in an authenticated turn,
- **a confirmation**: a human approved it out of band, or
- **a trusted record**: an operator-declared list such as a vendor master, the company's own domains or an address book, and only for arguments the overlay allows to use it.

Text the agent reads from emails, web pages, files or tool output **never**
grounds anything. Rewording an injection cannot change a decision. No model is
involved in the decision.

Builds on ROPE ([arXiv:2608.27496](https://arxiv.org/abs/2608.27496), MIT) and
CapLite ([arXiv:2611.17115](https://arxiv.org/abs/2611.17115)). This is an
independent implementation, not a fork.

```python
from originguard import Guard
g = Guard(tools, overlay)          # tool JSON schemas + reviewed overlay
g.user_turn(user_message)          # trusted text only
g.observe(tool_name, tool_result)  # every result; only record tools count
d = g.check(tool_name, args)       # ALLOW | CONFIRM | DENY, with a reason per argument
```

## Framework adapters
**Claude Agent SDK**: hooks on `UserPromptSubmit`, `PreToolUse` and `PostToolUse`:
```python
from originguard.adapters.claude_agent_sdk import guard_hooks
options = ClaudeAgentOptions(mcp_servers=..., hooks=guard_hooks(guard, approver=slack_approver))
```
- ALLOW makes no permission decision, so the SDK's own permissions still apply (the guard only tightens).
- DENY becomes `"deny"`, with the reason sent back to the model.
- CONFIRM goes to your out-of-band `approver`, or else becomes `"ask"`.
- Built-in tools (Bash, Write, WebFetch…) are denied unless you list them in `passthrough`.

**OpenAI Agents SDK**: `needs_approval` plus tool input/output guardrails:
```python
og = OpenAIAgentsGuard(Guard(OpenAIAgentsGuard.schemas(tools), overlay))
agent = Agent(..., tools=og.wrap(tools))
# CONFIRM pauses the run; resume with og.approve(state, item) or og.reject(state, item)
```
A call approved with a plain `state.approve()` that skips the guard is still rejected.

**Shadow mode** (`mode="shadow"` on either adapter): decide and log, never block. Run this on real traffic first.

## Audit log
```python
from originguard.audit import AuditLog
guard = Guard(tools, overlay, audit=AuditLog("audit.jsonl", session="run-42"))
```
Every input and decision is written as one hash-chained JSON line. Untrusted tool output is stored as a hash only.
`python -m originguard.audit audit.jsonl tools.json overlay.json` checks the chain **and** replays the inputs to re-derive every decision. An edited verdict is caught even if the attacker recomputes every hash.

## Defaults are fail-closed
- Tools are classified by leading verb. Unknown tools (`execute_sql`, `run_command`, `http_request`) are **denied** until the overlay classifies them.
- Every argument of a write tool is checked unless its name marks it as free-text payload (`body`, `subject`, `memo`…).
- Booleans, enums and dates must equal the schema default or be stated (e.g. `recurring=True`, `permission="edit"`).
- On read tools, URL, email and phone arguments are checked, because reads can send data somewhere.
- Extra arguments and free-form objects are denied. Every element of a list is checked.
- Overlay entries are pinned to a SHA-256 of the tool schema, so a changed schema is denied until re-reviewed.
- Values are matched by type:
  - `$1,250` equals `1250.00`;
  - "account 7" grounds the id `7`, never the amount 7;
  - "Q3" grounds nothing;
  - IBANs must pass the checksum;
  - look-alike domains are IDNA-encoded and never collide;
  - invisible characters and `https://trusted.com@evil` URLs are rejected.
- Strict mode (`strict=True` + `commit([...])`) freezes the set of write tools before any untrusted read.

## What it does NOT protect (read this before relying on it)
- **Payload text.** An injection can still change what an email *says*, as long as it goes to a permitted recipient.
- **The final answer** shown to the user, and markdown or image exfiltration through rendering.
- **Read-side confidentiality.** The agent can read everything its read tools can reach; only destinations are checked.
- **A contaminated request.** If pasted emails or tickets are passed to `user_turn`, the attacker's text becomes trusted.
- **Wrong-slot reuse.** A value the user stated may ground any argument of a matching type. "Pay 100 to Alice and 250 to Bob" can be swapped.
- **Malicious tool definitions.** Schemas are trusted once reviewed and pinned.
- **Humans who approve everything.** CONFIRM is only as strong as the approver.
- **Records you declare trusted but an attacker can write**, such as auto-added contacts.

## Run
```bash
pip install -e ".[test]"
python3 demo.py        # accounts-payable agent: changed-bank-details attack
python3 -m pytest -q   # 50 tests: properties, regressions, audit, adapters
ANTHROPIC_API_KEY=... python3 bench/live_ap.py --runs 3   # live Claude agent, guarded vs baseline (costs money)
```

Status: **week 2 of a 5-week validation build.** See `BUILD_PLAN.md`.
