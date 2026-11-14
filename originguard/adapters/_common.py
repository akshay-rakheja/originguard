from __future__ import annotations

from typing import Any, Awaitable, Callable, Literal

from ..guard import Decision, Guard

Mode = Literal["enforce", "shadow"]
# An out-of-band approver: shown the decision, returns True to approve. It must reach a
# human through a channel the agent cannot write to (Slack, push, email). Never let the
# model answer it.
Approver = Callable[[Decision], Awaitable[bool]]


def explain(d: Decision) -> str:
    """A short, plain-text reason for the model and the approver. Values are repr()'d so
    attacker-controlled text cannot render as markup."""
    bad = [a for a in d.args if a.verdict != "ALLOW"]
    if not bad:
        return f"originguard: {d.verdict} {d.tool}: {d.reason}"
    parts = "; ".join(f"{a.path}={a.value!r}: {a.detail}" for a in bad[:5])
    return f"originguard: {d.verdict} {d.tool}: {parts}"


def shadow_log(guard: Guard, d: Decision) -> None:
    guard._emit("shadow", {"tool": d.tool, "would_be": d.verdict})


def resolve_name(guard: Guard, name: str) -> str:
    """'mcp__payments__pay_invoice' -> 'pay_invoice' when that is a reviewed tool."""
    if name in guard.policies:
        return name
    if name.startswith("mcp__"):
        short = name.split("__", 2)[-1]
        if short in guard.policies:
            return short
    return name


def parse_args(raw: Any) -> dict:
    import json
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        v = json.loads(raw)
        if not isinstance(v, dict):
            raise ValueError("tool arguments must be a JSON object")
        return v
    return {}
