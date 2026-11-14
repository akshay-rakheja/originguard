"""Claude Agent SDK adapter.

    from originguard.adapters.claude_agent_sdk import guard_hooks
    options = ClaudeAgentOptions(..., hooks=guard_hooks(guard))

Hooks registered:
  UserPromptSubmit  the prompt becomes a trusted user turn (register_prompts=True)
  PreToolUse        every tool call is checked
  PostToolUse       every tool result is observed (only overlay-declared record tools count)

Decisions map to the SDK's permissionDecision:
  ALLOW   -> no decision, so the SDK's normal permission flow still applies (the guard
             only ever tightens; it never grants a permission the app didn't)
  DENY    -> "deny", with the reason sent back to the model
  CONFIRM -> your `approver` if given (out of band; approve = confirm the values), else "ask"

Tools that are not in the guard's tool list (built-ins such as Bash, Write, WebFetch)
are denied unless listed in `passthrough`. Passthrough tools are not checked at all;
list only tools you have reviewed.
"""
from __future__ import annotations

from typing import Any, Iterable

from ..guard import Guard
from ._common import Approver, Mode, explain, resolve_name, shadow_log


def _pre(decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def make_callbacks(guard: Guard, *, mode: Mode = "enforce", approver: Approver | None = None,
                   passthrough: Iterable[str] = (), register_prompts: bool = True):
    """The three hook callbacks, framework-free (useful for testing)."""
    passthrough = set(passthrough)

    async def on_prompt(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        if register_prompts and input_data.get("prompt"):
            guard.user_turn(input_data["prompt"])
        return {}

    async def on_pre_tool(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        raw = input_data.get("tool_name", "")
        if raw in passthrough:
            return {}
        d = guard.check(resolve_name(guard, raw), input_data.get("tool_input") or {})
        if mode == "shadow":
            shadow_log(guard, d)
            return {}
        if d.verdict == "ALLOW":
            return {}
        if d.verdict == "CONFIRM":
            if approver is None:
                return _pre("ask", explain(d))
            if await approver(d):
                guard.confirm_decision(d)
                return {}
            return _pre("deny", explain(d) + " (a human declined)")
        return _pre("deny", explain(d))

    async def on_post_tool(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        raw = input_data.get("tool_name", "")
        if raw not in passthrough:
            guard.observe(resolve_name(guard, raw), input_data.get("tool_response"))
        else:
            guard.observe(raw, input_data.get("tool_response"))  # unknown tool: marks untrusted
        return {}

    return on_prompt, on_pre_tool, on_post_tool


def guard_hooks(guard: Guard, **kw) -> dict:
    """Hooks dict for ClaudeAgentOptions(hooks=...)."""
    from claude_agent_sdk import HookMatcher

    on_prompt, on_pre, on_post = make_callbacks(guard, **kw)
    return {
        "UserPromptSubmit": [HookMatcher(hooks=[on_prompt])],
        "PreToolUse": [HookMatcher(matcher=None, hooks=[on_pre])],
        "PostToolUse": [HookMatcher(matcher=None, hooks=[on_post])],
    }
