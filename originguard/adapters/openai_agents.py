"""OpenAI Agents SDK adapter.

    og = OpenAIAgentsGuard(guard)
    agent = Agent(..., tools=og.wrap([pay_invoice, send_email]))
    guard.user_turn(user_input)            # the trusted request
    result = await Runner.run(agent, user_input)
    for item in result.interruptions:      # CONFIRM decisions pause the run
        if human_says_yes(item):           # out of band: Slack, push, email
            og.approve(state, item)
        else:
            og.reject(state, item)

How it maps:
  needs_approval        returns True for CONFIRM, so the SDK pauses the run for a human
  tool_input_guardrail  re-checks at invocation; anything not ALLOW is rejected with a
                        message to the model. Approval through og.approve() confirms the
                        values first, so an approved call passes. A call approved some
                        other way (plain state.approve) is still rejected: approvals must
                        go through the guard.
  tool_output_guardrail every tool result is observed

DENY never interrupts the run; the model gets the reason and can try something else.
"""
from __future__ import annotations

import copy
import json
from typing import Any

from ..guard import Guard
from ._common import Mode, explain, parse_args, shadow_log


class OpenAIAgentsGuard:
    def __init__(self, guard: Guard, *, mode: Mode = "enforce") -> None:
        self.guard = guard
        self.mode = mode

    # -- the three callables (framework-free signatures, easy to test) --------------------
    async def needs_approval(self, tool_name: str, params: dict) -> bool:
        if self.mode == "shadow":
            return False
        return self.guard.check(tool_name, params).verdict == "CONFIRM"

    def check_invocation(self, tool_name: str, raw_args: Any) -> str | None:
        """None to allow, else the rejection message for the model."""
        try:
            args = parse_args(raw_args)
        except (ValueError, json.JSONDecodeError):
            return "originguard: DENY: tool arguments are not a JSON object"
        d = self.guard.check(tool_name, args)
        if self.mode == "shadow":
            shadow_log(self.guard, d)
            return None
        return None if d.verdict == "ALLOW" else explain(d)

    # -- wiring ---------------------------------------------------------------------------
    def wrap(self, tools: list) -> list:
        from agents.tool_guardrails import (ToolGuardrailFunctionOutput, tool_input_guardrail,
                                            tool_output_guardrail)

        wrapped = []
        for tool in tools:
            name = tool.name
            if not hasattr(tool, "params_json_schema"):
                raise TypeError(f"{name}: only FunctionTool is supported; hosted tools bypass the guard")

            async def _needs(ctx, params, call_id, _n=name):
                return await self.needs_approval(_n, params)

            @tool_input_guardrail(name=f"originguard_in_{name}")
            def _in(data, _n=name):
                msg = self.check_invocation(_n, data.context.tool_arguments)
                if msg is None:
                    return ToolGuardrailFunctionOutput.allow()
                return ToolGuardrailFunctionOutput.reject_content(message=msg)

            @tool_output_guardrail(name=f"originguard_out_{name}")
            def _out(data, _n=name):
                self.guard.observe(_n, data.output)
                return ToolGuardrailFunctionOutput.allow()

            t = copy.copy(tool)
            t.needs_approval = _needs
            t.tool_input_guardrails = [*(tool.tool_input_guardrails or []), _in]
            t.tool_output_guardrails = [*(tool.tool_output_guardrails or []), _out]
            wrapped.append(t)
        return wrapped

    @staticmethod
    def schemas(tools: list) -> list[dict]:
        """Tool schemas in the shape Guard expects, from FunctionTools."""
        return [{"name": t.name, "description": getattr(t, "description", ""),
                 "parameters": t.params_json_schema} for t in tools]

    def _item_call(self, item) -> tuple[str, dict]:
        raw = item.raw_item
        name = getattr(item, "tool_name", None) or getattr(raw, "name", None) or raw.get("name")
        args = getattr(raw, "arguments", None)
        if args is None and isinstance(raw, dict):
            args = raw.get("arguments")
        return name, parse_args(args)

    def approve(self, state, item) -> None:
        """A human approved this call out of band: confirm its values, then resume."""
        name, args = self._item_call(item)
        self.guard.confirm_decision(self.guard.check(name, args))
        state.approve(item)

    def reject(self, state, item, message: str | None = None) -> None:
        state.reject(item, rejection_message=message or "A human declined this action.")
