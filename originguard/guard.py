"""The guard: admit a tool call only if every checked argument has a trusted origin.

Trusted origins:
  user          values the user typed in a trusted turn
  confirmed     values a human approved out of band
  record:<name> operator-declared trusted records (payee list, own domains,
                address book), or the output of a tool the overlay declares
                as a record source. An argument may use a record set only if
                its overlay entry lists that set in `sources`.

Untrusted tool output never adds to the grounding set. That is the core
security property (non-interference): for a fixed request, records,
confirmations and policy, the verdict is the same whatever untrusted
content the agent has read.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable, Literal

from . import canon
from .extract import Fact, extract, words
from .policy import ArgSpec, ToolPolicy, derive

Verdict = Literal["ALLOW", "CONFIRM", "DENY"]
_RANK = {"ALLOW": 0, "CONFIRM": 1, "DENY": 2}


@dataclass
class ArgDecision:
    path: str
    type: str
    value: Any
    verdict: Verdict
    detail: str  # origin when allowed, reason otherwise


@dataclass
class Decision:
    tool: str
    verdict: Verdict
    reason: str
    args: list[ArgDecision] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"


def _flatten(args: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    """Yield (schema path, leaf value). Lists use 'name[]', so EVERY element is checked."""
    if isinstance(args, dict):
        for k, v in args.items():
            yield from _flatten(v, f"{prefix}{k}" if not prefix else f"{prefix}.{k}")
    elif isinstance(args, (list, tuple)):
        if not args:
            yield f"{prefix}[]", None
        for v in args:
            if isinstance(v, dict):
                for k, vv in v.items():
                    yield from _flatten(vv, f"{prefix}[].{k}")
            else:
                yield f"{prefix}[]", v
    else:
        yield prefix, args


class Guard:
    def __init__(self, tools: list[dict], overlay: dict | None = None, *, strict: bool = False) -> None:
        overlay = overlay or {}
        tool_overlays = overlay.get("tools", {})
        self.policies: dict[str, ToolPolicy] = {t["name"]: derive(t, tool_overlays.get(t["name"])) for t in tools}
        self.facts: dict[str, set[Fact]] = {"user": set(), "confirmed": set()}
        self.user_words: set[str] = set()
        self.strict = strict
        self.committed: set[str] | None = None
        self._untrusted_seen = False
        for name, rec in (overlay.get("records") or {}).items():
            for typ, values in rec.items():
                self.add_record(name, typ, values)

    # ---- trusted inputs -------------------------------------------------------------
    def user_turn(self, text: str) -> None:
        """Text from an authenticated human turn. Never pass tool output or pasted content here."""
        self.facts["user"] |= extract(text)
        self.user_words |= words(text)

    def add_record(self, name: str, typ: str, values: Iterable[Any]) -> None:
        bucket = self.facts.setdefault(f"record:{name}", set())
        for v in values:
            try:
                c = canon.CANON[typ](v)
            except canon.CanonError:
                continue
            bucket.add((typ, c))
            if typ == "email":
                bucket.add(("domain", c.split("@")[1]))

    def confirm(self, typ: str, value: Any) -> None:
        """Called by the out-of-band approval channel only, never by the agent."""
        self.facts["confirmed"].add((typ, canon.CANON[typ](value)))

    def commit(self, write_tools: Iterable[str]) -> None:
        """Strict mode: declare the write tools a task needs before reading untrusted content."""
        if self._untrusted_seen:
            raise RuntimeError("commit() must be called before any untrusted tool output is read")
        self.committed = {t for t in write_tools if t in self.policies}

    def observe(self, tool: str, result: Any) -> None:
        """Feed every tool result here. Only overlay-declared record tools contribute facts."""
        pol = self.policies.get(tool)
        rec = pol.record if pol and pol.effect == "read" else None
        if not rec:
            self._untrusted_seen = True
            return
        data = result
        if isinstance(result, str):
            try:
                data = json.loads(result)
            except ValueError:
                self._untrusted_seen = True
                return  # an unparseable record licenses nothing
        rows = data if isinstance(data, list) else [data]
        for field_name, typ in rec.get("fields", {}).items():
            self.add_record(rec["name"], typ, [r[field_name] for r in rows if isinstance(r, dict) and field_name in r])

    # ---- the check ------------------------------------------------------------------
    def check(self, tool: str, args: dict | None) -> Decision:
        args = args or {}
        pol = self.policies.get(tool)
        if pol is None:
            return Decision(tool, "DENY", "unknown tool (not in the reviewed tool list)")
        if pol.effect in ("unknown", "denied"):
            return Decision(tool, "DENY", pol.reason)
        if pol.effect == "write" and self.strict and self.committed is not None and tool not in self.committed:
            return Decision(tool, "DENY", "write tool was not committed before reading untrusted content")

        out: list[ArgDecision] = []
        for path, value in _flatten(args):
            spec = pol.args.get(path)
            if spec is None:
                out.append(ArgDecision(path, "?", value, "DENY", "argument not in the tool schema"))
                continue
            out.append(self._check_arg(spec, value, pol))
        worst = max((a.verdict for a in out), key=_RANK.get, default="ALLOW")
        reason = {"ALLOW": "every checked argument has a trusted origin",
                  "CONFIRM": "some values were not stated by the user; ask a human",
                  "DENY": "blocked"}[worst]
        return Decision(tool, worst, reason, out)

    def _check_arg(self, spec: ArgSpec, value: Any, pol: ToolPolicy) -> ArgDecision:
        def ungrounded(why: str) -> ArgDecision:
            return ArgDecision(spec.path, spec.type, value, "DENY" if pol.on_ungrounded == "deny" else "CONFIRM", why)

        if spec.role == "payload" or value is None:
            return ArgDecision(spec.path, spec.type, value, "ALLOW", "payload (not checked)")
        if spec.role == "opaque":
            return ArgDecision(spec.path, spec.type, value, "DENY", "free-form object cannot be checked")
        if spec.type in ("bool", "enum"):
            if spec.has_default and value == spec.default:
                return ArgDecision(spec.path, spec.type, value, "ALLOW", "schema default")
            if str(value).lower() in self.user_words:
                return ArgDecision(spec.path, spec.type, value, "ALLOW", "user")
            return ungrounded("control value differs from the default and was not stated")
        try:
            c = canon.CANON[spec.type](value)
        except (canon.CanonError, KeyError) as e:
            if not spec.inferred:
                return ArgDecision(spec.path, spec.type, value, "DENY", f"cannot canonicalize: {e}")
            # The type was only a guess from the name (e.g. "recipient" holding "bob"):
            # fall back to exact identifier matching, which is at least as strict.
            from dataclasses import replace
            spec = replace(spec, type="id", inferred=False)
            try:
                c = canon.identifier(value)
            except canon.CanonError as e2:
                return ArgDecision(spec.path, spec.type, value, "DENY", f"cannot canonicalize: {e2}")
        origins = ["user", "confirmed"] + [f"record:{s}" for s in spec.sources]
        for origin in origins:
            if self._matches(spec, c, self.facts.get(origin, set())):
                return ArgDecision(spec.path, spec.type, value, "ALLOW", origin)
        return ungrounded(f"{spec.type} {c!r} has no trusted origin")

    @staticmethod
    def _matches(spec: ArgSpec, c: str, facts: set[Fact]) -> bool:
        if spec.type == "amount":
            v, cur = canon.parse_money(c)
            for typ, f in facts:
                if typ == "amount":
                    fv, fcur = canon.parse_money(f)
                    if Decimal(fv) == Decimal(v) and (cur is None or fcur is None or cur == fcur):
                        return True
            return False
        if spec.type == "url" and spec.match == "host":
            host = c.split("//", 1)[1].split("/", 1)[0]
            return any((t == "url" and canon.url_host(f) == host) or (t == "domain" and f == host) for t, f in facts)
        return (spec.type, c) in facts
