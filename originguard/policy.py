"""Derive a per-tool policy from its JSON schema, with an optional reviewed overlay.

Defaults are fail-closed:
- A tool is a READ only if its leading verb is a known read verb. A known write
  verb makes it a WRITE. Anything else (execute_sql, run_command, http_request,
  browser_click) is UNKNOWN and denied until an overlay classifies it.
- Every argument of a write tool is AUTHORITY unless its name marks it as
  free-text payload. Booleans, enums and dates are CONTROL: they must equal the
  schema default or be stated.
- On read tools, URL/email/phone arguments are destinations and are checked,
  because a read can exfiltrate data through where it sends a request.
- An argument that is not in the schema, or a free-form object, is denied.
- An overlay entry is pinned to a hash of the tool schema. If the schema
  changes, the tool is denied until the overlay is re-reviewed.

MCP annotations (readOnlyHint, destructiveHint) may only make a tool stricter.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

Effect = Literal["read", "write", "unknown", "denied"]
Role = Literal["authority", "control", "payload", "opaque"]

READ_VERBS = {"get", "list", "read", "search", "fetch", "view", "find", "lookup", "check",
              "describe", "show", "count", "retrieve", "download", "browse", "query_readonly"}
WRITE_VERBS = {"send", "create", "delete", "remove", "update", "transfer", "pay", "post", "share",
               "invite", "write", "move", "schedule", "book", "reply", "forward", "add", "set",
               "grant", "revoke", "cancel", "refund", "approve", "upload", "publish", "deploy",
               "push", "merge", "edit", "modify", "rename", "assign", "submit", "purchase", "buy",
               "order", "checkout", "reset", "change", "close", "archive", "insert", "put",
               "patch", "copy", "link", "unlink", "enable", "disable", "comment", "react", "tag"}
PAYLOAD_NAMES = {"body", "content", "message", "text", "subject", "title", "description", "note",
                 "notes", "comment", "memo", "summary", "html", "markdown", "reason", "caption",
                 "prompt", "bio", "details", "explanation"}
_TYPE_HINTS: list[tuple[str, str]] = [
    (r"(^|_)(e?mail|emails|to|cc|bcc|recipient|recipients|attendee|attendees|participants?|"
     r"invitees?|from|sender|reply_to)$", "email"),
    (r"(^|_)iban$", "iban"),
    (r"(^|_)(amount|price|total|sum|value_usd|cost|fee)$", "amount"),
    (r"(^|_)currency$", "currency"),
    (r"(^|_)(url|urls|link|uri|webhook|endpoint|href)$", "url"),
    (r"(^|_)(phone|mobile|tel|telephone|sms)$", "phone"),
    (r"(^|_)(domain|domains|host|hostname)$", "domain"),
    (r"(^|_)(date|day|due|deadline)$", "date"),
]


def schema_hash(schema: dict) -> str:
    """Stable hash of the parts of a tool schema that change its meaning."""
    material = {k: schema.get(k) for k in ("name", "description", "parameters", "inputSchema")}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verb(name: str) -> str:
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().replace("-", "_").split("_")
    return parts[0] if parts else ""


def _params(schema: dict) -> dict:
    return schema.get("parameters") or schema.get("inputSchema") or {"type": "object", "properties": {}}


def infer_type(arg: str, spec: dict) -> str:
    fmt = spec.get("format")
    if fmt == "email":
        return "email"
    if fmt in ("uri", "url"):
        return "url"
    if fmt in ("date", "date-time"):
        return "date"
    if spec.get("type") == "boolean":
        return "bool"
    if "enum" in spec:
        return "enum"
    leaf = arg.split(".")[-1].rstrip("[]").lower()
    for pat, typ in _TYPE_HINTS:
        if re.search(pat, leaf):
            return typ
    if spec.get("type") in ("number", "integer") and re.search(r"(amount|price|total|sum|cost)", leaf):
        return "amount"
    return "id"


@dataclass
class ArgSpec:
    path: str
    role: Role
    type: str
    sources: tuple[str, ...] = ()            # trusted record sets that may ground this arg
    match: Literal["exact", "host"] = "exact"  # for URLs: whole URL or host only
    default: Any = None
    has_default: bool = False
    inferred: bool = False  # type guessed from the argument name, not stated by schema format or overlay


@dataclass
class ToolPolicy:
    name: str
    effect: Effect
    reason: str
    args: dict[str, ArgSpec] = field(default_factory=dict)
    on_ungrounded: Literal["confirm", "deny"] = "confirm"
    record: dict | None = None   # read tool whose output the operator declares trustworthy
    schema_sha256: str = ""


def _walk(props: dict, prefix: str, out: dict[str, dict]) -> None:
    for name, spec in props.items():
        path = f"{prefix}{name}"
        if spec.get("type") == "array":
            items = spec.get("items", {})
            if items.get("type") == "object" and items.get("properties"):
                _walk(items["properties"], f"{path}[].", out)
            else:
                out[f"{path}[]"] = {**items, **({"default": spec["default"]} if "default" in spec else {})}
        elif spec.get("type") == "object" and spec.get("properties"):
            _walk(spec["properties"], f"{path}.", out)
        else:
            out[path] = spec


def derive(schema: dict, overlay: dict | None = None) -> ToolPolicy:
    name = schema["name"]
    h = schema_hash(schema)
    if overlay is not None:
        pinned = overlay.get("schema_sha256")
        if pinned and pinned != h:
            return ToolPolicy(name, "denied", "tool schema changed since the overlay was reviewed", schema_sha256=h)

    verb = _verb(name)
    ann = schema.get("annotations") or {}
    if verb in WRITE_VERBS or ann.get("destructiveHint") is True:
        effect: Effect = "write"
        reason = f"leading verb {verb!r} is a write verb" if verb in WRITE_VERBS else "destructiveHint"
    elif verb in READ_VERBS:
        effect, reason = "read", f"leading verb {verb!r} is a read verb"
    else:
        effect, reason = "unknown", f"cannot classify {name!r} from its name; add it to the overlay"
    if overlay and overlay.get("effect"):
        wanted = overlay["effect"]
        # an overlay may classify an unknown tool, or tighten read->write; never loosen write->read
        if not (effect == "write" and wanted == "read" and not overlay.get("schema_sha256")):
            effect, reason = wanted, "set by reviewed overlay"

    flat: dict[str, dict] = {}
    _walk(_params(schema).get("properties", {}), "", flat)
    args: dict[str, ArgSpec] = {}
    for path, spec in flat.items():
        leaf = path.split(".")[-1].rstrip("[]").lower()
        typ = infer_type(path, spec)
        if leaf in PAYLOAD_NAMES:
            role: Role = "payload"
        elif spec.get("type") == "object" or (spec == {} and not path.endswith("[]")):
            role = "opaque"  # free-form object: cannot be checked, so it is denied when used
        elif typ in ("bool", "enum", "date"):
            role = "control"
        else:
            role = "authority"
        if effect == "read" and typ not in ("url", "email", "phone"):
            role = "payload"  # reads are free, except where they send data somewhere
        a = ArgSpec(path, role, typ, default=spec.get("default"), has_default="default" in spec,
                    inferred=typ not in ("id", "bool", "enum") and "format" not in spec)
        o = (overlay or {}).get("args", {}).get(path, {})
        if "type" in o:
            a.inferred = False
        for k in ("role", "type", "match"):
            if k in o:
                setattr(a, k, o[k])
        if "sources" in o:
            a.sources = tuple(o["sources"])
        args[path] = a

    return ToolPolicy(
        name, effect, reason, args,
        on_ungrounded=(overlay or {}).get("on_ungrounded", "confirm"),
        record=(overlay or {}).get("record"),
        schema_sha256=h,
    )
