"""Tamper-evident audit log and offline verifier.

Every guard input (user turns, records, confirmations, commitments, tool
results) and every decision is appended as one JSON line. Each line carries
the SHA-256 of the previous line, so editing, deleting or reordering any line
breaks the chain.

`verify()` does two things:
  1. checks the hash chain;
  2. replays the logged inputs into a fresh Guard built from the same tool
     schemas and overlay, and re-derives every decision. A decision that does
     not match is reported. This is what a reviewer or auditor runs, with no
     access to the live system.

Untrusted tool output is logged by hash only. It cannot affect a decision
(the non-interference property), so the replay doesn't need it.

Note: user turns are stored in full, because decisions depend on them.
Treat the log as sensitive data.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64


def _line_hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, default=str)).encode()).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL file. Safe to share between threads of one process."""

    def __init__(self, path: str | os.PathLike, *, session: str | None = None, clock=time.time) -> None:
        self.path = os.fspath(path)
        self.session = session
        self.clock = clock
        self._lock = threading.Lock()
        self._prev, self._seq = GENESIS, 0
        if os.path.exists(self.path):  # resume the chain
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        self._prev, self._seq = rec["hash"], rec["seq"] + 1

    def append(self, typ: str, data: dict) -> None:
        with self._lock:
            body = {"seq": self._seq, "ts": self.clock(), "session": self.session, "type": typ,
                    "data": json.loads(json.dumps(data, default=str)), "prev": self._prev}
            h = _line_hash(self._prev, body)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({**body, "hash": h}, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev, self._seq = h, self._seq + 1


@dataclass
class VerifyReport:
    ok: bool
    lines: int = 0
    decisions: int = 0
    problems: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        head = f"{'OK' if self.ok else 'FAILED'}: {self.lines} lines, {self.decisions} decisions re-derived"
        return "\n".join([head] + [f"  - {p}" for p in self.problems])


def verify(path: str | os.PathLike, tools: list[dict], overlay: dict | None = None) -> VerifyReport:
    from .guard import Guard, _sha  # local import: no cycle at module load

    rep = VerifyReport(ok=True)
    with open(path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    rep.lines = len(records)

    # 1. hash chain
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("seq") != i:
            rep.problems.append(f"line {i}: sequence number {rec.get('seq')} (expected {i})")
        if rec.get("prev") != prev:
            rep.problems.append(f"line {i}: broken chain (prev hash mismatch)")
        if _line_hash(rec.get("prev", ""), body) != rec.get("hash"):
            rep.problems.append(f"line {i}: content does not match its hash (edited?)")
        prev = rec.get("hash", "")

    # 2. replay and re-derive every decision
    guard: Guard | None = None
    for i, rec in enumerate(records):
        t, d = rec["type"], rec["data"]
        if t == "init":
            guard = Guard(tools, overlay, strict=d.get("strict", False))
            want = {n: p.schema_sha256 for n, p in sorted(guard.policies.items())}
            if d.get("tools") != want:
                rep.problems.append(f"line {i}: tool schemas differ from the ones the session ran with")
            if d.get("overlay_sha256") != _sha(overlay or {}):
                rep.problems.append(f"line {i}: overlay differs from the one the session ran with")
            continue
        if guard is None:
            rep.problems.append(f"line {i}: event before init")
            continue
        if t == "user_turn":
            guard.user_turn(d["text"])
        elif t == "record":
            guard.add_record(d["name"], d["type"], d["values"])
        elif t == "confirm":
            guard.confirm(d["type"], d["value"])
        elif t == "commit":
            guard.commit(d["tools"])
        elif t == "observe":
            if d.get("record"):
                guard.observe(d["tool"], d["result"])
            else:
                guard._untrusted_seen = True
        elif t == "check":
            rep.decisions += 1
            got = guard._check(d["tool"], d["args"]).verdict
            if got != d["verdict"]:
                rep.problems.append(f"line {i}: {d['tool']} logged {d['verdict']} but replay gives {got}")
        elif t == "shadow":
            pass
        else:
            rep.problems.append(f"line {i}: unknown event type {t!r}")
    rep.ok = not rep.problems
    return rep


def main(argv: list[str] | None = None) -> int:
    """python -m originguard.audit LOG TOOLS.json [OVERLAY.json]"""
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) not in (2, 3):
        print(main.__doc__)
        return 2
    tools = json.load(open(argv[1]))
    overlay = json.load(open(argv[2])) if len(argv) == 3 else None
    r = verify(argv[0], tools, overlay)
    print(r)
    return 0 if r.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
