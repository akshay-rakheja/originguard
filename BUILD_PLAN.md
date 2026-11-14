# Build plan and status

The plan comes from `docs/investigation.md` (section 6.4). The idea came from the paper-scout run of 2026-11-14.

## Week 1: core mediator ✅ (2026-11-14)
- [x] Schema-derived policy, fail-closed classification, default-authority arguments
- [x] Typed canonicalizers: email, domain, URL, IBAN, amount + currency, phone, date, id
- [x] Typed extraction from user text (type binding)
- [x] Trusted records, static or from overlay-declared record tools, scoped per argument
- [x] Overlay with schema-hash pinning; strict mode with write commitment
- [x] Property tests 1–5 (grounding, non-interference, fail closed, canonicalization, type binding). Mutation-checked: deliberately broken guards fail the suite.
- [x] Regression tests for the four fail-open holes in the old prototype
- [~] Discovery calls: **skipped for now** (decision 2026-11-14). The week-3 design-partner gate still applies.
- [ ] Reproduce ROPE's numbers from its shipped logs. This was blocked in-session by the safety check on running downloaded code; run `runs/aggregate.py` from github.com/xhOwenMa/ROPE locally, or approve running it here.

## Week 2: adapters + benchmarks
- [x] Claude Agent SDK adapter (`UserPromptSubmit` / `PreToolUse` / `PostToolUse` hooks; out-of-band approver; passthrough list)
- [x] OpenAI Agents SDK adapter (`needs_approval` + tool input/output guardrails; approvals must go through the guard)
- [x] Hash-chained audit log + offline verifier that replays inputs and re-derives every decision
- [x] Shadow (log-only) mode in both adapters
- [x] Tests against the real SDK types (no model calls): 50 tests total
- [x] `bench/live_ap.py`: live Claude agent on accounts-payable scenarios, guarded vs baseline
- [ ] Run `bench/live_ap.py` (**needs ANTHROPIC_API_KEY in the environment**)
- [ ] AgentDojo + AgentDyn runs on Claude Opus 5.5, Claude Sonnet 5.5 and Claude Haiku 5.5, vs undefended and ROPE, reported per model with confirmations counted three ways (needs the key)
- [ ] End-to-end run inside the real Claude Agent SDK loop (needs the key and the bundled CLI)

## Week 3: confirmation flow + GATE
- Out-of-band approval (Slack), showing where each value came from, rendered as plain text; batched approvals
- **Gate:** at least 2 design partners in shadow mode, and utility within 10 points of undefended on a frontier model

## Week 4: hardening
- Payout scenario suite (classes A–F), canonicalizer fuzzing, internal red-team round, confirmation-dialog mini user study

## Week 5: release + decision
- Docs, open-source release, external review of the mediator, decision memo

## Kill criteria (any one stops the project)
- Shadow-mode confirmations above 25% of write calls after trusted records are configured
- Fewer than 2 design partners willing to enforce
- A bypass in the trusted base that can't be fixed without a model call in the decision path
- A competitor ships origin-based checks. Re-check Arcjet, Microsoft's Agent Governance Toolkit, AWS AgentCore Policy and Invariant/Snyk at weeks 3 and 5.

## Known gaps to close
- Wrong-slot binding (strict mode should bind stated values to argument roles)
- Multi-turn growth of the grounding set (confirmed and user values currently accumulate for the whole session)
- Named-source rule ("reply to this thread" → that thread's sender), as in ROPE
- Dates beyond ISO format, phone numbers without a leading +, non-Latin amounts
