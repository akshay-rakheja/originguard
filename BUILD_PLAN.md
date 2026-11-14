# Build plan and status

The plan comes from `research/write-guard/investigation.md` (section 6.4).

## Week 1: core mediator ✅ (2026-11-14)
- [x] Schema-derived policy, fail-closed classification, default-authority arguments
- [x] Typed canonicalizers: email, domain, URL, IBAN, amount + currency, phone, date, id
- [x] Typed extraction from user text (type binding)
- [x] Trusted records, static or from overlay-declared record tools, scoped per argument
- [x] Overlay with schema-hash pinning; strict mode with write commitment
- [x] Property tests 1–5 (grounding, non-interference, fail closed, canonicalization, type binding). Mutation-checked: deliberately broken guards fail the suite.
- [x] Regression tests for the four fail-open holes in the old prototype
- [ ] **Owner: you.** Ten discovery calls with finance-ops and payout engineering leads. Ask what they use today, and what a bad payout cost them.
- [ ] Reproduce ROPE's numbers from its shipped logs. This was blocked in-session by the safety check on running downloaded code; run `runs/aggregate.py` from github.com/xhOwenMa/ROPE locally, or approve running it here.

## Week 2: adapters + benchmarks
- Claude Agent SDK `PreToolUse` adapter; OpenAI Agents SDK `needs_approval` adapter
- Hash-chained audit log + offline verifier; shadow (log-only) mode
- AgentDojo + AgentDyn runs on two frontier models and one small model, vs undefended and ROPE. Report results per model, with confirmations counted three ways. **Needs an API key** (OpenRouter or Anthropic/OpenAI).

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
