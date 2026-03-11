# NonSudo Public Contract

**Date:** 2026-03-02 | **Version:** VAR v1.0

---

## What NonSudo Does

NonSudo is a signing proxy between an AI agent and its tools. Every tool call is evaluated
against a policy and recorded as an Ed25519-signed receipt before the call proceeds.
Receipts are hash-chained so that the chain is independently verifiable by any party
holding the public key — no dependency on NonSudo infrastructure required.

---

## Three Modes

| Mode | Identity | Bypassable | Post-receipts | Suitable For |
|------|----------|-----------|---------------|--------------|
| **Crawl** | Header-asserted | Yes | No | Observability, audit prototyping |
| **Walk** | Header-asserted + session provenance | Yes, if agent holds credentials outside proxy | Yes, money actions | Production enforcement, compliance |
| **Run** | Workload identity (OIDC/SPIFFE) | No | Yes, all actions | High-assurance, regulated |

Run is v1.1. Walk is the production mode in v1.0.

---

## Receipt Invariants

- Every session starts with a **signed manifest** recording which policy was active, which
  tools were declared, and who initiated the workflow.
- Every money action has a **signed pre-receipt** (decision) and a **signed post-receipt**
  (terminal outcome). Neither can be removed without breaking the hash chain.
- Every chain is **independently verifiable offline** using only the receipt file and the
  public JWK. No NonSudo service involvement required.

---

## What NonSudo Does Not Do

- Does not read parameter content — only hashes it.
- Does not detect prompt injection or semantic manipulation.
- Does not guarantee non-bypass in Walk mode if the agent holds credentials outside the proxy.
- Does not provide outcome binding in Crawl mode.

---

## Verification Tiers

**L1 — Cryptographic integrity:** Ed25519 signature valid; key resolves from trust store.

**L2 — Chain integrity:** Sequence numbers contiguous; hash chain unbroken; manifest first.

**L3 — Time integrity:** RFC 3161 token valid; messageImprint matches receipt hash; TSA allowlisted.

**L4 — Outcome binding:** Every ALLOW'd money action has a terminal post-receipt; budget
accounting consistent; projection hash matches.

---

## Six Answers to Common Objections

**Q1 — "We have OPA and CloudTrail."**
Neither produces a signed chain of agent decisions with the policy hash, agent identity,
and arguments committed together before the call completes.

**Q5 — "Does this stop prompt injection?"**
No. NonSudo records what the agent tried to do and applies policy. The receipt chain
proves what happened; it does not prevent manipulation of the agent.

**Q8 — "Why stateful?"**
Budget accounting, velocity limits, and idempotency deduplication require state. A
stateless logger cannot enforce "$1,000 refund cap" across concurrent sessions.

**Q11 — "Audit logs already exist. What does crypto add?"**
Logs can be modified before you look. Hash chaining makes modification detectable.
The receipt chain is verifiable out-of-band with no trust in NonSudo.

**Q23 — "A proxy hop is operational friction."**
Policy evaluation completes in under 2ms for local state. RFC 3161 timestamping is
asynchronous. A TSA outage does not block agents; it yields L3: SKIPPED.

**Q34–Q37 — "What about gateways / SIEMs / service meshes / provider controls?"**
Gateways see bytes, not tool semantics. SIEMs aggregate logs; NonSudo generates evidence.
Service meshes are L4–L7; MCP tool calls are application-layer structured actions.
Provider rate limits operate on model output quotas, not on tool semantics — they cannot
enforce "no refunds over $500."

---

*NonSudo, Inc. — [Technical reference](reference/contract.md) — [Core spec](spec/var-core-v1.0.md)*
