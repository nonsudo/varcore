# VAR v1.0 Public Contract

**Verifiable Action Receipt — Version 1.0**
**Status:** LOCKED — field names frozen. Changes require version bump and PR against this file.  
**Canonical URL:** `schemas.nonsudo.dev/var/v1/contract.md`  
**Last updated:** 2026-02-28  

---

## 1. Purpose

This document is the canonical specification for a Verifiable Action Receipt (VAR). It defines:

- All mandatory and optional fields, with types and signing scope
- The canonicalization rule for signing
- The chaining rule for tamper-evidence
- The verifier level definitions
- Redaction rules for receipt-only mode
- Phase 0 vs Phase 1 feature gates

Every implementation — proxy, library, framework wrapper, verifier — is an implementation of this document. If this document and any implementation disagree, this document is correct.

---

## 2. Receipt Types

A receipt is a JSON object. Every receipt carries a `record_type` field that determines which schema applies.

| `record_type` | When emitted |
|---|---|
| `workflow_manifest` | Once, at workflow start, before any tool calls. sequence_number: 0. |
| `action_receipt` | Once per tool call evaluation. sequence_number: 1, 2, 3… |
| `workflow_closed` | Phase 1 only: emitted as a signed receipt by the proxy on connection teardown. Phase 0: no signed receipt exists — workflow state expires via Redis TTL (24h default). |

---

## 3. Field Definitions

### 3.1 Fields present on ALL receipt types

| Field | Type | Signed | Phase | Description |
|---|---|---|---|---|
| `receipt_id` | string (ULID) | yes | 0 | Unique identifier for this receipt. Present on all types. Required for independent addressability (`nonsudo verify <receipt-id>`). |
| `record_type` | enum | yes | 0 | `workflow_manifest \| action_receipt \| workflow_closed` |
| `spec_version` | string | yes | 0 | Protocol version. Value: `"var/1.0"` |
| `workflow_id` | string | yes | 0 | Owning workflow identifier. Always assigned by NonSudo proxy. Format depends on tier: ULID (tier A), HMAC hex (tier B). See Section 10. |
| `workflow_id_source` | enum | yes | 0 | `nonsudo_generated \| framework_mapped \| parent_join` |
| `agent_id` | string | yes | 0 | Stable identifier for the agent. Hash of agent identity + environment. |
| `issued_at` | string (RFC3339) | yes | 0 | UTC timestamp at receipt generation. e.g. `"2026-02-27T10:15:03Z"` |
| `prev_receipt_hash` | string \| null | yes | 0 | SHA-256 of JCS-canonical form of complete previous receipt (including its signature block). null on workflow_manifest. |
| `sequence_number` | integer | yes | 0 | Monotonic counter per workflow_id. Manifest = 0. First action = 1. No gaps. |
| `policy_bundle_hash` | string (SHA-256) | yes | 0 | Hash of the policy bundle in effect when this receipt was generated. |
| `signature` | object | n/a | 0 | See Section 4. Not included in signing payload. |
| `rfc3161_token` | string \| null | no | 0 | Base64-encoded RFC 3161 timestamp token. Always null in Phase 0. Populated by async TSA worker in Phase 1. Present with null value in Phase 0 so that L3: SKIPPED is returned rather than a missing-field error. |
| `tsa_id` | string \| null | no | 0 | Identifies which TSA issued rfc3161_token. Always null in Phase 0. Populated alongside rfc3161_token in Phase 1. |

### 3.2 Fields on `action_receipt` only

| Field | Type | Signed | Phase | Description |
|---|---|---|---|---|
| `tool_name` | string | yes | 0 | MCP tool name exactly as called. |
| `params_canonical_hash` | string (SHA-256) | yes | 0 | SHA-256 of JCS-canonical params. Never raw params. |
| `decision` | enum | yes | 0 | `ALLOW \| BLOCK \| FAIL_OPEN \| FAIL_CLOSED \| STEP_UP`. Note: STEP_UP is a valid field value in Phase 0 receipts but the approval engine that acts on it ships Phase 1. In Phase 0, STEP_UP is treated as BLOCK. |
| `decision_reason` | string | yes | 0 | Human-readable explanation of the decision. |
| `decision_order` | integer | yes | 0 | Position of this call in the per-workflow evaluation queue. Value is `1` when no concurrent calls exist. Resets to `1` for each new batch of concurrent calls. Combined with `state_version_before`/`state_version_after`: if receipt A has `state_version_after=N` and receipt B has `state_version_before=N`, causal order is provable from the receipts alone. |
| `queue_status` | enum | yes | 0 | `COMPLETED \| DEAD_LETTER`. Note: ENQUEUED is a transient in-memory state — it never appears on a signed receipt. A receipt is only signed once evaluation reaches COMPLETED or DEAD_LETTER, at which point `decision` and all other fields are known. |
| `queue_timeout_ms` | integer | yes | 0 | SLA for policy evaluation before dead-letter. Configurable per tool. |
| `blast_radius` | enum | yes | 0 | `LOW \| MED \| HIGH \| CRITICAL` |
| `reversible` | boolean | yes | 0 | Whether the tool action can be undone. |
| `state_version_before` | integer | yes | 0 | Workflow session state version before this evaluation. |
| `state_version_after` | integer | yes | 0 | Workflow session state version after this evaluation. |
| `response_hash` | string \| null | yes | 0 | SHA-256 of tool response. **Always null at signing time in v0.1** — the tool has not yet been called when the receipt is signed. Reserved for a response-binding mechanism in v0.2. Implementations MUST write null here at signing time. |

### 3.3 Additional fields on `action_receipt` when `queue_status` is `DEAD_LETTER`

| Field | Type | Signed | Phase | Description |
|---|---|---|---|---|
| `failure_reason` | string | yes | 0 | What caused the dead-letter (e.g. `"worker_crash"`, `"queue_timeout"`). |
| `fallback_policy` | enum | yes | 0 | `fail_closed \| fail_open`. Which fallback rule applied per policy configuration. |

### 3.4 Fields on `workflow_manifest` only

| Field | Type | Signed | Phase | Description |
|---|---|---|---|---|
| `initiator_id` | string | yes | 0 | Identity of the user or service that initiated the workflow. |
| `workflow_owner` | string | yes | 0 | Team or system that owns this workflow (may differ from initiator_id in automated pipelines). |
| `session_budget` | object | yes | 0 | Budget constraints for this workflow. e.g. `{ "api_calls": 100, "steps": 50 }` |
| `declared_tools` | string[] | yes | 0 | Tool names the agent declared at initialization. |
| `capability_manifest_hash` | string \| null | yes | 0 | SHA-256 of agent capability declaration. null if not provided. |
| `parent_workflow_id` | string \| null | yes | 0 | Present only when `workflow_id_source: parent_join`. The workflow_id of the parent workflow this sub-agent is joining. null otherwise. |
| `framework_ref` | string \| null | yes | 0 | Present only when `workflow_id_source: framework_mapped`. Stores the original upstream run/thread ID (e.g. LangGraph run_id) for correlation. The framework_ref is NOT the workflow_id — it is stored separately so auditors can correlate without reversing the HMAC. null otherwise. |

### 3.5 Fields on `workflow_closed` only

| Field | Type | Signed | Phase | Description |
|---|---|---|---|---|
| `total_calls` | integer | yes | 1 | Total action_receipt records in this workflow. |
| `total_blocked` | integer | yes | 1 | Number of calls with decision BLOCK, FAIL_CLOSED, or STEP_UP (STEP_UP is treated as BLOCK). |
| `total_spend` | number \| null | yes | 1 | Cumulative financial spend if tracked. null otherwise. |
| `session_duration_ms` | integer | yes | 1 | Wall time from workflow_manifest issued_at to workflow_closed issued_at. |
| `close_reason` | enum | yes | 1 | `connection_teardown \| ttl_expired \| explicit_close` |

---

## 4. Signature Block

The `signature` field is a nested object. It is NOT included in the signing payload.

```json
"signature": {
  "alg": "Ed25519",
  "key_id": "nonsudo-key-1",
  "sig": "<base64url-encoded Ed25519 signature>"
}
```

| Subfield | Description |
|---|---|
| `alg` | Signing algorithm. Value in v0.1: `"Ed25519"` always. |
| `key_id` | Identifies which keypair signed this receipt. Required for key rotation without invalidating past receipts. |
| `sig` | Base64url-encoded 64-byte Ed25519 signature over the signing payload (canonical bytes, not the hash). |

---

## 5. Signing Rule

**The signing payload is the JCS-canonical form (RFC 8785) of all fields where `signed = yes` in Section 3.** Fields marked `signed = n/a` or `signed = no` are excluded from the signing payload. `signature` is `n/a` because it is the output of the signing step — it cannot be part of its own input. `rfc3161_token` and `tsa_id` are `no` because they are added post-signing by the TSA worker.

Steps:

1. Construct a JSON object containing only the fields marked `signed = yes` for this receipt's `record_type`.
2. Canonicalize using JCS (RFC 8785): deterministic key ordering, no insignificant whitespace, Unicode normalization per spec.
3. Compute SHA-256 of the canonical bytes. This is an intermediate value used for debugging — it is **not** stored as a receipt field.
4. Sign the canonical bytes (not the hash) with Ed25519.
5. Encode the 64-byte signature as base64url. Store in `signature.sig`.

**Critical:** Use RFC 8785 JCS canonicalization, not `JSON.stringify`. These produce different byte sequences. `JSON.stringify` key order is implementation-defined; JCS key order is lexicographic by Unicode code point. An implementation that uses `JSON.stringify` will produce signatures that fail verification on a different platform.

To validate your JCS implementation before building: test against the vectors in `schemas.nonsudo.dev/var/v1/test-vectors.json` — each vector includes the expected `canonical_form` as hex-encoded bytes.

**Hash encoding:** All SHA-256 hash fields (`prev_receipt_hash`, `params_canonical_hash`, `policy_bundle_hash`, `capability_manifest_hash`, `response_hash`) use the format `sha256:<hex>` where `<hex>` is 64 lowercase hexadecimal characters. Example: `"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`. A verifier MUST reject any hash value that does not match this format.

---

## 6. Chaining Rule

```
prev_receipt_hash = SHA-256( JCS( complete_previous_receipt_object ) )
```

- The hash input is the JCS-canonical form of the **complete** previous receipt object, including its `signature` block and null-valued fields.
- The `workflow_manifest` has `prev_receipt_hash: null` and `sequence_number: 0`.
- Every subsequent receipt has `sequence_number` incremented by exactly 1.
- `sequence_number` gaps are never valid. A gap means a receipt is missing or was deleted. L2 verifier returns `INCOMPLETE_CHAIN`.
- The `workflow_closed` receipt chains to the last receipt in the workflow. If action_receipts exist, it chains to the last one. If no action_receipts exist (workflow opened and immediately closed), it chains to the `workflow_manifest` (sequence_number: 0 → workflow_closed sequence_number: 1).

### Trust Model

RFC 3161 timestamp tokens are stored in a **sidecar file** (`<receipts>.tsa`) rather than inline in the receipt. The sidecar is an append-only NDJSON file: each line is a `TsaRecord` with `receipt_id`, `rfc3161_token` (base64-encoded DER `TimeStampResp`), `tsa_id`, and `timestamped_at`.

L3 verification (`verifyL3`) validates each sidecar entry against its corresponding receipt by:
1. Checking `tsa_id` against the configured `accepting_tsa_ids` allowlist.
2. Parsing the DER bytes as an RFC 3161 `TimeStampResp`.
3. Checking `PKIStatus` is `granted` (0) or `grantedWithMods` (1).
4. Navigating `timeStampToken → SignedData → encapContentInfo → TSTInfo`.
5. Comparing `messageImprint.hashedMessage` with `SHA-256(JCS(complete_signed_receipt))`.

#### L3 Verification States

| Status | Meaning |
|--------|---------|
| `PASS` | TSA token valid, `messageImprint` matches receipt hash, TSA in allowlist |
| `FAIL` | Token invalid, hash mismatch, or TSA not in allowlist |
| `SKIPPED` | No sidecar entry found for this receipt (Phase 0 mode or sidecar absent). Not a verification failure. |
| `PENDING` | Receipt is in an open batch not yet timestamped by a TSA (v1.1 batch mode only). Not a verification failure. |

#### Sidecar Entry Types (v1.0 and v1.1)

In v1.0, all sidecar entries are per-receipt entries. The `entry_type` field is absent on v1.0 entries and is implicitly treated as `"receipt"` by v1.1 verifiers for backward compatibility.

In v1.1, sidecar files may contain two entry types:

**Receipt entry (v1.0 format — backward compatible):**
```json
{
  "receipt_id": "<ulid>",
  "tsa_id": "<tsa-identifier>",
  "rfc3161_token": "<base64-der>"
}
```

**Receipt entry (v1.1 format — batch mode):**
```json
{
  "entry_type": "receipt",
  "receipt_id": "<ulid>",
  "batch_id": "<batch-ulid>",
  "merkle_proof": ["<sha256-hex>", "<sha256-hex>", "..."]
}
```

**Batch entry (v1.1 — one per batch):**
```json
{
  "entry_type": "batch",
  "batch_id": "<batch-ulid>",
  "merkle_root": "<sha256-hex>",
  "tsa_id": "<tsa-identifier>",
  "rfc3161_token": "<base64-der>",
  "receipt_count": "<integer>",
  "closed_at": "<iso8601>"
}
```

In v1.1 batch mode, L3 verification for a receipt proceeds as:

1. Find the receipt's sidecar entry by `receipt_id` — obtain `batch_id` and `merkle_proof`
2. Find the batch entry by `batch_id` — obtain `merkle_root`, `rfc3161_token`, `tsa_id`
3. Verify `tsa_id` against the TSA allowlist
4. Parse `rfc3161_token` DER — verify `PKIStatus: granted`
5. Verify `messageImprint.hashedMessage` == `SHA-256(merkle_root)`
6. Verify `merkle_proof` inclusion: `SHA-256(JCS(signed_receipt))` is a leaf of the Merkle tree with root `merkle_root`

Step 6 uses a standard binary Merkle tree with SHA-256 as the hash function. Leaf hash: `SHA-256(0x00 || SHA-256(JCS(signed_receipt)))`. Internal node hash: `SHA-256(0x01 || left || right)`. The domain separation bytes `0x00` and `0x01` prevent second-preimage attacks.

---

## 7. Verifier Level Definitions

Verification is graduated. An auditor can verify at any level their use case requires.

| Level | Name | What it checks | Phase |
|---|---|---|---|
| **L1** | Signature Valid | Ed25519 signature over signing payload (Section 5) verifies against the public key identified by `key_id`. | 0 |
| **L2** | Chain Intact | `prev_receipt_hash` values form an unbroken hash chain back to `workflow_manifest`. `sequence_number` increments by 1 with no gaps. Gap → `INCOMPLETE_CHAIN` error. | 0 |
| **L3** | Externally Timestamped | `rfc3161_token` is a valid RFC 3161 timestamp token from a trusted TSA. If `rfc3161_token` is null: `L3: SKIPPED — receipt generated before Phase 1 timestamping; not a chain integrity failure`. | 1 |
| **L4** | Merkle Checkpoint | Receipt hash appears in a published Merkle tree checkpoint. (Reserved — not implemented in v0.1.) | future |
| **L5** | Policy Provenance | `policy_bundle_hash` matches a policy bundle in the verifier's known-good archive. (Reserved — not implemented in v0.1.) | future |

**Phase 0 ships L1 + L2.**  
**Phase 1 Day 1 adds L3.**

### L3 TSA allowlist

Enterprises may configure `accepting_tsa_ids: []` to restrict which TSAs are accepted at L3. If `tsa_id` is not in the allowlist:

```
L3: FAIL — TSA not in approved CA list: <tsa_id>
```

Default trusted TSAs: DigiCert, Sectigo, GlobalSign.

### Offline verification

A receipt with a valid `rfc3161_token` can be verified with no NonSudo tooling:

```bash
openssl ts -verify -in token.der -CAfile digicert-tsa.pem
```

Receipts remain verifiable independently of NonSudo's operational status.

---

## 8. Batch Timestamping (v1.1 Design Direction)

Per-receipt RFC 3161 timestamping (v1.0) couples TSA availability to agent execution throughput at high volume. At millions of tool calls per day, per-receipt TSA calls are impractical — each call adds latency and creates an availability dependency on the TSA endpoint.

NonSudo v1.1 introduces Merkle batch timestamping as the scalable alternative:

**Architecture:**
- Every receipt is signed and hash-chained at the edge (L1 + L2) — no change from v1.0
- Receipts are accumulated into time-windowed or count-windowed batches
- A Merkle tree is constructed over the batch — one leaf per receipt,
  leaf value is `SHA-256(JCS(signed_receipt))`
- A single RFC 3161 token is obtained for the Merkle root
- Each receipt's sidecar entry carries a Merkle inclusion proof

**Properties preserved:**
- Independent per-receipt timestamp verification remains possible offline
  (verify the inclusion proof + the batch root token)
- TSA call volume is O(batches) not O(receipts)
- The trust model is unchanged — the TSA still attests to a specific hash
  at a specific time; the hash now commits to a batch of receipts rather than one

**Default batch boundaries:**
- Time window: one batch per minute (configurable)
- Count limit: maximum 10,000 receipts per batch
- Whichever limit is reached first closes the batch

**Verification states under batch mode:**
- `L3: PASS` — receipt is in a closed batch with valid TSA token and valid inclusion proof
- `L3: FAIL` — token invalid, inclusion proof invalid, or TSA not in allowlist
- `L3: PENDING` — receipt is in an open batch not yet timestamped
- `L3: SKIPPED` — no batch record found and no per-receipt sidecar entry (Phase 0 mode)

**v1.0 compatibility:** v1.0 per-receipt sidecar entries are valid indefinitely. v1.1 verifiers check for per-receipt entries first; if absent, check for batch entries. Mixed chains (some receipts per-receipt timestamped, others batch-timestamped) are valid. A receipt with neither is `L3: SKIPPED`.

**Merkle tree construction:** Receipts in a batch are ordered by `sequence_number` within workflow, then by `issued_at` across workflows. Leaf hash: `SHA-256(0x00 || SHA-256(JCS(signed_receipt)))`. Internal node: `SHA-256(0x01 || left || right)`. Domain separation prevents second-preimage attacks (RFC 6962 §2.1).

---

## 9. Dead-Letter Semantics

If a queued tool call exceeds `queue_timeout_ms` or the evaluation worker crashes, the proxy MUST emit a dead-letter `action_receipt` as the next sequence number in the chain. The dead-letter receipt:

- Has `queue_status: DEAD_LETTER`
- Has `decision: FAIL_CLOSED` or `decision: FAIL_OPEN` per policy
- Includes `failure_reason` and `fallback_policy`
- Is signed and chained identically to a normal receipt

Default behaviour: CRITICAL tools → `FAIL_CLOSED`. LOW tools → `FAIL_OPEN`. MED and HIGH → configurable per policy.

`state_version_before` and `state_version_after` on a DEAD_LETTER receipt MUST both equal the state version at enqueue time. No state transition occurred, so before and after are identical.

No tool call goes unrecorded. The dead-letter receipt is the record.

---

## 10. Redaction Rules (Receipt-Only Mode)

Receipt-only mode allows deployment without storing raw tool parameters, for environments with strict data minimisation requirements.

**Redaction rule:** All redaction happens at signing time (pre-signing). Writing `"[redacted]"` as a field value before signing is valid — the signature covers the redacted value and L1 still passes. Replacing a field value with `"[redacted]"` after signing invalidates L1 verification. Post-signing modification of any field is tampering.

| Field | Redaction allowed | Notes |
|---|---|---|
| `params_canonical_hash` | Never redact | Already non-reversible — this is the hash, not the params. |
| Raw params | Never stored by default | Only the hash is stored. Raw params are not part of the receipt schema. |
| `decision_reason` | May be redacted (pre-signing only) | Write `"[redacted]"` as the value before signing. L1 and L2 unaffected. |
| `response_hash` | May be null | If tool response is not captured, null is valid. |
| `framework_ref` | May be redacted (pre-signing only) | Write `"[redacted]"` as the value before signing. L1 and L2 unaffected. |
| All other signed fields | Must not be modified post-signing | Any post-signing modification of a signed field invalidates L1 verification. |

---

## 11. workflow_id Assignment

`workflow_id` is always assigned by the NonSudo proxy. Three tiers:

| Tier | Source | `workflow_id_source` value | `workflow_id` format | Notes |
|---|---|---|---|---|
| A (default) | Proxy generates at workflow initialization (before workflow_manifest is signed) | `nonsudo_generated` | ULID | Works with all frameworks. No configuration required. |
| B (optional) | `HMAC(customer_secret, upstream_run_id)` | `framework_mapped` | Hex string (HMAC output) | Ties to framework's run/thread ID without leaking it. Store original ID in `framework_ref`. Requires config. |
| C (multi-agent) | Parent workflow passes `parent_workflow_id` | `parent_join` | Inherited from parent | Sub-agent joins existing workflow. `parent_workflow_id` stored on manifest. |

`workflow_id` is not under agent or framework control. The proxy is the sole authority.

**Key rotation for tier B:** A new `customer_secret` generates new `workflow_id` values going forward. Receipts issued under the old secret remain valid — they carry `workflow_id_source: framework_mapped` and the old `framework_ref` value. No retroactive re-keying is needed or possible.

---

## 12. Phase 0 vs Phase 1 Summary

| Feature | Phase 0 | Phase 1 Day 1 |
|---|---|---|
| Ed25519 signing | ✓ | ✓ |
| SHA-256 hash chaining | ✓ | ✓ |
| L1 + L2 verification | ✓ | ✓ |
| `rfc3161_token` field | Present, always null | Populated by async TSA worker |
| `tsa_id` field | Present, always null | Populated alongside token |
| L3 verification | Returns SKIPPED | Returns PASS or FAIL |
| `workflow_closed` receipt | TTL-inferred (Redis 24h default) | Emitted explicitly by proxy on connection teardown |
| STEP_UP decision value | Stored in receipt; treated as BLOCK | Triggers Slack/webhook approval engine |

Phase 0 receipts are **tamper-evident but not externally time-attested**.  
Phase 1 receipts are **tamper-evident and externally time-attested**.

Phase 0 receipts verified after Phase 1 ships still pass L1 and L2. L3 returns SKIPPED with annotation. No retroactive invalidation.

---

## 13. Field Name Freeze

The following field names are frozen as of v0.1. Any implementation using the old names is non-conformant.

| Frozen name (v0.1) | Previous name (pre-v0.1) |
|---|---|
| `params_canonical_hash` | `params_hash` |
| `policy_bundle_hash` | `policy_hash` |
| `issued_at` | `timestamp` |
| `prev_receipt_hash` | `prev_hash` |
| `record_type` | `receipt_type` |
| `spec_version` | `schema_version` |

---

## 14. Conformance

An implementation is conformant with VAR v1.0 if and only if:

1. All receipts it generates pass L1 verification against the public key identified by `key_id` in the receipt's `signature` block. Keys are published as JWK (RFC 8037, OKP key type, crv: Ed25519) at `schemas.nonsudo.dev/.well-known/keys/<key_id>.json`. A verifier MUST fetch and cache the key before verifying; it MUST NOT hard-code key material.
2. All receipts it generates pass L2 verification (chain intact, no sequence gaps)
3. All field names match Section 3 exactly (no aliases, no additions without version bump)
4. JCS (RFC 8785) is used for signing payload canonicalization, not `JSON.stringify`
5. All test vectors in `schemas.nonsudo.dev/var/v1/test-vectors.json` produce the expected verification results

---

## 15. Changelog

| Version | Date | Changes |
|---|---|---|
| v1.0 | 2026-02-28 | v1.0 GA release. Pluggable state backend (MemoryWorkflowState default, RedisWorkflowState for production). `nonsudo proxy` CLI subcommand. `spec_version` bumped to `"var/1.0"`. |
| v0.1 | 2026-02-28 | Initial release. Field names frozen. L1–L2 verification defined. L3–L5 reserved. Added `receipt_id` to all receipt types; `parent_workflow_id`, `framework_ref`, `workflow_owner` to workflow_manifest; clarified STEP_UP Phase 0 behaviour; fixed `workflow_id` type annotation for tier B; resolved `response_hash` signed/async contradiction (always null at signing in var/1.0); specified `state_version` behaviour on DEAD_LETTER; added hash encoding format (sha256:<hex>); added public key format (JWK RFC 8037). |

---

*VAR v1.0 Public Contract — NonSudo, Inc. — schemas.nonsudo.dev*
