# VAR Core v1.0 — Normative Specification

**Status:** NORMATIVE — all conformant NonSudo deployments must satisfy this document.
**Supersedes:** Individual sections of `docs/reference/contract.md` where this document is more specific.
**Canonical URL:** `schemas.nonsudo.dev/var/v1.0/spec.md`
**Last updated:** 2026-03-02

---

## 1. Scope and Versioning

This document is VAR Core v1.0. It defines:

- Deployment modes (Crawl, Walk, Run)
- Verification tiers (L1 through L4)
- Receipt invariants (RI-1 through RI-10)
- Degraded mode semantics and normative behavior table
- Projection DSL permitted operations

VAR Core v1.0 applies to **all** NonSudo deployments regardless of vertical. Vertical
extensions — including VAR-Money v1.0 — extend this base without modifying it.

A conformant implementation MUST satisfy all requirements in this document that apply to
its declared deployment mode. Requirements scoped to specific modes (Walk, Run) are not
applicable to Crawl deployments.

Field definitions and signing rules are in `docs/reference/contract.md`. Operational
procedures are in `docs/guides/`. This document defines behavioral rules; it references
field names from contract.md without duplicating their definitions.

### 1.1 Deployment Modes

Three deployment modes define the enforcement contract and identity model:

| Mode | Identity Model | Bypassable | Post-receipts Required | Suitable For |
|------|---------------|------------|----------------------|--------------|
| **Crawl** | Header-asserted agent ID | Yes — proxy is observe-only | No — action receipts only | Observability, audit prototyping |
| **Walk** | Header-asserted agent ID + session provenance via signed manifest | Yes — if agent holds credentials outside the proxy | Yes — for money actions (VAR-Money v1.0) | Production enforcement, compliance |
| **Run** | Workload identity (OIDC / SPIFFE) | No — agent cannot reach upstream without proxy | Yes — for all actions | High-assurance, regulated environments |

**Version scope:**
- Crawl and Walk are production modes in v1.0.
- Run is reserved for v1.1. Implementations MUST NOT declare mode `run` in v1.0.

**Mode declaration:** The deployment mode is declared in `nonsudo.yaml` as `mode: crawl |
walk | run`. If absent, the default is `crawl`. Mode is committed into the
`workflow_manifest` as a signed field.

### 1.2 Spec Version Identifier

Every receipt MUST carry `spec_version: "var/1.0"`. A verifier encountering an unknown
`spec_version` MUST return L1: FAIL with reason `UNKNOWN_SPEC_VERSION` and MUST NOT
attempt further verification.

---

## 2. Verification Tiers

Verification is structured in four independent tiers. Each tier MUST be independently
verifiable offline using only:

- The receipt chain (NDJSON file)
- The applicable public key
- The applicable spec version
- For L3: the TSA sidecar file

A verifier MAY implement any subset of tiers, but MUST accurately report which tiers it
evaluated and which it skipped.

### 2.1 L1 — Cryptographic Integrity

L1 verifies the Ed25519 signature on each individual receipt.

**Requirements:**
- The Ed25519 signature in `signature.sig` MUST be a valid signature over the JCS-canonical
  form of all fields where `signed = yes` in `docs/reference/contract.md §3`.
- The public key MUST be resolved by `key_id` from the verifier's trust store (see
  `docs/guides/trust-model.md §3.2` for resolution order).
- The `key_id` MUST match the pattern `/^[a-zA-Z0-9_-]{1,64}$/`. A receipt with a
  malformed `key_id` MUST fail L1 with reason `INVALID_KEY_ID` without accessing the
  filesystem or network.

**Outcome:**
- `L1: PASS` — all receipts in the chain have valid signatures.
- `L1: FAIL` — at least one receipt has an invalid signature, missing signature block, or
  unresolvable `key_id`.

### 2.2 L2 — Chain Integrity

L2 verifies the structural integrity of the receipt chain after L1 has been applied.
L2 operates on receipts that passed L1; L1-failed receipts are excluded from L2 analysis.

**Requirements:**
- The first receipt in the chain MUST have `record_type: workflow_manifest` and
  `sequence_number: 0`. Violation: `MISSING_MANIFEST`.
- All receipts MUST share the same `workflow_id` as the manifest. Violation:
  `WORKFLOW_ID_MISMATCH`.
- Sequence numbers MUST be consecutive integers starting at 0 with no gaps.
  Violation: `SEQUENCE_ERROR` or `INCOMPLETE_CHAIN`.
- The `prev_receipt_hash` of receipt N MUST equal `SHA-256(JCS(complete receipt N-1))`,
  including the `signature` block and all null-valued fields. Violation: `HASH_MISMATCH`.
- The manifest MUST have `prev_receipt_hash: null`. Violation: `NULL_HASH_EXPECTED`.
- For Walk and Run mode money actions: RI-1 through RI-3 are enforced at L2.

**Warnings (do not cause L2: FAIL but are reported):**
- `DEGRADED_STATE` — state store was unavailable during a recorded action.
- `DEGRADED_APPROVAL` — approval channel was unavailable during a recorded STEP_UP.
- `MONEY_ACTION_TAG_MISSING` — a tool matching a VAR-Money taxonomy pattern was called
  without `money_action: true` in the governing policy rule.
- `DUPLICATE_IDEMPOTENCY_KEY` — same dedupe tuple produced two terminal SUCCESS posts.
- `RECOVERY_INCOMPLETE` — proxy restarted and could not confirm clean pre-receipt state.

**Outcome:**
- `L2: PASS` — chain is structurally intact (with optional warnings).
- `L2: FAIL` — at least one chain integrity violation. Reports the error code and the
  `sequence_number` of the offending receipt.

### 2.3 L3 — Time Integrity

L3 verifies RFC 3161 timestamp tokens from a TSA sidecar file. L3 is optional; absence of
a sidecar is not a failure unless `--require-timestamps` is set.

**Requirements (when a sidecar entry exists for a receipt):**
1. The `tsa_id` in the sidecar entry MUST be in the operator's `accepting_tsa_ids` allowlist.
2. The `TimeStampResp` DER MUST parse successfully.
3. `PKIStatus` MUST be `granted (0)` or `grantedWithMods (1)`.
4. `messageImprint.hashAlgorithm` MUST be SHA-256.
5. `messageImprint.hashedMessage` MUST equal `SHA-256(JCS(complete signed receipt))`.
6. `genTime` in `TSTInfo` MUST be ≥ the receipt's `issued_at`.

**Outcome:**
- `L3: PASS` — all sidecar entries validate.
- `L3: FAIL` — at least one entry is invalid (token parse failure, hash mismatch, TSA not
  in allowlist, invalid PKIStatus).
- `L3: SKIPPED` — no sidecar is present. Not a failure. Does not affect overall pass/fail
  unless `--require-timestamps` is set.
- `L3: PENDING` — receipt is in an open Merkle batch not yet timestamped (v1.1 batch mode).
  Not a failure.

### 2.4 L4 — Outcome Binding

L4 applies only to Walk and Run mode deployments using VAR-Money v1.0. It is `N/A` for
Crawl deployments and for non-money actions in any mode.

**Requirements:**
- Every money action `action_receipt` with `decision: ALLOW` MUST have exactly one terminal
  `post_receipt` (RI-1).
- Budget accounting MUST be consistent at every point in the chain (RI-6).
- Projection hash in `post_receipt.projection_hash` MUST match the recomputed hash using
  the declared projection definition (RI-8).
- Idempotency dedupe tuples MUST be unique for terminal SUCCESS outcomes (RI-7).

**Outcome:**
- `L4: PASS` — all outcome binding requirements are satisfied.
- `L4: FAIL` — a critical invariant is violated (e.g., MISSING_POST_RECEIPT,
  BUDGET_INVARIANT_VIOLATED, PROJECTION_UNRESOLVABLE).
- `L4: WARN` — a non-critical anomaly is present (DUPLICATE_IDEMPOTENCY_KEY,
  BUDGET_WARNING, BUDGET_CAP_ENFORCED).
- `L4: N/A` — no money actions in this chain.

### 2.5 `nonsudo verify` Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | All applicable tiers PASS; chain complete (`workflow_closed` receipt present) |
| `1` | Any tier FAIL (L1, L2, L3, or L4) |
| `2` | Chain open (no `workflow_closed` receipt); all tiers PASS or N/A |
| `3` | L4 WARN only (no failures); chain otherwise valid |

> Exit code `2` applies only to chains without a `workflow_closed` receipt. A proxy that
> shuts down cleanly writes a `workflow_closed` receipt and produces a complete chain —
> exit 0 if all tiers pass. Degraded mode scenarios that include a clean shutdown produce
> exit 0, not exit 2. Exit 2 applies to in-progress sessions, chains exported mid-session,
> or chains where the proxy was killed before writing `workflow_closed`.

Exit code `3` MUST NOT be returned for L1, L2, or L3 issues. Exit code `2` takes
precedence over exit code `3` (chain open is a stronger signal than L4 warnings). Exit
code `1` takes precedence over all others.

---

## 3. Receipt Invariants (RI-1 through RI-10)

Each invariant is stated as a normative requirement using RFC 2119 key words. Verifier
behaviors are stated for each violation.

**RI-1: Money action post-receipt required (Walk/Run only)**

Every money action `action_receipt` with `decision: ALLOW` in Walk or Run mode MUST have
exactly one terminal `post_receipt` with a matching `pre_receipt_id`.

*Verifier behavior:* L4: FAIL — `MISSING_POST_RECEIPT` if the chain contains an ALLOW
money action with no corresponding `post_receipt`.

---

**RI-2: Null digest on TIMEOUT/ERROR is valid**

A `post_receipt` with `terminal_outcome: TIMEOUT`, `terminal_outcome: ERROR`, or
`terminal_outcome: CANCELED` MAY have `upstream_response_digest: null`. This is not a
chain error.

*Verifier behavior:* L4: PASS — null digest on these terminal outcomes is explicitly valid
and MUST NOT be flagged as a violation.

---

**RI-3: Every terminal proxy state MUST produce a receipt**

No receipt never happens. Every terminal proxy state (ALLOW, BLOCK, FAIL_OPEN,
FAIL_CLOSED, STEP_UP, DEAD_LETTER) MUST produce a signed `action_receipt` or
`post_receipt` as applicable. A proxy that cannot write a receipt MUST fail closed and
refuse to execute the tool call.

*Verifier behavior:* None — this is a proxy implementation requirement. Gaps in the hash
chain detected by L2 (`INCOMPLETE_CHAIN`) are evidence of a violation.

---

**RI-4: Missing amount field requires STEP_UP**

A money action where the `amount_field` parameter is absent, non-numeric, or cannot be
resolved MUST produce `decision: STEP_UP` with `degraded_reason: AMOUNT_FIELD_UNRESOLVABLE`.
The proxy MUST NOT proceed to the tool call.

*Verifier behavior:* L4: FAIL if a money action has `decision: ALLOW` without amount
validation evidence.

---

**RI-5: Invalid amounts require DENY**

A money action with amount < 0 MUST produce `decision: BLOCK`. A money action with amount
`NaN` or `Infinity` MUST produce `decision: BLOCK`. Negative zero (`-0`) is treated as 0
and is not subject to this rule.

*Verifier behavior:* L4: FAIL if a money action with a negative or non-finite amount
produced `decision: ALLOW`.

---

**RI-6: Budget enforcement must be checked before ALLOW**

Budget enforcement MUST check `spent + reserved ≤ cap` before emitting `decision: ALLOW`
on any money action. Budget state transitions:

- `ALLOW` issued → reserve the action amount.
- `post_receipt.terminal_outcome: SUCCESS` → move from reserved to spent.
- `post_receipt.terminal_outcome: PENDING` → keep in reserved.
- `post_receipt.terminal_outcome: FAILED` or `CANCELED` → release from reserved.
- `post_receipt.terminal_outcome: TIMEOUT` → keep in reserved until TTL expiry.
- `RESERVATION_EXPIRED` receipt emitted → release from reserved.

*Verifier behavior:* L4: FAIL — `BUDGET_INVARIANT_VIOLATED` if accounting at any point in
the chain is inconsistent with the above transitions.

---

**RI-7: Idempotency dedupe scope**

Idempotency deduplication scope is the tuple: `(tool_name, action_type,
idempotency_key, account_context)`. Two terminal `post_receipt` records sharing the same
dedupe tuple with `terminal_outcome: SUCCESS` MUST NOT increase `spent` or `reserved` for
the second occurrence. The second SUCCESS MUST be recorded and flagged.

*Verifier behavior:* L4: WARN — `DUPLICATE_IDEMPOTENCY_KEY` if two terminal SUCCESS posts
share the same dedupe tuple.

---

**RI-8: Projection evaluation order**

Projection evaluation MUST apply operations in this order:

1. Apply `omit_if_null` to all declared fields — produce filtered object.
2. Apply remaining transforms in declaration order.
3. Apply JCS canonicalization (RFC 8785) to the result.
4. Compute SHA-256 of the canonical bytes → `upstream_response_digest`.

The verifier MUST implement the same transform set. A verifier that cannot evaluate a
projection MUST return L4: FAIL — `PROJECTION_UNRESOLVABLE`.

*Verifier behavior:* L4: FAIL — `PROJECTION_HASH_MISMATCH` if the recomputed hash does
not match `post_receipt.projection_hash`.

---

**RI-9: Proxy crash semantics by mode**

| Mode | Money actions | Read-only actions |
|------|--------------|-------------------|
| Walk | FAIL CLOSED — proxy refuses to execute and emits a dead-letter receipt on recovery | FAIL OPEN — pass-through; no receipt on crash |
| Crawl | FAIL OPEN always | FAIL OPEN always |
| Run | FAIL CLOSED always | FAIL CLOSED always |

A proxy recovering from a crash MUST emit a `recovery_event` receipt before resuming
normal operation.

*Verifier behavior:* L2: WARN — `RECOVERY_INCOMPLETE` if a `recovery_event` receipt is
present and `index_status: REBUILT` or `CORRUPT`.

---

**RI-10: Post-restart index integrity check**

On proxy restart, the open-pre index (set of action_receipts awaiting a post_receipt)
MUST be integrity-checked. If the index is invalid: perform a bounded scan — last 30
minutes OR last 1000 receipts, whichever is smaller. If the scan is insufficient to
confirm clean state: emit a `RECOVERY_INCOMPLETE` `recovery_event` receipt and require
`STEP_UP` for all money actions until a clean session starts.

*Verifier behavior:* L2: WARN — `RECOVERY_INCOMPLETE` if a `recovery_event` receipt with
`index_status: CORRUPT` is present in the chain.

---

## 4. Degraded Mode Normative Table

Each row defines a failure mode, the required proxy decision, the receipts that MUST be
written, and the verifier output.

| Failure Trigger | Decision Rule | Required Receipts | Verifier Output |
|----------------|---------------|-------------------|-----------------|
| **State store unavailable** — state operation exceeds 20 ms or returns an error | Apply local caps; money actions above local threshold → STEP_UP | `action_receipt` (pre) with `degraded_reason: STATE_UNAVAILABLE`; terminal `post_receipt` MUST exist | L2: PASS + `DEGRADED_STATE` warning |
| **Approval channel down** — webhook timeout > 5 s | STEP_UP → treat as DENIED | `action_receipt` (STEP_UP pre) + `post_receipt` (DENIED) with `degraded_reason: APPROVAL_CHANNEL_DOWN` | L2: PASS + `DEGRADED_APPROVAL` warning |
| **TSA unavailable** — TSA request fails or times out | Non-blocking; do not block the tool call | No change to pre/post receipts; sidecar entry absent or PENDING | L3: SKIPPED or L3: PENDING (not a failure) |
| **Taxonomy unavailable** — VAR-Money taxonomy network fetch fails at startup | Continue with last cached taxonomy; if no cache, disable taxonomy warnings for the session | `workflow_manifest` carries `taxonomy_status: CACHED` or `taxonomy_status: UNAVAILABLE` | L2: WARN — `TAXONOMY_CACHED` if cached; no warning if UNAVAILABLE (no baseline to compare) |
| **Queue worker crash** — evaluation worker process exits | In-flight actions get terminal `post_receipt` with `terminal_outcome: TIMEOUT` on recovery | `post_receipt` (TIMEOUT) emitted at restart for each orphaned `action_receipt` | L2: PASS |
| **Proxy process crash** — SIGKILL or OOM | Walk money actions: FAIL CLOSED; read-only: pass-through; Crawl: pass-through | `recovery_event` receipt + `post_receipt` (CANCELED) for each orphaned pre-receipt | L2: PASS + `CRASH_RECOVERY` note |
| **Budget cap at 90%** — `spent + reserved ≥ 0.9 × cap` | Emit warning receipt; continue normal policy enforcement | `budget_warning` receipt (signed, `threshold_pct: 90`) | L4: WARN — `BUDGET_WARNING` |
| **Budget cap at 100%** — `spent + reserved ≥ cap` | All money actions require STEP_UP regardless of policy rule | `action_receipt` (STEP_UP) for every subsequent money action | L4: WARN — `BUDGET_CAP_ENFORCED` |

---

## 5. Projection DSL

The Projection DSL defines how the proxy extracts a stable, reproducible digest from a
tool response. The digest (`upstream_response_digest`) is signed into the `post_receipt`
and is the basis for L4 outcome binding verification.

### 5.1 Permitted Operations

The following operations are permitted in v1.0. No other operations are valid.

| Operation | Arguments | Description |
|-----------|-----------|-------------|
| `omit_if_null` | `field: string` | Exclude the field from projection output if its value is `null` or absent. Applied in step 1 of evaluation order (RI-8). |
| `to_minor_units` | `field: string`, `currency_field: string` | Convert a decimal amount to integer minor units. The currency is read from `currency_field` to determine the exponent (e.g., USD → multiply by 100). |
| `lowercase` | `field: string` | Normalize the string value of `field` to lowercase. Applies only to string fields; non-string values MUST cause L4: FAIL — `PROJECTION_TYPE_ERROR`. |
| `sort_array_by_key` | `field: string`, `key: string` | Sort an array of objects by a specified key in ascending order. Objects without the key are sorted last. |

### 5.2 Explicitly Prohibited Operations

The following are normatively prohibited. An implementation encountering any of these in a
projection definition MUST return L4: FAIL — `PROJECTION_PROHIBITED_OPERATION` and MUST
NOT execute the operation.

- `eval`, `vm`, `Function`, or any form of dynamic code execution
- JSONPath expressions (patterns containing `$`, `@`, `..`, `[*]`, etc.)
- Regex transform operations
- Floating-point arithmetic (use `to_minor_units` instead)
- Network calls of any kind

### 5.3 Evaluation Order (Normative)

1. Apply `omit_if_null` to all declared fields — produce a filtered object containing only
   non-null fields.
2. Apply remaining transforms in the order declared in the projection definition.
3. Apply JCS canonicalization (RFC 8785) to the result.
4. Compute SHA-256 of the canonical bytes.
5. Encode as `sha256:<hex>` → store as `upstream_response_digest` in the `post_receipt`.

A verifier implementing outcome binding MUST implement this exact evaluation order. An
implementation that applies transforms before omit_if_null, or that varies from JCS
canonicalization, produces different digests and MUST return L4: FAIL.

### 5.4 Verifier Obligations

A verifier that cannot parse a projection definition MUST return L4: FAIL —
`PROJECTION_UNRESOLVABLE`.

A verifier that can parse the definition but encounters an unknown operation MUST return
L4: FAIL — `PROJECTION_UNKNOWN_OPERATION`.

A verifier that evaluates the projection but obtains a different digest than the one in
`post_receipt.projection_hash` MUST return L4: FAIL — `PROJECTION_HASH_MISMATCH`.

---

## 6. Conformance

A deployment is conformant with VAR Core v1.0 if and only if:

1. All receipts it generates pass L1 verification using the public key identified by
   `key_id` in the `signature` block.
2. All receipts it generates pass L2 verification (chain intact, no sequence gaps).
3. All field names match `docs/reference/contract.md §3` exactly.
4. JCS (RFC 8785) is used for signing payload canonicalization.
5. The proxy implements the degraded-mode behaviors specified in Section 4.
6. For Walk/Run deployments with VAR-Money v1.0: RI-1 through RI-10 are satisfied.
7. All test vectors in the published conformance suite produce the expected results.

A Crawl deployment that satisfies requirements 1–4 and 7 is conformant. RI-1 through RI-10
and the degraded-mode behaviors for money actions are not applicable to Crawl deployments.

---

*VAR Core v1.0 — NonSudo, Inc. — schemas.nonsudo.dev/var/v1.0/spec.md*
