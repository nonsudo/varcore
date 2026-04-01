# Receipt Types Reference

**VAR v1.0 — 2026-03-02**
**Status:** NORMATIVE — Session A implements all types defined here.

This document is the complete reference for all VAR v1.0 receipt types. The existing
types (`workflow_manifest`, `action_receipt`, `workflow_closed`) are defined in
`docs/reference/contract.md`. This document adds five new types introduced with
VAR-Money v1.0 and the Walk/Run mode enforcement model.

For signing rules, canonicalization, and chain rules, see `docs/reference/contract.md §4–6`.

---

## Existing Types (defined in contract.md)

- `workflow_manifest` — see `contract.md §3.4`
- `action_receipt` — see `contract.md §3.2` and `§3.3`
- `workflow_closed` — see `contract.md §3.5`

---

## New Types (defined here)

### `post_receipt`

Emitted once per money action that produced `decision: ALLOW`. Records the terminal
outcome of the upstream tool call. The `post_receipt` is the second half of the
outcome-binding pair; the first half is the `action_receipt` (pre-receipt).

A `post_receipt` MUST be emitted for every ALLOW'd money action in Walk and Run modes
(RI-1 from `docs/spec/var-core-v1.0.md §3`). The proxy MUST emit the `post_receipt`
regardless of whether the upstream call succeeded or failed.

**Chain position:** Emitted as the next sequence number after the corresponding
`action_receipt`. If concurrent ALLOWs are in flight, `post_receipt` records are emitted
in order of call completion.

| Field | Type | Signed | Nullable | Description |
|-------|------|--------|----------|-------------|
| `post_receipt_id` | string (ULID) | yes | no | Unique identifier for this post-receipt. |
| `record_type` | string | yes | no | Always `"post_receipt"`. |
| `spec_version` | string | yes | no | Always `"var/1.0"`. |
| `pre_receipt_id` | string (ULID) | yes | no | The `receipt_id` of the corresponding `action_receipt`. |
| `workflow_id` | string | yes | no | Must match the `workflow_id` of the corresponding `action_receipt`. |
| `agent_id` | string | yes | no | Must match the `agent_id` of the corresponding `action_receipt`. |
| `sequence_number` | integer | yes | no | Position in the workflow chain. Contiguous with no gaps. |
| `prev_receipt_hash` | string (sha256:hex) | yes | no | SHA-256 of the JCS-canonical complete previous receipt. |
| `policy_bundle_hash` | string (sha256:hex) | yes | no | Must match the `policy_bundle_hash` of the `action_receipt`. |
| `tool_name` | string | yes | no | Must match the `tool_name` of the corresponding `action_receipt`. |
| `terminal_outcome` | enum | yes | no | `SUCCESS \| DENIED \| ESCALATED \| TIMEOUT \| ERROR \| CANCELED` |
| `upstream_response_digest` | string (sha256:hex) | yes | yes | SHA-256 of the JCS-canonical upstream tool response. Null on `TIMEOUT`, `ERROR`, or `CANCELED`. |
| `projection_id` | string | yes | yes | Projection definition ID used to compute `upstream_response_digest`. Null if no projection is defined for this rule. |
| `projection_hash` | string (sha256:hex) | yes | yes | SHA-256 of the projected stable response. Null if `projection_id` is null. See VAR-Money v1.0 §5 and VAR Core v1.0 §5 for projection semantics. |
| `idempotency_key` | string | yes | yes | Value of the idempotency key parameter. Null if `idempotency_key_field` is not declared in the policy rule. |
| `tool_call_correlation_id` | string | yes | yes | Upstream tool call ID for correlation with the tool provider's own logs (e.g. Stripe charge ID). Null if not provided by the tool. |
| `execution_start_ms` | integer | yes | no | Monotonic timestamp (milliseconds) when the upstream call was initiated. |
| `execution_end_ms` | integer | yes | no | Monotonic timestamp (milliseconds) when the upstream call terminated. |
| `degraded_reason` | string | yes | yes | Present when the outcome was influenced by a degraded condition. See VAR Core v1.0 §4 for possible values. Null otherwise. |
| `billable` | boolean | yes | no | Whether this post-receipt is a billable event. See VAR-Money v1.0 §6.1. |
| `billable_reason` | string | yes | no | Human-readable reason for billability classification. |
| `issued_at` | string (ISO 8601) | yes | no | UTC timestamp at receipt generation. |
| `signature` | object | n/a | no | See `contract.md §4`. Not included in signing payload. |
| `rfc3161_token` | string | no | yes | Base64-encoded RFC 3161 TSA token. Null at signing; populated asynchronously. |
| `tsa_id` | string | no | yes | TSA identifier. Null at signing; populated alongside `rfc3161_token`. |

**`terminal_outcome` values:**

| Value | Meaning |
|-------|---------|
| `SUCCESS` | Upstream call completed successfully. |
| `DENIED` | STEP_UP was denied by the approval authority. |
| `ESCALATED` | STEP_UP is pending approval; post-receipt records the escalation event. |
| `TIMEOUT` | Upstream call exceeded `queue_timeout_ms`. `upstream_response_digest` is null. |
| `ERROR` | Upstream call returned an error. `upstream_response_digest` is null. |
| `CANCELED` | Call was canceled before completion (e.g., client disconnected). |

---

### `recovery_event`

Emitted when the proxy restarts and performs an integrity check on the open-pre index
(the set of `action_receipt` records that have no corresponding `post_receipt`). Always
emitted as the first receipt after a restart, before any new `action_receipt` records.

Implements RI-10 from `docs/spec/var-core-v1.0.md §3`.

| Field | Type | Signed | Nullable | Description |
|-------|------|--------|----------|-------------|
| `recovery_event_id` | string (ULID) | yes | no | Unique identifier for this recovery event. |
| `record_type` | string | yes | no | Always `"recovery_event"`. |
| `spec_version` | string | yes | no | Always `"var/1.0"`. |
| `workflow_id` | string | yes | no | Workflow ID this recovery event belongs to. |
| `agent_id` | string | yes | no | Agent identifier. Matches the manifest. |
| `sequence_number` | integer | yes | no | Next sequence number in the chain after restart. |
| `prev_receipt_hash` | string (sha256:hex) | yes | no | SHA-256 of the JCS-canonical last receipt before the crash. |
| `policy_bundle_hash` | string (sha256:hex) | yes | no | Policy bundle hash at restart time. |
| `recovered_open_pres_count` | integer | yes | no | Number of `action_receipt` records found without a corresponding `post_receipt`. |
| `index_status` | enum | yes | no | `OK \| CORRUPT`. `OK`: the recovery integrity check completed without detecting corruption. `CORRUPT`: the recovery integrity check could not confirm clean state. |
| `recovery_method` | enum | yes | no | `INDEX \| CHECKPOINT`. `INDEX`: recovery used the persisted open-pre index directly. `CHECKPOINT`: recovery used the checkpoint-based fallback path. |
| `scan_window_minutes` | integer | yes | yes | Reserved field. Always null in v1.0. |
| `scan_receipts_examined` | integer | yes | yes | Reserved field. Always null in v1.0. |
| `issued_at` | string (ISO 8601) | yes | no | UTC timestamp at receipt generation. |
| `signature` | object | n/a | no | See `contract.md §4`. Not included in signing payload. |
| `rfc3161_token` | string | no | yes | Base64-encoded RFC 3161 TSA token. Null at signing; populated asynchronously. |
| `tsa_id` | string | no | yes | TSA identifier. Null at signing; populated alongside `rfc3161_token`. |

**Verifier behavior:** A `recovery_event` with `index_status: CORRUPT` MUST trigger
L2: WARN — `RECOVERY_INCOMPLETE`. The chain is structurally valid (L2: PASS) but the
verifier must note that outcome completeness cannot be guaranteed for the period before
the crash.

---

### `approval_receipt`

Emitted when an `action_receipt` produces `decision: STEP_UP` and the approval engine
records the final approval outcome for that action.

**Chain position:** Emitted immediately after the `action_receipt` that produced
`decision: STEP_UP`.

| Field | Type | Signed | Nullable | Description |
|-------|------|--------|----------|-------------|
| `receipt_id` | string (ULID) | yes | no | Base receipt identifier for this approval receipt. |
| `record_type` | string | yes | no | Always `"approval_receipt"`. |
| `spec_version` | string | yes | no | Always `"var/1.0"`. |
| `workflow_id` | string | yes | no | Workflow ID shared with the triggering `action_receipt`. |
| `workflow_id_source` | enum | yes | no | `nonsudo_generated \| framework_mapped \| parent_join`. |
| `agent_id` | string | yes | no | Agent identifier. Matches the manifest and triggering receipt. |
| `issued_at` | string (RFC3339) | yes | no | UTC timestamp at receipt generation. |
| `prev_receipt_hash` | string \| null | yes | yes | SHA-256 of the JCS-canonical previous receipt. In practice this chains to the triggering `action_receipt`. |
| `sequence_number` | integer | yes | no | Next sequence number in the workflow chain. |
| `policy_bundle_hash` | string (sha256:hex) | yes | no | Policy bundle hash in effect. |
| `action_receipt_id` | string (ULID) | yes | no | The `receipt_id` of the `action_receipt` that triggered approval. |
| `approval_receipt_id` | string (ULID) | yes | no | Unique ID for this approval receipt. |
| `tool_name` | string | yes | no | Tool name for cross-reference with the triggering receipt. |
| `approval_outcome` | enum | yes | no | `APPROVED \| DENIED \| TIMEOUT`. |
| `approver` | string | yes | yes | Identity of the approver/denier, or null on timeout or unavailable identity. |
| `approval_dir` | string | yes | no | Directory where approval files are polled. |
| `wait_duration_ms` | integer | yes | no | Total time spent waiting for the approval decision, in milliseconds. |
| `signature` | object | n/a | no | See `contract.md §4`. Not included in signing payload. |
| `rfc3161_token` | string | no | yes | Base64-encoded RFC 3161 TSA token. Null at signing; populated asynchronously. |
| `tsa_id` | string | no | yes | TSA identifier. Null at signing; populated alongside `rfc3161_token`. |

**Signing coverage:** The signing payload includes every field marked `Signed = yes`
above. It excludes `signature` because it is the output of signing, and excludes
`rfc3161_token` and `tsa_id` because they are attached after signing by the TSA worker.

---

### `budget_warning`

Emitted when the budget for a money action rule crosses a threshold: 90% of `max_spend`
or 100% of `max_spend`. Emitted in the chain as the next sequence number.

See VAR-Money v1.0 §3.5 for emission conditions.

| Field | Type | Signed | Nullable | Description |
|-------|------|--------|----------|-------------|
| `budget_warning_id` | string (ULID) | yes | no | Unique identifier for this budget warning. |
| `record_type` | string | yes | no | Always `"budget_warning"`. |
| `spec_version` | string | yes | no | Always `"var/1.0"`. |
| `workflow_id` | string | yes | no | Workflow this warning applies to. |
| `agent_id` | string | yes | no | Agent identifier. Matches the manifest. |
| `sequence_number` | integer | yes | no | Next sequence number in the chain. |
| `prev_receipt_hash` | string (sha256:hex) | yes | no | SHA-256 of the JCS-canonical previous receipt. |
| `policy_bundle_hash` | string (sha256:hex) | yes | no | Policy bundle hash in effect. |
| `tool_name` | string | yes | no | The tool name (and governing rule) that triggered the budget check. |
| `spent` | integer | yes | no | Cumulative amount spent at the time of this warning, in minor units. |
| `reserved` | integer | yes | no | Cumulative amount reserved (in-flight ALLOW'd actions awaiting post) at the time of this warning, in minor units. |
| `cap` | integer | yes | no | The `max_spend` value configured in the governing rule, in minor units. |
| `threshold_pct` | integer | yes | no | The threshold that was crossed: `90` or `100`. |
| `issued_at` | string (ISO 8601) | yes | no | UTC timestamp at receipt generation. |
| `signature` | object | n/a | no | See `contract.md §4`. Not included in signing payload. |
| `rfc3161_token` | string | no | yes | Base64-encoded RFC 3161 TSA token. Null at signing; populated asynchronously. |
| `tsa_id` | string | no | yes | TSA identifier. Null at signing; populated alongside `rfc3161_token`. |

**Verifier behavior:** A `budget_warning` with `threshold_pct: 90` produces
L4: WARN — `BUDGET_WARNING`. A `budget_warning` with `threshold_pct: 100` produces
L4: WARN — `BUDGET_CAP_ENFORCED`. Neither causes L4: FAIL.

---

### `reservation_expired`

Emitted when a TIMEOUT-held budget reservation reaches its TTL and is released from the
budget state. The proxy MUST emit this receipt before releasing the amount from `reserved`
so that the release is traceable in the chain.

See VAR-Money v1.0 §3.3 (TTL release) and RI-6 from `docs/spec/var-core-v1.0.md §3`.

| Field | Type | Signed | Nullable | Description |
|-------|------|--------|----------|-------------|
| `reservation_expired_id` | string (ULID) | yes | no | Unique identifier for this reservation expiry receipt. |
| `record_type` | string | yes | no | Always `"reservation_expired"`. |
| `spec_version` | string | yes | no | Always `"var/1.0"`. |
| `workflow_id` | string | yes | no | Workflow this expiry belongs to. |
| `agent_id` | string | yes | no | Agent identifier. Matches the manifest. |
| `sequence_number` | integer | yes | no | Next sequence number in the chain. |
| `prev_receipt_hash` | string (sha256:hex) | yes | no | SHA-256 of the JCS-canonical previous receipt. |
| `policy_bundle_hash` | string (sha256:hex) | yes | no | Policy bundle hash in effect. |
| `pre_receipt_id` | string (ULID) | yes | no | The `receipt_id` of the `action_receipt` that initiated the reservation. |
| `amount_released` | integer | yes | no | Amount released from `reserved`, in minor units. |
| `currency` | string | yes | no | ISO 4217 currency code for the released amount. |
| `reason` | enum | yes | no | `TTL_EXPIRY \| MANUAL_RELEASE`. In v1.0, only `TTL_EXPIRY` is emitted automatically. `MANUAL_RELEASE` is reserved for operator-initiated releases in future versions. |
| `issued_at` | string (ISO 8601) | yes | no | UTC timestamp at receipt generation. |
| `signature` | object | n/a | no | See `contract.md §4`. Not included in signing payload. |
| `rfc3161_token` | string | no | yes | Base64-encoded RFC 3161 TSA token. Null at signing; populated asynchronously. |
| `tsa_id` | string | no | yes | TSA identifier. Null at signing; populated alongside `rfc3161_token`. |

**Verifier behavior:** The L4 verifier MUST account for `reservation_expired` receipts
when reconstructing the budget state timeline. A `reservation_expired` receipt with no
corresponding TIMEOUT `post_receipt` (via `pre_receipt_id`) is L4: FAIL —
`ORPHANED_RESERVATION_EXPIRY`.

---

## Record Types Summary

| `record_type` | Defined In | When Emitted | Billable |
|---------------|-----------|--------------|---------|
| `workflow_manifest` | contract.md §3.4 | Session start (seq 0) | No |
| `action_receipt` | contract.md §3.2, §3.3 | Every tool call evaluation | Conditional |
| `workflow_closed` | contract.md §3.5 | Session end | No |
| `post_receipt` | This document | After every ALLOW'd money action | No |
| `approval_receipt` | This document | Immediately after an `action_receipt` with `decision: STEP_UP` | No |
| `recovery_event` | This document | Proxy restart, before new actions | No |
| `budget_warning` | This document | Budget threshold crossed (90%, 100%) | No |
| `reservation_expired` | This document | TIMEOUT reservation TTL expiry | No |

---

## Signing Rules for New Types

All new types follow the same signing rules as existing types:

1. Construct a JSON object containing only fields where `Signed = yes`.
2. Canonicalize using JCS (RFC 8785).
3. Sign the canonical bytes (not the hash) with Ed25519.
4. Encode the 64-byte signature as base64url. Store in `signature.sig`.

Fields marked `Signed = n/a` (`signature`) are excluded because they are the output of
signing. Fields marked `Signed = no` (`rfc3161_token`, `tsa_id`) are excluded because they
are added post-signing by the TSA worker.

The `prev_receipt_hash` for each new type MUST be computed as:
```
SHA-256(JCS(complete previous receipt object, including its signature block))
```

---

*VAR v1.0 Receipt Types — NonSudo, Inc.*
