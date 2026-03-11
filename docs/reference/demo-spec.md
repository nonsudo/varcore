# NonSudo Demo Spec — `stripe-refunds-loop`

**Status:** DEMO UX SPEC — terminal output is normative for v1.1  
**Audience:** CLI implementers, demo authors, solutions engineers

This document defines the **exact user experience** for the `nonsudo demo stripe-refunds-loop`
command. Every line of terminal output below is **locked**; implementations MUST match it
byte-for-byte (except for ANSI color codes, which are optional).

The demo illustrates:

- VAR-Money v1.0 money actions and budgets.
- A **Velocity Circuit Breaker (VCB)** for Stripe refunds.
- Receipt IDs for each attempt.
- Offline verification output (`nonsudo verify`).
- A human-readable summary with fixed field names.

---

## 1. Invocation

The demo is invoked as:

```bash
nonsudo demo stripe-refunds-loop
```

No additional flags are required. The command runs five synthetic refund attempts against a
mock Stripe server and prints a deterministic transcript.

---

## 2. Expected Terminal Output (Locked)

The following terminal output is the **canonical reference**. Implementations MUST emit
these lines in this exact order with these exact spellings and punctuation.

```text
$ nonsudo demo stripe-refunds-loop

--- VCB CONFIG (stripe-refunds-loop) ---
tool_name: stripe.refund
window_seconds: 60
max_attempts_per_window: 3
max_total_amount_minor: 100000
currency: usd
projection_id: stripe-refund-v1
----------------------------------------

>>> ATTEMPT 1/5
amount_minor: 1000
currency: usd
status_label: ALLOW
status_reason: within_velocity_window
receipt_ids: pre=rcpt_demo_pre_001 post=rcpt_demo_post_001

>>> ATTEMPT 2/5
amount_minor: 1000
currency: usd
status_label: ALLOW
status_reason: within_velocity_window
receipt_ids: pre=rcpt_demo_pre_002 post=rcpt_demo_post_002

>>> ATTEMPT 3/5
amount_minor: 1000
currency: usd
status_label: ALLOW
status_reason: within_velocity_window_at_limit
receipt_ids: pre=rcpt_demo_pre_003 post=rcpt_demo_post_003

>>> ATTEMPT 4/5
amount_minor: 1000
currency: usd
status_label: BLOCKED_BY_VCB
status_reason: velocity_exceeded_window_limit
receipt_ids: pre=rcpt_demo_pre_004 post=rcpt_demo_post_004

>>> ATTEMPT 5/5
amount_minor: 1000
currency: usd
status_label: BLOCKED_BY_VCB
status_reason: duplicate_idempotency_key
receipt_ids: pre=rcpt_demo_pre_005 post=rcpt_demo_post_005

--- VERIFIER OUTPUT (nonsudo verify) ---
workflow_id: wf_demo_stripe_refunds_loop_001
spec_version: var/1.0
mode: walk

L1: PASS
L2: PASS
L3: SKIPPED (no TSA sidecar)
L4: WARN (BUDGET_CAP_ENFORCED, DUPLICATE_IDEMPOTENCY_KEY)

exit_code: 3
-----------------------------------------

--- HUMAN SUMMARY (stripe-refunds-loop) ---
workflow_id: wf_demo_stripe_refunds_loop_001
total_attempts: 5
allowed_attempts: 3
blocked_attempts: 2
blocked_by_vcb: 1
blocked_by_idempotency: 1
total_refunded_minor: 3000
currency: usd
vcb_window_seconds: 60
policy_budget_minor: 100000
projection_id: stripe-refund-v1
-------------------------------------------
```

Notes:

- ANSI colors are permitted, but the **plain text content and line breaks MUST match**.
- `workflow_id` is fixed for this demo and MUST NOT change between runs.
- Receipt IDs are deterministic demo identifiers and do not have to match real receipt IDs.

---

## 3. Demo Semantics

The intended semantics behind the five attempts are:

- Attempts 1–3:
  - Each issues a 1,000 minor-unit refund (`$10.00` if USD).
  - All three are permitted by the VCB (`status_label: ALLOW`).
  - Attempt 3 lands exactly on the configured attempt cap for the 60-second window.
- Attempt 4:
  - Same amount; exceeds the `max_attempts_per_window` threshold.
  - Blocked by the VCB (`status_label: BLOCKED_BY_VCB`).
  - Reason is `velocity_exceeded_window_limit`.
- Attempt 5:
  - Replays the same refund with a duplicate idempotency key.
  - Blocked with `status_reason: duplicate_idempotency_key`.

The verifier output reflects:

- L1 and L2 passing for all receipts.
- L3 being skipped (no TSA sidecar in the demo).
- L4 emitting warnings for:
  - `BUDGET_CAP_ENFORCED` (hitting the velocity/budget threshold).
  - `DUPLICATE_IDEMPOTENCY_KEY` (per RI-7).
- Exit code `3` per VAR Core v1.0 §2.5 (L4 warnings present).

---

## 4. Mock Stripe Server Response Shape (`transfer_funds` Tool)

The demo uses a mock Stripe-like server behind the `transfer_funds` tool. The **response
shape** is fixed and MUST match the following JSON schema (field names and types are
normative; example values are illustrative):

```json
{
  "id": "tr_demo_123456789",
  "object": "transfer",
  "amount": 1000,
  "currency": "usd",
  "source_account": "acct_demo_source_123",
  "destination_account": "acct_demo_destination_456",
  "status": "succeeded",
  "created": 1710000000,
  "reversed": false,
  "metadata": {
    "demo_run_id": "wf_demo_stripe_refunds_loop_001",
    "attempt_index": 1
  }
}
```

Requirements:

- `amount` is expressed in minor units.
- `currency` MUST be lowercase ISO 4217.
- `created` is a Unix timestamp (seconds since epoch).
- `metadata.demo_run_id` MUST match the workflow ID printed in the verifier and human
  summary blocks.

The projection used for outcome binding in the demo MUST include the following **stable
fields** from the mock response:

- `id`
- `amount`
- `currency`
- `source_account`
- `destination_account`
- `status`
- `created`

These fields SHOULD be wired to a projection definition consistent with VAR-Money v1.0
(`to_minor_units`, `lowercase`, `omit_if_null`, etc.), but the exact projection ID for
`transfer_funds` is out of scope for this demo spec.

---

## 5. Operator Expectations

Operators and SREs running the demo SHOULD be able to:

- Confirm that:
  - The VCB configuration block appears exactly as specified.
  - All five attempts and their status labels/reasons match the locked transcript.
  - The verifier output block and human summary block are present and consistent.
- Use the printed `workflow_id` to:
  - Locate the underlying NDJSON receipt chain.
  - Run `nonsudo verify` independently and reproduce the verifier block.

Any deviation from the locked output above indicates a non-conformant demo implementation.

