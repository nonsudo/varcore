# VAR-Money v1.0 — Normative Specification

**Status:** NORMATIVE — applies to deployments with `var_money_version: "1.0"`.
**Extends:** VAR Core v1.0 (`docs/spec/var-core-v1.0.md`)
**Canonical URL:** `schemas.nonsudo.dev/var-money/v1.0/spec.md`
**Last updated:** 2026-03-02

---

## 1. Scope

VAR-Money v1.0 extends VAR Core v1.0 with semantics for money-moving tool calls:

- Action tagging (identifying which tool calls are money actions)
- Budget enforcement (tracking and capping spend per session/day/month)
- Outcome binding (verifiable post-receipt for every money action)
- Idempotency deduplication (preventing double-spend on replayed calls)

Policy bundles that set `var_money_version: "1.0"` MUST conform to this document and
to VAR Core v1.0. A deployment that sets `var_money_version` but not `var_core_version`
is non-conformant.

**Mode applicability:** VAR-Money v1.0 is applicable to Walk and Run mode deployments.
Crawl mode deployments MUST NOT set `var_money_version`; money action semantics are
undefined in observe-only mode.

---

## 2. Money Action Definition

A tool call is a **money action** if any of the following conditions is true:

1. The policy rule governing it has `money_action: true`, OR
2. The tool name matches a pattern in the VAR-Money v1.0 default taxonomy (Section 2.1)
   AND the policy bundle has `var_money_version: "1.0"` set.

Both conditions may be true simultaneously; the result is the same.

### 2.1 Default Taxonomy Patterns (v1.0)

The following glob patterns define money actions by default. Pattern matching is
case-insensitive and applies to the full tool name string.

```
*refund*
*chargeback*
*transfer*
*payout*
*withdrawal*
*disbursement*
*settle*
*void_payment*
*reverse_payment*
```

Taxonomy patterns are loaded at proxy startup from the canonical taxonomy manifest at
`schemas.nonsudo.dev/var-money/v1.0/taxonomy.json`. Failure to load is handled per the
degraded mode table in VAR Core v1.0 §4.

### 2.2 Missing Tag Warning

If a tool name matches a taxonomy pattern and the governing policy rule does NOT have
`money_action: true`, the verifier MUST emit L2: WARN — `MONEY_ACTION_TAG_MISSING`.
This warning does not cause L2: FAIL.

### 2.3 Explicit Override

To declare that a taxonomy-matched tool name is NOT a money action, the policy rule MUST
set `unsafe_override: true`. This field is signed into the `workflow_manifest` as
`money_action_overrides: string[]`. The verifier records the override and does not emit
a `MONEY_ACTION_TAG_MISSING` warning. The name `unsafe_override` is intentional — it
exists to prevent accidental silencing of taxonomy warnings.

---

## 3. Budget Enforcement Model

### 3.1 Policy YAML Fields

The following fields govern budget enforcement for a money action rule:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `max_spend` | Yes (money actions) | — | Maximum cumulative spend in minor units for this rule's `spend_window`. |
| `spend_window` | No | `session` | Accounting window: `session`, `daily`, or `monthly`. |
| `amount_field` | Yes (money actions) | — | Parameter field containing the action amount. |
| `currency_field` | Yes (money actions) | — | Parameter field containing the ISO 4217 currency code. |
| `idempotency_key_field` | No | — | Parameter field containing the idempotency key. If absent, deduplication is best-effort. |
| `reservation_ttl_hours` | No | `24` | Hours before a TIMEOUT-held reservation is automatically released. |
| `monthly_cap` | No | — | Separate monthly ceiling in minor units. Enforced independently of `max_spend` and `spend_window`. |

### 3.2 Budget State

Budget state is maintained in-memory per `spend_window`:

| State Variable | Description |
|---------------|-------------|
| `spent` | Sum of minor units from terminal `post_receipt` records with `terminal_outcome: SUCCESS`. |
| `reserved` | Sum of minor units from in-flight ALLOWed money actions awaiting a terminal `post_receipt`. |

**Enforcement invariant:** The proxy MUST check `spent + reserved ≤ max_spend` before
emitting `decision: ALLOW` on any money action (RI-6).

### 3.3 State Transitions

| Event | Effect on Budget State |
|-------|----------------------|
| `action_receipt` with `decision: ALLOW` emitted | Reserve amount: `reserved += amount` |
| `post_receipt` with `terminal_outcome: SUCCESS` | Commit: `reserved -= amount; spent += amount` |
| `post_receipt` with `terminal_outcome: PENDING` | Keep in reserved: no change |
| `post_receipt` with `terminal_outcome: FAILED` | Release: `reserved -= amount` |
| `post_receipt` with `terminal_outcome: CANCELED` | Release: `reserved -= amount` |
| `post_receipt` with `terminal_outcome: TIMEOUT` | Keep in reserved until TTL |
| `RESERVATION_EXPIRED` receipt emitted at TTL | Release: `reserved -= amount` |

**TTL duration:** Configurable via `reservation_ttl_hours`. Default: 24 hours. On TTL
expiry, the proxy MUST emit a signed `RESERVATION_EXPIRED` receipt before releasing the
reservation from the budget state.

### 3.4 Amount Validation

Amount validation MUST be applied before the budget check and before the policy decision.
Validation rules (in order):

1. If `amount_field` is absent from the tool call parameters → produce `decision: STEP_UP`
   with `degraded_reason: AMOUNT_FIELD_UNRESOLVABLE`. Do not proceed to budget check.
2. If `amount_field` value is non-numeric → same as absent: STEP_UP with
   `AMOUNT_FIELD_UNRESOLVABLE`.
3. If amount < 0 → produce `decision: BLOCK`.
4. If amount is `NaN` or `Infinity` → produce `decision: BLOCK`.
5. All amounts MUST be provided in minor units in request parameters for v1.0. The proxy
   MUST NOT perform currency conversion; conversion is the caller's responsibility.

### 3.5 Budget Cap Warnings

When `spent + reserved ≥ 0.9 × max_spend`, the proxy MUST emit a signed `budget_warning`
receipt with `threshold_pct: 90`. This is L4: WARN — `BUDGET_WARNING`.

When `spent + reserved ≥ max_spend`, ALL subsequent money actions require `decision:
STEP_UP` regardless of policy rules. The proxy MUST emit `budget_warning` with
`threshold_pct: 100`. This is L4: WARN — `BUDGET_CAP_ENFORCED`.

The monthly cap (`monthly_cap`) is enforced independently. When the monthly accumulation
equals or exceeds `monthly_cap`, the same 100% rule applies.

---

## 4. Idempotency Deduplication

### 4.1 Dedupe Scope

The idempotency deduplication scope is the tuple:

```
(tool_name, action_type, idempotency_key, account_context)
```

| Tuple Element | Source |
|--------------|--------|
| `tool_name` | The MCP tool name exactly as called |
| `action_type` | Always `"money_action"` for money actions in v1.0 |
| `idempotency_key` | Value of the parameter named in `idempotency_key_field` |
| `account_context` | Value of the parameter named in `account_context_field` |

`account_context` is an operator-defined identifier that scopes deduplication to a
specific account (e.g., Stripe account ID, tenant ID). Declared in the policy rule as
`account_context_field: "<param_name>"`.

### 4.2 Deduplication Behavior

If `idempotency_key_field` is not declared in the governing policy rule, deduplication is
best-effort. No `DUPLICATE_IDEMPOTENCY_KEY` warnings are emitted.

If two terminal `post_receipt` records share the same dedupe tuple with
`terminal_outcome: SUCCESS`:

1. The second SUCCESS MUST NOT increase `spent` or `reserved`.
2. The proxy MUST record the duplicate and emit L4: WARN — `DUPLICATE_IDEMPOTENCY_KEY`.
3. The verifier MUST flag this condition in the L4 report.

---

## 5. Stripe Refund Outcome Projection (Reference Implementation)

This projection defines the stable response digest for Stripe refund tool calls. Operators
reference it in their policy bundle as `projection_id: "stripe-refund-v1"`.

```json
{
  "projection_id": "stripe-refund-v1",
  "spec_version": "var-money-1.0",
  "tool_pattern": "*refund*",
  "stable_fields": [
    "id",
    "amount",
    "currency",
    "charge",
    "payment_intent",
    "status",
    "created"
  ],
  "transforms": [
    { "op": "omit_if_null", "field": "charge" },
    { "op": "omit_if_null", "field": "payment_intent" },
    { "op": "to_minor_units", "field": "amount", "currency_field": "currency" },
    { "op": "lowercase", "field": "currency" },
    { "op": "lowercase", "field": "status" }
  ]
}
```

**Fields excluded from projection (normative for Stripe refunds):** `metadata`,
`reason`, `receipt_number`, `source_transfer_reversal`, `transfer_reversal`,
any expanded sub-objects (e.g., expanded `charge` object, expanded
`payment_intent` object).

Only the scalar `charge` and `payment_intent` ID strings are included when non-null.

**Evaluation trace for a representative Stripe refund response:**

```
Input fields:   id, amount, currency, charge, payment_intent, status, created
Step 1 (omit_if_null charge):         include (non-null)
Step 1 (omit_if_null payment_intent): include (non-null)
Step 2 (to_minor_units amount):       e.g. 10.00 USD → 1000
Step 2 (lowercase currency):          "USD" → "usd"
Step 2 (lowercase status):            "succeeded" → "succeeded"
Step 3 (JCS canonicalize):            lexicographic key order, no whitespace
Step 4 (SHA-256):                     → upstream_response_digest
```

The verifier MUST apply the identical evaluation trace. Any deviation produces a different
digest and MUST result in L4: FAIL — `PROJECTION_HASH_MISMATCH`.

---

## 6. Billable Action Definition

A receipt is **billable** if it represents a terminal pre-decision on a money action
and `billable: true` is present in the receipt.

### 6.1 Billable Events

| Event | Billable | Reason |
|-------|----------|--------|
| ALLOW on money action | Yes | Policy enforcement: action authorized |
| DENY/BLOCK on money action | Yes | Policy enforcement: action denied |
| STEP_UP on money action | Yes | Policy enforcement: approval required |
| BLOCK (velocity_exceeded) on money action | Yes | VCB enforcement: circuit breaker triggered |
| BLOCK (proxy_guard) on any action | No | Proxy guard: not policy enforcement |
| BLOCK (declared_tools_unavailable) on any action | No | Degraded session: proxy cannot operate |
| Crawl mode, any action | No | Observe-only: no enforcement |
| Read-only tool calls | No | Not a money action |
| Approval resolution events (post-STEP_UP) | No | Outcome only, billed on STEP_UP |

**Billing principle:** Bill on attempt, not on approval resolution. If a STEP_UP becomes
ALLOW after human approval, the billing event is the STEP_UP `action_receipt`
(pre-receipt). The `post_receipt` records the outcome. No double counting.

### 6.2 Overage Billing

Budget warnings and cap enforcement (Section 3.5) do not create additional billable events.
They are operational receipts (`budget_warning` type) that record budget state transitions.

---

## 7. Conformance

A deployment is conformant with VAR-Money v1.0 if and only if it satisfies VAR Core v1.0
conformance requirements AND:

1. Money actions are correctly identified per Section 2.
2. Amount validation is applied before budget enforcement per Section 3.4.
3. Budget state transitions follow Section 3.3 exactly.
4. Every ALLOW'd money action has a corresponding `post_receipt` (RI-1 from VAR Core v1.0).
5. Idempotency deduplication is implemented per Section 4 when `idempotency_key_field` is
   declared.
6. Projection evaluation follows the order in VAR Core v1.0 §5.3 exactly.
7. `budget_warning` receipts are emitted at 90% and 100% thresholds per Section 3.5.
8. `RESERVATION_EXPIRED` receipts are emitted at TTL expiry per Section 3.3.

---

*VAR-Money v1.0 — NonSudo, Inc. — schemas.nonsudo.dev/var-money/v1.0/spec.md*
