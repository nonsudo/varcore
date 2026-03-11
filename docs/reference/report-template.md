# NonSudo Report Template — `nonsudo report --workflow <id>`

> This template reflects the output of `nonsudo report --workflow <id>` as implemented in Session D.
> It is the authoritative reference for the report format. If the implementation and this document
> conflict, this document must be updated to match the implementation — not the reverse.
> Last updated: Session D.

**Status:** REPORT STRUCTURE SPEC — matches `packages/cli/src/commands/report.ts` (file-based mode)  
**Audience:** CLI implementers, SREs, auditors

This document defines the **canonical Markdown structure** produced by:

```bash
nonsudo report --workflow <id>
```

Optional flags: `--receipts <path>` (receipts directory; default `~/.nonsudo/receipts/`), `--output <path>` (write to file), `--policy <path>` (policy file for L4 budget verification).

Sections appear in this fixed order:

1. Report title and header block  
2. Executive Summary  
3. Enforcement Outcomes  
4. Budget  
5. Verification  
6. Artifact References  
7. Degraded Events  

Headings, table columns, and conditional text below are **normative** and must match the implementation verbatim.

---

## Report title and header block

The report begins with a level-1 heading and four bold key-value lines.

- **Heading:** exactly `# NonSudo Enforcement Report`
- **Header lines** (in order):
  - `**Workflow:**` followed by the workflow ID
  - `**Generated:**` followed by an ISO 8601 timestamp (e.g. from `new Date().toISOString()`)
  - `**Policy hash:**` followed by the manifest `policy_bundle_hash`
  - `**Mode:**` followed by the manifest `mode` (e.g. `walk`)

A blank line and a horizontal rule `---` follow before the next section.

---

## Executive Summary

- **Heading:** exactly `## Executive Summary`

The section contains a short narrative (four sentences):

1. `<N> tool call attempt(s) were made in this session under policy <first 16 chars of policy_bundle_hash>.`
2. `<allowed> were allowed and executed. <blocked> were blocked before reaching the upstream.`
3. `<amount_processed> USD was processed. <amount_protected> USD was prevented by enforcement.`  
   Amounts are formatted from `amount_minor_units` (divide by 100 for two decimals; USD as `$X.XX`). If non-USD currency, the raw currency code is used instead of `$`.
4. `The receipt chain is cryptographically verified: L1 PASS, L2 <PASS|FAIL>, L4 <status>.`  
   L2 and L4 reflect the result of `verifyChain` and the L4 outcome (or WARN when `--policy` not provided).

**Normative definitions (as implemented):**

- **amount_processed:** Sum of `amount_minor_units` from every `action_receipt` where `money_action === true` and `decision === "ALLOW"`.
- **amount_protected:** Sum of `amount_minor_units` from every `action_receipt` where `money_action === true` and the upstream was **not** called. Upstream was not called when any of the following holds:
  - `upstream_call_initiated === false`
  - `decision === "BLOCK"`
  - `queue_status === "DEAD_LETTER"`

---

## Enforcement Outcomes

- **Heading:** exactly `## Enforcement Outcomes`

A Markdown table with **six columns** and these exact headers:

| Column    | Header      |
|-----------|-------------|
| 1         | `#`         |
| 2         | `Tool`      |
| 3         | `Decision`  |
| 4         | `Reason`    |
| 5         | `Amount`    |
| 6         | `Receipt ID`|

Separator row: `|---|------|----------|--------|--------|------------|`

- **#:** Row number (1-based) for each `action_receipt`.
- **Tool:** `tool_name` from the action_receipt (or `—` if missing).
- **Decision:** For COMPLETED receipts, the `decision` value; for DEAD_LETTER, the literal `DEAD_LETTER`.
- **Reason:** `decision_reason`, or `failure_reason` when present; if the value is `velocity_limit_exceeded` it is displayed as `velocity_exceeded`.
- **Amount:** From `amount_minor_units` and optional `currency`: if null, `—`; otherwise minor units divided by 100, formatted as `$X.XX` for USD or `<value> <currency>` for other currencies.
- **Receipt ID:** First 12 characters of the receipt ID, or full ID if 12 or fewer characters; suffix `...` when truncated.

Row order follows the order of `action_receipt` entries in the receipt chain.

---

## Budget

- **Heading:** exactly `## Budget`

**Conditional behavior:**

- If there are **no** action_receipts with `money_action === true`, the section contains exactly one line of text:
  - `No money actions recorded.`
- Otherwise, a Markdown table is shown:

| Column | Header     |
|--------|------------|
| 1      | `Metric`   |
| 2      | `Value`    |

Separator: `|--------|-------|`

Rows (in order): **Cap**, **Processed**, **Protected**, **Remaining**. Values are formatted as amount + ` USD` (e.g. `$500.00 USD`). Cap is a fixed default in the current implementation (e.g. 50000 minor units); Processed and Protected use the normative definitions above; Remaining is derived from the cap and processed amount.

---

## Verification

- **Heading:** exactly `## Verification`

A Markdown table with **three columns** and these exact headers:

| Column | Header   |
|--------|----------|
| 1      | `Tier`   |
| 2      | `Status` |
| 3      | `Detail` |

Separator: `|------|--------|--------|`

**Rows (in order):**

1. **L1 Cryptographic integrity**  
   Status: `PASS` or `FAIL`.  
   Detail: `All signatures valid` when PASS, `Signature failure` when FAIL.

2. **L2 Chain integrity**  
   Status: `PASS` or `FAIL`.  
   Detail: `No gaps, manifest-first` when PASS, `Chain error` when FAIL.

3. **L3 Timestamp**  
   Status: `SKIPPED` or the L3 result status.  
   Detail: `No TSA sidecar` when SKIPPED, otherwise the L3 reason string (or empty).

4. **L4 Outcome binding**  
   Status and Detail depend on whether `--policy` was provided and on the result of `verifyL4`:
   - **When `--policy` is not provided:** Status is `WARN`, Detail is exactly `policy not provided, budget check skipped`.
   - When `--policy` is provided: Status may be `N/A`, `PASS`, `WARN`, or `FAIL`; Detail is `No money actions in chain` for N/A, `All money actions have terminal posts` for PASS, or the violation message(s) for WARN/FAIL.

---

## Artifact References

- **Heading:** exactly `## Artifact References`

A Markdown table with **two columns** and these exact headers:

| Column | Header   |
|--------|----------|
| 1      | `Artifact` |
| 2      | `Value`    |

Separator: `|----------|-------|`

Rows (in order):

| Artifact          | Value source                                      |
|-------------------|---------------------------------------------------|
| Receipt file      | Path to the NDJSON receipt file used for the report |
| Policy hash       | Full `policy_bundle_hash` from the manifest       |
| Key ID            | `key_id` from the manifest (first receipt’s signature) |
| Manifest receipt  | Receipt ID of the first receipt (workflow_manifest) |
| Chain length      | Total number of receipts in the chain             |

---

## Degraded Events

- **Heading:** exactly `## Degraded Events`

**Conditional behavior:**

- If there are **no** receipts with `record_type` in `recovery_event`, `budget_warning`, or `reservation_expired`, the section contains exactly one line:
  - `No degraded events recorded.`
- Otherwise, a Markdown table is shown with these exact headers:

| Column     | Header      |
|------------|-------------|
| 1          | `Receipt ID`|
| 2          | `Type`      |
| 3          | `Reason`    |
| 4          | `Sequence`  |

Separator: `|------------|------|--------|----------|`

Each row corresponds to one degraded receipt. **Receipt ID** is the receipt’s primary ID (`recovery_event_id`, `budget_warning_id`, `reservation_expired_id`, or `receipt_id` as applicable). **Type** is the `record_type`. **Reason** is from `reason` or `threshold_pct` (or empty). **Sequence** is the receipt’s `sequence_number`.

---

## Summary of structure (non-normative)

- Title: `# NonSudo Enforcement Report`
- Header block: Workflow, Generated, Policy hash, Mode
- Horizontal rule `---` between sections
- Sections in order: Executive Summary, Enforcement Outcomes, Budget, Verification, Artifact References, Degraded Events
- All section headings are level-2 (`##`) and use the exact names above (no numbering).
- Amounts in the report use `amount_minor_units` from action_receipts; display is in major units (divide by 100) with two decimal places; USD shown as `$X.XX`, other currencies as value + code.
