# Session D — Prompt (report command and demo consistency fix)

**Use this prompt to run Session D.** The read-first block below must stay at the very top; scope and instructions follow.

---

## Before writing any code — read these files

Before writing any code, read the following files in full. These documents define why this session exists, what the system has already built, and what the output must conform to. If any instruction in this prompt conflicts with these documents, **the documents win** — flag the conflict, do not silently resolve it.

- `NS-BUILD-STATE-C.md`
- `NS-BUILD-STATE-A.md`
- `docs/spec/var-core-v1.0.md`
- `docs/spec/var-money-v1.0.md`
- `docs/public-contract.md`
- `docs/reference/receipt-types.md`
- `docs/reference/report-template.md`

**Why each one matters for Session D:**

- Without **var-money-v1.0.md**: Cursor will guess at `amount_protected` semantics and get it wrong.
- Without **receipt-types.md**: field names in the report parser will drift from the actual TypeScript types.
- Without **public-contract.md**: the executive summary language won't match what the product claims.
- Without **NS-BUILD-STATE-A.md**: Cursor won't know that `amount_minor_units` is a signed field on `action_receipt` and may try to read amount from params instead.

---

## Scope

This session has three parts. Both touch only `packages/cli/`. No changes outside `packages/cli/`.

Run `pnpm test --recursive` after each part. Zero failures required before proceeding.

---

## Part 1 — Demo fixes

**File: `packages/cli/src/commands/demo.ts`**

Three fixes:

1. **Terminology consistency:** In the attempt output lines, show `velocity_exceeded` (not `velocity_limit_exceeded`) so the canonical `failure_reason` in the receipt is reflected correctly in the demo output.
2. **Receipt persistence:** Write demo receipts to `~/.nonsudo/receipts/<workflow_id>.ndjson` (not a temp directory). Create `~/.nonsudo/receipts/` with `mkdirSync({ recursive: true })` if it does not exist. Summary must print the exact runnable path and report hint using that path.
3. **`--policy` in internal verify:** When the demo runs verify internally, pass `--policy <bundled-policy-path>` pointing at `stripe-refunds-policy.yaml` so L4 runs with budget verification and exits PASS rather than WARN. Resolve the bundled policy path at runtime (e.g. `path.resolve(__dirname, '../demo/stripe-refunds-policy.yaml')`).

Update `packages/cli/src/__tests__/demo.test.ts`:

- Expect `velocity_exceeded` (not `velocity_limit_exceeded`) in attempt lines.
- Assert receipt file exists at `~/.nonsudo/receipts/<workflow_id>.ndjson` after the demo completes.
- Assert demo output contains `L4  Outcome binding             PASS`.

Gate: `pnpm test --recursive` must pass before Part 2.

---

## Part 2 — Report command

**File: `packages/cli/src/commands/report.ts`** (new or replace existing)

`nonsudo report --workflow <id>` reads the receipt NDJSON for the given workflow and outputs a Markdown report to stdout.

- **Locating the receipt file:** Default directory `~/.nonsudo/receipts/`, file `<workflow_id>.ndjson`. Override with `--receipts <path>`. If not found: exit 1 with `Error: no receipt file found for workflow <id>`.
- **Flags:** `--workflow <id>`, `[--receipts <path>]`, `[--output <path>]`, `[--policy <path>]`.
- **amount_protected (normative):** Sum of `amount_minor_units` from all `action_receipt` where `money_action: true` and the upstream was **not** called (e.g. `upstream_call_initiated: false`, or `decision: "BLOCK"`, or `queue_status: "DEAD_LETTER"`). Total money the system prevented from moving.
- **amount_processed:** Sum of `amount_minor_units` from `action_receipt` where `money_action: true` and `decision: "ALLOW"`.

Report structure must follow the exact Markdown defined in the task (Executive Summary, Enforcement Outcomes table, Budget, Verification, Artifact References, Degraded Events). Use `verifyChain` and `verifyL4` internally; do not re-implement verification logic. When `--policy` is not provided, L4 row shows WARN. Degraded events: receipts with `record_type` in `recovery_event`, `budget_warning`, `reservation_expired`.

Register in `packages/cli/src/index.ts`: `nonsudo report --workflow <id>` (and flags).

---

## Part 3 — Tests

**File: `packages/cli/src/__tests__/report.test.ts`** (new)

Use receipt NDJSON from GV-19 (money action SUCCESS) and GV-16 (complete chain) as test fixtures — copy into a temp directory per test; do not read from golden vector paths directly.

Required tests: report generates without error; output starts with `# NonSudo Enforcement Report`; workflow ID in header; enforcement outcomes row count correct; DEAD_LETTER rows show `velocity_exceeded`; `amount_protected` includes BLOCK and upstream_call_initiated: false; `amount_processed` is sum of ALLOW money action amounts only; L1 PASS and L4 PASS (with policy) / L4 WARN (without policy) in verification section; `--output <path>` writes file and stdout is empty; missing workflow exits 1 with correct error; chain with no money actions shows “No money actions recorded.” in budget section; degraded events section as specified.

---

## Final gate

1. `pnpm test --recursive` — ≥ current count plus new tests, zero failures. Report final count and breakdown by package.
2. `tsc --noEmit` — zero errors.
3. `eslint --max-warnings 0` — zero warnings.
4. `nonsudo demo stripe-refunds-loop` — attempts 4 and 5 show `velocity_exceeded`, receipt file at `~/.nonsudo/receipts/`, L4 PASS.
5. `nonsudo report --workflow <id>` with the demo’s workflow ID — valid Markdown, exit 0, amount_protected and amount_processed correct.
6. `npm audit --audit-level high` — zero findings.
7. Confirm no files outside `packages/cli/` were modified.

Produce `NS-BUILD-STATE-D.md` recording: all three demo fixes confirmed; report command complete and tested; `amount_protected` definition used (normative); test fixtures used for report tests; final test count and breakdown; any deviations from `docs/reference/report-template.md` flagged.

---

*Session D prompt — see docs/reference/session-prompt-standard.md for the standard that applies to every session.*
