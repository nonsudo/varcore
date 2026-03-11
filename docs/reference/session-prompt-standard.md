# Session Prompt Standard

This standard applies to **every session prompt** (Session D and onward). The read list may vary by session scope, but the principle is fixed: **understand the system before touching it.**

---

## Read-first block (place at top of every session prompt)

Before any scope or instructions, include this block (adjust the file list per session):

> Before writing any code, read the following files in full. These documents define why this session exists, what the system has already built, and what the output must conform to. If any instruction in this prompt conflicts with these documents, **the documents win** — flag the conflict, do not silently resolve it.
>
> - `NS-BUILD-STATE-C.md`
> - `NS-BUILD-STATE-A.md`
> - `docs/spec/var-core-v1.0.md`
> - `docs/spec/var-money-v1.0.md`
> - `docs/public-contract.md`
> - `docs/reference/receipt-types.md`
> - `docs/reference/report-template.md`

---

## Why each document matters (Session D example)

| Document | Why it matters |
|----------|----------------|
| **var-money-v1.0.md** | Without it, implementers guess at `amount_protected` semantics and get it wrong. |
| **receipt-types.md** | Field names in the report parser will drift from the actual TypeScript types without it. |
| **public-contract.md** | Executive summary language in reports must match what the product claims. |
| **NS-BUILD-STATE-A.md** | Confirms that `amount_minor_units` is a signed field on `action_receipt`; otherwise implementers may read amount from params instead. |
| **var-core-v1.0.md** | RI-1 through RI-10, L4 tier definition, degraded mode table. |
| **report-template.md** | Locked report structure; output must conform. |
| **NS-BUILD-STATE-C.md** | What Session C built, current test count, any deviations flagged. |

For other sessions, adjust the list to match scope (e.g. add or remove build-state files, spec sections, or reference docs).

---

*NonSudo — session prompt standard*
