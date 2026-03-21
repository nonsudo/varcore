# VAR-Core

**Open standard for cryptographic AI agent action receipts.**

An AI coding agent deleted 2.5 years of student data
from a production database. The founder disclosed
publicly. There was no receipt chain — no way to prove
what the agent attempted, what was authorized, and
what actually executed.

VAR-Core is the audit primitive that fixes this. Every
tool call an agent makes produces a tamper-evident,
independently verifiable receipt. Nothing can be
altered, backdated, or denied.

[![npm](https://img.shields.io/npm/v/@varcore/receipts)](https://www.npmjs.com/package/@varcore/receipts)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-205%2F205-brightgreen)](packages)
[![NIST CAISI](https://img.shields.io/badge/NIST%20CAISI-submitted-blue)](https://www.nist.gov/artificial-intelligence)

---

## How it works

Every agent tool call goes through three steps:

**1. Evaluate** — the call is checked against a
deterministic policy. No LLM in the enforcement path.
Same call + same params + same policy = same decision.
Every time.

**2. Decide** — one of five outcomes:

| Decision | What happens |
|---|---|
| `ALLOW` | Call executes. Receipt signed. |
| `BLOCK` | Call does not execute. Receipt signed. |
| `STEP_UP` | Held for human approval. Receipt signed on resolution. |
| `FAIL_CLOSED` | Policy error. Blocked by default. Receipt signed. |
| `FAIL_OPEN` | Policy error. Allowed with warning. Receipt signed. |

**3. Receipt** — a cryptographically signed,
hash-chained record is produced for every decision,
whether allowed or blocked.

---

## What a receipt looks like

```json
{
  "var_id": "var_01J5Q7XP8R2NKWZ9T4MVCLB3Y",
  "schema_version": "1.0.0",
  "record_type": "action_receipt",
  "tool_name": "stripe.refunds.create",
  "decision": "BLOCK",
  "blast_radius": "HIGH",
  "policy_bundle_hash": "sha256:abc123...",
  "agent_id": "agent_prod_01",
  "sequence_number": 4,
  "prev_receipt_hash": "sha256:a14f8c...d02e91",
  "response_entropy_hash": "sha256:7b2f9a...",
  "issued_at": "2026-03-20T09:22:31.411Z",
  "timestamp_rfc3161": "base64:MIIG...",
  "signature": "ed25519:3d9f2a...",
  "schema_url": "https://schemas.nonsudo.com/v1/receipt"
}
```

**Ed25519 signed.** The signature covers every field.
Tamper one byte and verification fails.

**Hash-chained.** Each receipt links to the prior
receipt via `prev_receipt_hash`. Delete or reorder
any receipt and the chain breaks.

**RFC 3161 timestamped.** An independent TSA proves
the receipt existed at a specific time.
No backdating possible.

**Independently verifiable.** Any third party can
verify a receipt chain with no nonsudo account.
Try it: https://schemas.nonsudo.com

---

## Install

```bash
npm install @varcore/receipts @varcore/policy
```

`@noble/ed25519` is included as a dependency of
`@varcore/receipts` — no separate install needed.

---

## Quickstart

```typescript
import * as ed from "@noble/ed25519";
import {
  createReceipt,
  signReceipt,
  chainReceipt,
  verifyChain,
} from "@varcore/receipts";
import { loadPolicy, evaluatePolicy } from "@varcore/policy";

// Generate an Ed25519 key pair
const privKey = ed.utils.randomPrivateKey();
const pubKey  = await ed.getPublicKeyAsync(privKey);

// Load your policy file
const policy = loadPolicy("./nonsudo.yaml");

// Evaluate a tool call against the policy
const result = evaluatePolicy(
  "stripe_refund",
  policy,
  { amount: 75000 }  // $750.00 in minor units
);
// result.decision === "STEP_UP" (over $500 threshold)

// Create the genesis receipt (first in chain)
const genesis = createReceipt({
  record_type:        "workflow_manifest",
  spec_version:       "var/1.0",
  workflow_id:        "wf_01J5Q7XP8R",
  workflow_id_source: "nonsudo_generated",
  agent_id:           "agent_prod_01",
  issued_at:          new Date().toISOString(),
  prev_receipt_hash:  null,
  sequence_number:    0,
  policy_bundle_hash: "sha256:abc123...",
  rfc3161_token:      null,
  tsa_id:             null,
  initiator_id:       "user@example.com",
  workflow_owner:     "team-alpha",
  session_budget:     { USD: 1000.00 },
  declared_tools:     ["stripe_refund", "stripe_charge"],
});
const signed1 = await signReceipt(genesis, privKey, "my-key-1");
// signed1.var_id    → "var_01..."
// signed1.signature → "ed25519:..."

// Create and chain the action receipt
const action = chainReceipt(
  createReceipt({
    record_type:        "action_receipt",
    spec_version:       "var/1.0",
    workflow_id:        "wf_01J5Q7XP8R",
    workflow_id_source: "nonsudo_generated",
    agent_id:           "agent_prod_01",
    issued_at:          new Date().toISOString(),
    prev_receipt_hash:  null,   // chainReceipt sets this
    sequence_number:    0,      // chainReceipt sets this
    policy_bundle_hash: "sha256:abc123...",
    rfc3161_token:      null,
    tsa_id:             null,
    tool_name:          "stripe_refund",
    decision:           result.decision,
    reason:             result.reason,
    blast_radius:       "MED",
    reversible:         false,
  }),
  signed1  // links prev_receipt_hash + increments sequence
);
const signed2 = await signReceipt(action, privKey, "my-key-1");

// Verify the full chain
const verification = await verifyChain([signed1, signed2], pubKey);
console.log(verification.valid);   // true
console.log(verification.errors);  // []
console.log(verification.gaps);    // []
```

---

## Policy example

```yaml
# nonsudo.yaml
version: "1.0"
mode: enforce

rules:
  - tool: "stripe_refund"
    decision: BLOCK
    reason: "refunds over $1,000 require human approval"
    blast_radius: HIGH
    reversible: false
    params:
      conditions:
        - field: "amount"
          op: "gt"
          value: 100000   # $1,000.00 in minor units

  - tool: "stripe_refund"
    decision: STEP_UP
    reason: "refunds over $500 flagged for review"
    blast_radius: MED
    reversible: false
    params:
      conditions:
        - field: "amount"
          op: "gt"
          value: 50000    # $500.00 in minor units

  - tool: "github_delete_branch"
    decision: BLOCK
    reason: "protected branches cannot be deleted"
    blast_radius: HIGH
    reversible: false
    params:
      conditions:
        - field: "branch"
          op: "in"
          value: ["main", "master", "production"]

  - tool: "terraform_destroy"
    decision: BLOCK
    reason: "destroy requires explicit human approval
             outside the agent workflow"
    blast_radius: CRITICAL
    reversible: false
```

---

## Packages

| Package | Version | Description |
|---|---|---|
| [`@varcore/core`](packages/core) | 1.2.0 | Protocol-agnostic types and `SigningProvider` interface |
| [`@varcore/receipts`](packages/receipts) | 1.2.1 | VAR v1.0 signing, chaining, L1-L4 verification |
| [`@varcore/policy`](packages/policy) | 1.2.2 | YAML policy engine + 10 pre-built control packs |
| [`@varcore/store`](packages/store) | 1.2.0 | SQLite receipt store |
| [`@varcore/adapter-openai`](packages/adapter-openai) | 1.2.1 | OpenAI function-calling adapter |
| [`@varcore/adapter-langchain`](packages/adapter-langchain) | 1.2.1 | LangChain tool-call adapter |

---

## Verification layers

```typescript
import {
  verifyChain,
  verifyL3,
  verifyL4,
  loadTsaSidecar,
} from "@varcore/receipts";

// L1 + L2: signature integrity and chain integrity
const chain = await verifyChain(receipts, pubKey);
// chain.valid    → true if all signatures pass and
//                  hash chain is unbroken
// chain.complete → true if workflow_closed is final receipt
// chain.errors   → ChainError[] (empty if valid)
// chain.gaps     → number[] (missing sequence numbers)

// L3: RFC 3161 timestamp integrity
const tsaRecords = loadTsaSidecar("./receipts.ndjson.tsa");
const l3 = await verifyL3(receipt, tsaRecords);
// l3.status → "PASS" | "FAIL" | "SKIP"

// L4: outcome binding — proves what the tool returned
const l4 = await verifyL4(receipts);
// l4.status     → "PASS" | "WARN" | "FAIL" | "N/A"
// l4.violations → L4Violation[]
```

| Layer | What it proves |
|---|---|
| L1 | Receipt was signed by the key holder and not modified |
| L2 | No receipt was deleted, inserted, or reordered |
| L3 | Receipt existed at the stated time — no backdating |
| L4 | Tool response matches the hash recorded in the receipt |

---

## Control packs

`@varcore/policy` ships with 10 pre-built control packs
covering the most common compliance frameworks:

```typescript
import { SCHEMA_PACKS, mergePackRules, loadPolicy }
  from "@varcore/policy";

// See all available packs
console.log(Object.keys(SCHEMA_PACKS));
// [
//   "stripe/enforce",
//   "github/enforce",
//   "aws-s3/enforce",
//   "pci-dss/stripe",
//   "terraform/enforce",
//   "eu-ai-act/enforce",
//   "hipaa/enforce",
//   "soc2/enforce",
//   "gdpr/enforce",
//   "iso27001/enforce"
// ]

// Use a pack directly
const policy = {
  default: "ALLOW",
  rules: SCHEMA_PACKS["terraform/enforce"].rules,
};

// Or merge a pack into your own policy
const base   = loadPolicy("./nonsudo.yaml");
const merged = mergePackRules(base, "eu-ai-act/enforce");
```

| Pack ID | Covers |
|---|---|
| `stripe/enforce` | Payment limits, refund thresholds, currency controls |
| `github/enforce` | Force push, protected branch, webhook controls |
| `aws-s3/enforce` | Object deletion, bucket deletion, policy changes |
| `pci-dss/stripe` | PCI-DSS payment card data handling |
| `terraform/enforce` | Destroy blocks, production apply approval |
| `eu-ai-act/enforce` | Article 12 logging, high-risk system oversight |
| `hipaa/enforce` | PHI access, modification, and export controls |
| `soc2/enforce` | Customer data, production change management |
| `gdpr/enforce` | Lawful basis, cross-border transfer, erasure |
| `iso27001/enforce` | Asset classification, incident response, key ops |

---

## Conformance

Any implementation claiming VAR-Core conformance must
pass the full test vector suite:

```bash
npx @varcore/receipts test-vectors
```

Conformance vectors:
https://schemas.nonsudo.com/var/v1/test-vectors.json

Schema registry and receipt verifier:
https://schemas.nonsudo.com

---

## Standards

VAR-Core was submitted to NIST CAISI (Center for AI
Standards and Innovation) as a sector-specific
implementation reference for AI agent governance,
covering financial services, healthcare, and education.
Three separate submissions, March 2026.

The receipt format aligns with EU AI Act Article 12
requirements for automatic logging of high-risk AI
system decisions.

---

## Why open source

The audit primitive for AI agents should be owned by
nobody. An open standard that any implementation can
conform to — and that any auditor, regulator, or
insurer can verify independently — is more valuable
than a proprietary format.

VAR-Core is Apache-2.0. Use it, implement it, build
commercial products on top of it.

The reference runtime enforcement platform built on
VAR-Core is [nonsudo](https://nonsudo.com).

---

## Contributing

```bash
git clone https://github.com/nonsudo/varcore
cd varcore
npm install
npm test
```

205 tests across 5 packages. All must pass before
submitting a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache-2.0 — free to use, implement, extend, and
build commercial products on top of.
