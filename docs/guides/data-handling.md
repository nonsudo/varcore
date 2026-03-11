# Data Handling

> **VAR v1.0 — 2026-03-02**

This document describes what data the NonSudo proxy touches, stores, and explicitly does
not store.  It is intended to support privacy reviews, data-protection impact assessments,
and operator disclosure to end users.

See also: [Trust Model](trust-model.md) §5, [Key Management](key-management.md).

---

## 1. What NonSudo Processes

The NonSudo proxy sits on the path between an AI agent and an upstream tool server.
Every tool call that passes through the proxy is evaluated against a policy and recorded
as a signed receipt.

**Data processed per tool call:**

| Field | Source | Purpose |
|-------|--------|---------|
| `tool_name` | Agent request | Policy evaluation; recorded in receipt |
| `arguments` (tool params) | Agent request | Policy evaluation only; **not recorded** in receipt — only a SHA-256 hash of the canonical params is stored |
| Upstream tool response | Upstream server | Forwarded to agent; a SHA-256 hash of the response is recorded in the receipt |
| `workflow_id`, `agent_id` | Proxy-generated / header | Session correlation; recorded in all receipts |
| `initiator_id`, `workflow_owner` | `nonsudo.yaml` | Identity metadata; recorded in `workflow_manifest` |
| Policy decision (`ALLOW`/`BLOCK`/`STEP_UP`) | Policy evaluator | Recorded in receipt |

**Important:** The proxy processes raw tool arguments in memory for policy evaluation, but
does **not** persist them to any file or log.  Only the SHA-256 hash of the canonical
argument encoding is stored.

---

## 2. What NonSudo Stores

### 2.1 Receipt Files (NDJSON)

Signed receipt chains are written to NDJSON files in the configured `receipt_file` path
(stdio mode) or to `receipts-<workflow_id>.ndjson` in HTTP mode.

Each receipt contains:

- `workflow_id`, `receipt_id`, `sequence_number`, `issued_at`
- `tool_name`, `decision`, `decision_reason` — but **not** raw argument values
- `params_hash` — SHA-256 of the canonical JSON encoding of the tool arguments
- `response_hash` — SHA-256 of the upstream response (nullable for BLOCK)
- `upstream_call_initiated` — boolean | null indicating call disposition
- Ed25519 `signature` block (`alg`, `key_id`, `sig`)

### 2.2 TSA Sidecar Files (`.tsa` NDJSON)

When RFC 3161 timestamping is enabled, an optional sidecar file (`.tsa`) is written
alongside each receipt file.  Each entry contains:

- `receipt_id` — links to the corresponding receipt
- `rfc3161_token` — base64-encoded RFC 3161 `TimeStampResp` DER blob
- `tsa_id` — identifier of the Time-Stamp Authority used
- `timestamped_at` — wall-clock time of the timestamp request

TSA sidecar files contain **no** tool argument data.

### 2.3 Receipt Store (SQLite — optional)

When `nonsudo index` is used, receipt data is inserted into a SQLite database.  The
schema mirrors the NDJSON receipt structure: all fields present in receipts plus L1/L2/L3
verification status fields.  **No raw argument values are stored.**

### 2.4 Signing Keys

- Private key seed: `~/.nonsudo/keys/<key_id>.key` (hex, mode 0600)
- Public JWK: `~/.nonsudo/keys/<key_id>.jwk` (mode 0644)

See [Key Management](key-management.md) for storage details.

### 2.5 Logs

Structured logs are written to **stderr** only.  Log content is limited to:

- Structural metadata: tool names, decision codes, receipt IDs
- Hashes: `params_hash`, `receipt_id`
- Timing and session context: `workflow_id`, `agent_id`, timestamps

**Raw tool argument values are never logged.**  This is enforced by the D-005 principle
documented in `packages/proxy/src/logger.ts`.

---

## 3. What NonSudo Never Stores

The following data is explicitly **not** persisted anywhere by the proxy:

| Data | Notes |
|------|-------|
| Raw tool arguments (params values) | Only `params_hash` is stored |
| Raw upstream responses | Only `response_hash` is stored |
| Authentication credentials | Bearer tokens are compared in memory and discarded |
| Agent conversation history | NonSudo sees only individual tool calls, not the surrounding LLM context |
| User / end-user PII beyond initiator_id | `initiator_id` is operator-configured metadata, not collected from users |
| Network logs / request bodies | The proxy does not log HTTP request/response bodies |

---

## 4. Where Data Lives

| Artifact | Default Location | Configurable |
|----------|-----------------|--------------|
| Receipt NDJSON (stdio) | `<cwd>/<receipt_file>` from `nonsudo.yaml` | Yes (`proxy.receipt_file`) |
| Receipt NDJSON (HTTP) | `receipts-<workflow_id>.ndjson` in `receiptDir` | Yes (CLI flag) |
| TSA sidecar | `<receipt_file>.tsa` | No (derived from receipt path) |
| SQLite store | Operator-specified (`--db` flag) | Yes |
| Signing keys | `~/.nonsudo/keys/` | No |
| Public key cache | `~/.nonsudo/key-cache/` | No |
| Conform test-vector cache | `~/.nonsudo/conform-cache/` | No |

All storage is **local to the host running the proxy**.  NonSudo does not transmit receipt
data or tool arguments to any NonSudo-operated service.  The only outbound network calls
made by the proxy are:

1. Forwarding ALLOW'd tool calls to the configured `upstream_url`
2. RFC 3161 timestamping requests to the configured TSA (if enabled)
3. Public key resolution from `schemas.nonsudo.dev` (verify/conform, not proxy)

---

## 5. Retention

NonSudo does not implement automatic retention or deletion policies.  Operators are
responsible for:

- **Receipt file retention** — governed by your audit and compliance requirements.
  The `nonsudo index` command supports idempotent re-indexing if files are archived and
  restored.
- **Key retention** — keep old private keys for as long as you may need to forensically
  reconstruct signing history.  Keys are small (32 bytes) and have negligible storage cost.
- **Log retention** — managed by your log aggregation system (systemd journal, Docker log
  driver, etc.).  Logs do not contain raw PII or argument values, so retention risk is low.
- **SQLite store** — can be deleted and rebuilt from NDJSON source files at any time via
  `nonsudo index`.  NDJSON files are the source of truth.

**Deletion:** Deleting a receipt NDJSON file is irreversible.  The signed receipt chain
cannot be reconstructed from the SQLite store or logs alone.  Archive NDJSON files to
cold storage before deletion.
