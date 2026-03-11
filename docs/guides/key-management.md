# Key Management

> **VAR v1.0 — 2026-03-02**

See also: [Trust Model](trust-model.md) §3 for the verification-side key-resolution contract.

---

## 1. Storage at Rest

The NonSudo proxy generates a single **Ed25519** key pair on first run (or when the
configured `key_id` is absent from disk).

| File | Mode | Contents |
|------|------|----------|
| `~/.nonsudo/keys/<key_id>.key` | **0600** (owner read-only) | Hex-encoded 32-byte Ed25519 private key seed |
| `~/.nonsudo/keys/<key_id>.jwk` | **0644** (world-readable) | Public key as JSON Web Key (OKP / Ed25519) |

The `key_id` is a ULID generated at creation time (e.g. `01HZ3QKXR7...`).  It appears in
the `signature.key_id` field of every signed receipt and in every log line that carries a
`[workflow_id=...]` context.

**Security notes:**
- Never commit `.key` files to version control.
- Restrict access to the `~/.nonsudo/keys/` directory (mode 0700 recommended).
- The proxy reads the private key at startup; the key seed is not cached in memory beyond
  the signing-provider object lifetime.

---

## 2. Key Rotation

Rotation replaces the active signing key with a new one.  Receipts signed with the old key
remain verifiable — the chain verification (`nonsudo verify`) resolves keys by `key_id`,
so old and new keys coexist in the key store.

**Rotation procedure:**

1. **Generate a new key pair** using the NonSudo CLI:
   ```bash
   nonsudo init --force
   ```
   This creates a new key pair with a fresh ULID `key_id` and writes it to `~/.nonsudo/keys/`.

2. **Update `nonsudo.yaml`** if you pin a specific `key_id` under `proxy.key_id`.  Leave
   it as `"auto"` to have the proxy pick up the newest key automatically.

3. **Restart the proxy.**  The new key takes effect on the next process start.  Receipts
   written after restart carry the new `key_id`.

4. **Publish the new public JWK** if verifiers resolve keys remotely via
   `schemas.nonsudo.dev`.  Deploy the new `.jwk` file to the schema server under
   `/.well-known/keys/<new_key_id>.json`.

5. **Archive the old private key** (do not delete it yet).  You may need it to
   re-sign nothing — old receipts remain self-contained — but keep it for forensic
   reference for the duration of your retention policy.

**Zero-downtime rotation** is not currently supported in stdio mode.  HTTP mode can be
rotated with a rolling restart if multiple proxy replicas are deployed.

---

## 3. Key Compromise

If you suspect a private key has been leaked or the host running the proxy has been
compromised:

1. **Isolate the host** — revoke network access if possible.

2. **Rotate immediately** (see §2 above).  Generate a new key pair on a clean machine and
   deploy the new proxy binary with the new key.

3. **Audit the receipt chain** for the affected `key_id`:
   ```bash
   nonsudo verify <receipts-file> --require-complete
   ```
   Review the output for unexpected `ALLOW` decisions or anomalous tool calls.

4. **Mark the old key as compromised** in your internal key registry.  Inform verifiers
   that receipts signed by the old `key_id` should be treated as untrusted after the
   suspected compromise timestamp.

5. **Do not re-use the compromised key_id.**  Key IDs are unique ULIDs; generating a new
   pair automatically produces a distinct ID.

> **Note:** NonSudo does not implement automated key revocation or a certificate revocation
> list (CRL).  Compromise response is an operational procedure.  See [Trust Model §5.2](trust-model.md#52-out-of-scope--limitations).

---

## 4. Key Resolution (verify side)

When `nonsudo verify` or `nonsudo conform` validates a receipt chain, public keys are
resolved in this order:

1. **Permanent local cache** — `~/.nonsudo/key-cache/<key_id>.jwk`
2. **Proxy-written local key** — `~/.nonsudo/keys/<key_id>.jwk`
3. **Remote fetch** — `https://schemas.nonsudo.dev/.well-known/keys/<key_id>.json`
   (cached on success in the permanent cache; `--offline` skips this step)

**Path-traversal protection:** The `key_id` is validated against
`/^[a-zA-Z0-9_-]{1,64}$/` before any file system or network access.  A receipt with a
malformed `key_id` is rejected at L1 without touching the file system.

**Offline verification:** To verify receipts without network access, pre-cache the public
JWK:
```bash
cp ~/.nonsudo/keys/<key_id>.jwk ~/.nonsudo/key-cache/<key_id>.jwk
nonsudo verify <receipts-file> --offline
```
