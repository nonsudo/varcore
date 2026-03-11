# NonSudo Keypair Baseline — Pre-Session G Audit

## Findings

### Keypair
- **Generated:** In `packages/proxy/src/keypair.ts` via `loadOrGenerateKeypair(configKeyId)`. When `key_id` is `"auto"` (from nonsudo.yaml): on first proxy start, if no `*.key` file exists in `~/.nonsudo/keys/`, a new keypair is generated with `@noble/ed25519` (`ed.utils.randomPrivateKey()`, `ed.getPublicKeyAsync()`); key_id is a new ULID. When `key_id` is an explicit value, that key must already exist on disk.
- **Private key stored:** `~/.nonsudo/keys/<key_id>.key` — one line, hex-encoded 32-byte private key. Mode 0600. Not in nonsudo.yaml.
- **Public key stored:** `~/.nonsudo/keys/<key_id>.jwk` — RFC 8037 OKP JWK (Ed25519). Mode 0644. The JWK `x` field is base64url-encoded 32-byte public key. Not in nonsudo.yaml by default; after `nonsudo keys export <kid>`, `public_key: "hex:<hex>"` is written to cwd's nonsudo.yaml when that file exists.
- **Format:** On disk: private key = hex; public key = JWK (kty=OKP, crv=Ed25519, x=base64url). In memory: raw 32-byte `Uint8Array` for both.

### Signing
- **Library:** `@noble/ed25519`. Signed payload: **subset of fields per record_type** (buildSigningPayload in packages/receipts/src/index.ts). Canonicalisation: **JCS (RFC 8785)**. Signature encoding: **base64url** (no padding). Location: `receipt.signature.sig`.

### Verification (TypeScript L1)
- Public key from key_id resolution (key-cache, keys dir, remote). Verified payload: same signed-fields-only object, JCS-canonicalized UTF-8 bytes.

### For Session G
- **Option 1 (config):** `--key-from-config` → nonsudo.yaml `public_key` (format `hex:<hex>`).
- **Option 2 (file):** `--key nonsudo.pub` (PEM).
- **Option 3 (hex):** `--key-hex <hex>`.
- **Test key hex:** `3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06`
