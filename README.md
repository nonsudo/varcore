# VAR-Core

**Open standard for cryptographic AI agent action receipts.**

Every agent action — every tool call, every decision — produces an Ed25519-signed,
RFC 3161 timestamped, hash-chained receipt. Nothing can be altered, backdated, or
denied. Built for EU AI Act Article 12 compliance and NIST AI RMF accountability.

## Packages

| Package | Description |
|---------|-------------|
| [`@varcore/core`](packages/core) | Protocol-agnostic types and `SigningProvider` interface |
| [`@varcore/receipts`](packages/receipts) | VAR v1.0 signing, chaining, L1/L2/L3 verification |
| [`@varcore/policy`](packages/policy) | YAML policy engine + schema packs |
| [`@varcore/store`](packages/store) | SQLite receipt store |
| [`@varcore/adapter-openai`](packages/adapter-openai) | OpenAI function-calling adapter |
| [`@varcore/adapter-langchain`](packages/adapter-langchain) | LangChain tool-call adapter |

## Quick Start
```bash
npm install @varcore/recs
```

## Conformance
```bash
npm install -g @nonsudo/cli
nonsudo conform
```

Conformance test vectors: `https://schemas.nonsudo.com/var/v1/test-vectors.json`

## Specification

- [VAR-Core v1.0](docs/spec/var-core-v1.0.md) — normative spec
- [Receipt Types](docs/reference/receipt-types.md) — field definitions
- [Trust Model](docs/guides/trust-model.md) — verification layers, threat model

## Policy Examples

- [Observe mode](examples/observe.yaml) — full audit trail, no blocking
- [Enforce mode](examples/enforce.yaml) — reads allowed, destructive ops blocked

## License

Apache-2.0 — free to use, implement, extend, and build commercial products on top of.
