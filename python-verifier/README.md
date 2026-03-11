# nonsudo-verify

VAR-Core receipt chain verifier — **Reference Implementation 2** (Python).

Independent from the TypeScript Implementation 1. Verifies NDJSON receipt chains produced by the NonSudo proxy (L1 Ed25519, L2 hash chain, L3 RFC 3161 timestamps, L4 outcome binding).

## Install

```bash
pip install nonsudo-verify
```

## Usage

```bash
nonsudo-verify receipts.ndjson
nonsudo-verify receipts.ndjson --key-hex 3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06
nonsudo-verify receipts.ndjson --key-from-config
nonsudo-verify --conformance
```

See `nonsudo-verify --help` for all options.

## License

Apache-2.0
