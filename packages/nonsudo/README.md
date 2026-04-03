# nonsudo

Mandate enforcement and cryptographic receipts for AI agents.

## Install

```bash
npm install nonsudo
```

## Usage

### Receipt API

```typescript
import { createReceipt, signReceipt, chainReceipt, verifyChain } from 'nonsudo';
```

### Policy engine

```typescript
import { loadPolicy, evaluatePolicy } from 'nonsudo/policy';
```

### OpenAI adapter

```typescript
import { createActionReceipt } from 'nonsudo/adapter-openai';
```

### LangChain adapter

```typescript
import { createNonSudoCallbacks } from 'nonsudo/adapter-langchain';

const llm = new ChatOpenAI({ callbacks: createNonSudoCallbacks(config) });
```

### Receipt store

```typescript
import { ReceiptStore } from 'nonsudo/store';
```

## CLI

```bash
nonsudo verify receipts.ndjson         # L1 + L2 verification
nonsudo verify receipts.ndjson --full  # L1 + L2 + L3 + L4
nonsudo conform                        # conformance test vectors
```

## For implementers

The `@varcore/*` packages are the underlying open standard implementation.
Any implementation conforming to the VAR-Core spec can reference them directly.
Full spec: https://github.com/nonsudo/varcore

## Links

- **Platform:** https://nonsudo.com/docs/quickstart
- **Schema registry:** https://schemas.nonsudo.com
- **License:** Apache-2.0
