#!/usr/bin/env ts-node
/**
 * generate-golden-vectors.ts
 *
 * Generates 18 golden vectors (GV-01 through GV-18) in test/golden-vectors/GV-XX/.
 * Each vector directory contains:
 *   receipt.ndjson   — NDJSON file of signed receipts produced by the real proxy binary
 *   expected.json    — assertions to check in golden-vectors.test.ts
 *   README.md        — human-readable description
 *   (GV-17 only): receipt.ndjson.tsa — TSA sidecar NDJSON
 *
 * Most vectors run `node packages/cli/dist/index.js proxy` as a real subprocess.
 * GV-15 is constructed programmatically using the receipts library directly.
 *
 * Usage: npx ts-node scripts/generate-golden-vectors.ts
 *
 * Prerequisites:
 *   cd packages/cli && npm run build
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import * as child_process from "child_process";
import * as ed from "../packages/receipts/node_modules/@noble/ed25519/lib/index.js";
import canonicalize from "../packages/receipts/node_modules/canonicalize/index.js";

import {
  createReceipt,
  signReceipt,
  chainReceipt,
} from "../packages/receipts/src/index";
import type { ReceiptFields, SignedReceipt } from "../packages/receipts/src/index";
import { buildRfc3161Token } from "../packages/receipts/src/test-utils";

// ── Constants ─────────────────────────────────────────────────────────────────

const CLI_PATH = path.resolve(__dirname, "../packages/cli/dist/index.js");
const FIXTURE_PATH = path.resolve(
  __dirname,
  "../packages/proxy/src/__tests__/fixtures/test-mcp-server.mjs"
);
const OUTPUT_DIR = path.resolve(__dirname, "../test/golden-vectors");

const AGENT_ID = "gv-test-agent";
const INITIATOR_ID = "gv-tester";
const WORKFLOW_OWNER = "gv-team";

// ── Preflight ─────────────────────────────────────────────────────────────────

function preflight(): void {
  if (!fs.existsSync(CLI_PATH)) {
    throw new Error(
      `CLI binary not found: ${CLI_PATH}\nRun: cd packages/cli && npm run build`
    );
  }
  if (!fs.existsSync(FIXTURE_PATH)) {
    throw new Error(`Fixture missing: ${FIXTURE_PATH}`);
  }
}

// ── YAML builder ─────────────────────────────────────────────────────────────

interface YamlOptions {
  receiptFile: string;
  failToolsList?: boolean;
  queueTimeoutMs?: number;
  declaredTools?: string[];
  policyDefault?: string;
  policyRules?: Array<{
    tool: string;
    decision: string;
    reason?: string;
    blast_radius?: string;
    reversible?: boolean;
    params?: { conditions: Array<{ field: string; op: string; value: unknown }> };
  }>;
  velocityLimits?: Array<{ tool: string; max_calls: number; window: string }>;
}

function makeYaml(opts: YamlOptions): string {
  const upstreamArgs: string[] = [FIXTURE_PATH];
  if (opts.failToolsList) upstreamArgs.push("--fail-tools-list");

  const lines: string[] = [
    'version: "1.0"',
    "proxy:",
    "  upstream_command: node",
    `  upstream_args: ${JSON.stringify(upstreamArgs)}`,
    `  receipt_file: "${opts.receiptFile}"`,
    '  key_id: "auto"',
  ];

  if (opts.queueTimeoutMs !== undefined) {
    lines.push(`  queue_timeout_ms: ${opts.queueTimeoutMs}`);
  }

  lines.push("workflow:");
  lines.push(`  agent_id: "${AGENT_ID}"`);
  lines.push(`  initiator_id: "${INITIATOR_ID}"`);
  lines.push(`  workflow_owner: "${WORKFLOW_OWNER}"`);
  lines.push("  session_budget:");
  lines.push("    api_calls: 100");

  if (opts.declaredTools) {
    lines.push(`  declared_tools: ${JSON.stringify(opts.declaredTools)}`);
  }

  lines.push("policy:");
  lines.push(`  default: ${opts.policyDefault ?? "ALLOW"}`);

  if (opts.policyRules && opts.policyRules.length > 0) {
    lines.push("  rules:");
    for (const r of opts.policyRules) {
      lines.push(`    - tool: "${r.tool}"`);
      lines.push(`      decision: ${r.decision}`);
      lines.push(`      reason: "${r.reason ?? "golden vector rule"}"`);
      lines.push(`      blast_radius: ${r.blast_radius ?? "HIGH"}`);
      lines.push(`      reversible: ${r.reversible ?? false}`);
      if (r.params) {
        lines.push("      params:");
        lines.push("        conditions:");
        for (const c of r.params.conditions) {
          lines.push(`          - field: ${c.field}`);
          lines.push(`            op: ${c.op}`);
          lines.push(`            value: ${JSON.stringify(c.value)}`);
        }
      }
    }
  } else {
    lines.push("  rules: []");
  }

  if (opts.velocityLimits && opts.velocityLimits.length > 0) {
    lines.push("velocity:");
    lines.push("  limits:");
    for (const l of opts.velocityLimits) {
      lines.push(`    - tool: "${l.tool}"`);
      lines.push(`      max_calls: ${l.max_calls}`);
      lines.push(`      window: "${l.window}"`);
    }
  }

  return lines.join("\n");
}

// ── Minimal MCP JSON-RPC stdio client ────────────────────────────────────────

interface ToolCall {
  name: string;
  arguments?: Record<string, unknown>;
}

/**
 * Run the proxy binary as a subprocess, send tool calls via MCP JSON-RPC,
 * then close (SIGTERM) and read the produced receipts file.
 */
async function runProxyScenario(opts: {
  yaml: string;
  toolCalls: ToolCall[];
  expectedReceiptCount: number;
  maxWaitMs?: number;
}): Promise<SignedReceipt[]> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-gv-"));
  const receiptFile = path.join(tmpDir, "receipts.ndjson");
  const configPath = path.join(tmpDir, "nonsudo.yaml");

  fs.writeFileSync(configPath, opts.yaml);

  return new Promise<SignedReceipt[]>((resolve, reject) => {
    const proc = child_process.spawn(
      "node",
      [CLI_PATH, "proxy", "--config", configPath],
      { stdio: ["pipe", "pipe", "inherit"] }
    );

    let stdoutBuf = "";
    const responses: Map<number, unknown> = new Map();
    let nextId = 1;

    // Parse JSON-RPC responses from proxy stdout
    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf8");
      // MCP uses newline-delimited JSON
      const lines = stdoutBuf.split("\n");
      stdoutBuf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const msg = JSON.parse(trimmed) as { id?: number; result?: unknown; error?: unknown };
          if (msg.id !== undefined) {
            responses.set(msg.id, msg.result ?? msg.error);
          }
        } catch { /* ignore parse errors */ }
      }
    });

    const sendMsg = (msg: object) => {
      proc.stdin.write(JSON.stringify(msg) + "\n");
    };

    // Wait for a response to a specific request ID
    const waitForResponse = (id: number, timeoutMs = 10000): Promise<unknown> => {
      return new Promise((res, rej) => {
        const deadline = Date.now() + timeoutMs;
        const check = () => {
          if (responses.has(id)) return res(responses.get(id));
          if (Date.now() > deadline) return rej(new Error(`Timeout waiting for response id=${id}`));
          if (proc.exitCode !== null) return rej(new Error(`Proxy exited before response id=${id}`));
          setTimeout(check, 20);
        };
        check();
      });
    };

    const waitForReceipts = (minLines: number, timeoutMs: number): Promise<void> => {
      return new Promise((res, rej) => {
        const deadline = Date.now() + timeoutMs;
        const check = () => {
          if (!fs.existsSync(receiptFile)) {
            if (Date.now() > deadline) return rej(new Error(`Receipt file never created: ${receiptFile}`));
            return setTimeout(check, 50);
          }
          const lines = fs.readFileSync(receiptFile, "utf8").trim().split("\n").filter(Boolean);
          if (lines.length >= minLines) return res();
          if (Date.now() > deadline) {
            return rej(new Error(`Expected ${minLines} receipts, got ${lines.length}`));
          }
          setTimeout(check, 50);
        };
        check();
      });
    };

    async function run() {
      // MCP initialization
      const initId = nextId++;
      sendMsg({
        jsonrpc: "2.0",
        id: initId,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "gv-client", version: "1.0.0" },
        },
      });

      await waitForResponse(initId);

      // Send initialized notification
      sendMsg({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

      // Send tool calls sequentially
      for (const tc of opts.toolCalls) {
        const callId = nextId++;
        sendMsg({
          jsonrpc: "2.0",
          id: callId,
          method: "tools/call",
          params: { name: tc.name, arguments: tc.arguments ?? {} },
        });
        await waitForResponse(callId, 15000);
      }

      // Signal the proxy to shut down gracefully
      proc.kill("SIGTERM");

      // Wait for receipts to be written
      const maxWait = opts.maxWaitMs ?? 8000;
      await waitForReceipts(opts.expectedReceiptCount, maxWait);

      // Read and parse the receipts
      const content = fs.readFileSync(receiptFile, "utf8");
      const receipts = content
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as SignedReceipt);

      // Cleanup
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }

      return receipts;
    }

    run().then(resolve).catch(reject);

    proc.on("error", reject);
  });
}

// ── Programmatic GV-15 builder ────────────────────────────────────────────────

async function buildProgrammaticTtlChain(): Promise<{
  receipts: SignedReceipt[];
  pubKeyHex: string;
}> {
  // Deterministic 32-byte seed for GV-15
  const seed = Buffer.alloc(32);
  Buffer.from("gv15deadbeef").copy(seed);
  const privateKey = new Uint8Array(seed);
  const pubKey = await ed.getPublicKeyAsync(privateKey);
  const keyId = "gv15-deterministic";

  const workflowId = "GV15000000000000000000000000";
  const ZERO_HASH = "sha256:" + "0".repeat(64);

  const manifestFields: ReceiptFields = {
    receipt_id: "GV15MANIFEST0000000000000001",
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: AGENT_ID,
    issued_at: "2026-03-02T10:00:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: ZERO_HASH,
    rfc3161_token: null,
    tsa_id: null,
    initiator_id: INITIATOR_ID,
    workflow_owner: WORKFLOW_OWNER,
    session_budget: { api_calls: 100 },
    declared_tools: ["noop"],
    capability_manifest_hash: null,
    parent_workflow_id: null,
    framework_ref: null,
  };

  const signedManifest = await signReceipt(createReceipt(manifestFields), privateKey, keyId);

  const paramsCanonical = canonicalize(null) ?? "null";
  const paramsHash = "sha256:" + crypto.createHash("sha256").update(paramsCanonical).digest("hex");

  const actionFields: ReceiptFields = {
    receipt_id: "GV15ACTION000000000000000001",
    record_type: "action_receipt",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: AGENT_ID,
    issued_at: "2026-03-02T10:00:01Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: ZERO_HASH,
    rfc3161_token: null,
    tsa_id: null,
    tool_name: "noop",
    params_canonical_hash: paramsHash,
    decision: "ALLOW",
    decision_reason: "default allow",
    decision_order: 1,
    queue_status: "COMPLETED",
    queue_timeout_ms: 5000,
    blast_radius: "LOW",
    reversible: true,
    state_version_before: 0,
    state_version_after: 1,
    response_hash: null,
  };

  const signedAction = await signReceipt(
    chainReceipt(createReceipt(actionFields), signedManifest),
    privateKey,
    keyId
  );

  const manifestMs = new Date("2026-03-02T10:00:00Z").getTime();
  const closedMs = new Date("2026-03-02T10:30:00Z").getTime(); // 30 min TTL

  const closedFields: ReceiptFields = {
    receipt_id: "GV15CLOSED000000000000000001",
    record_type: "workflow_closed",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: AGENT_ID,
    issued_at: "2026-03-02T10:30:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: ZERO_HASH,
    rfc3161_token: null,
    tsa_id: null,
    total_calls: 1,
    total_blocked: 0,
    total_spend: null,
    session_duration_ms: closedMs - manifestMs,
    close_reason: "ttl_expired",
  };

  const signedClosed = await signReceipt(
    chainReceipt(createReceipt(closedFields), signedAction),
    privateKey,
    keyId
  );

  return {
    receipts: [signedManifest, signedAction, signedClosed],
    pubKeyHex: Buffer.from(pubKey).toString("hex"),
  };
}

// ── Expected JSON types ───────────────────────────────────────────────────────

interface ReceiptAssertion {
  index: number;
  assertions: Record<string, unknown>;
}

interface ExpectedJson {
  id: string;
  description: string;
  receipt_count: number;
  chain: { l1: "PASS"; l2: "PASS"; l3: "PASS" | "FAIL" | "SKIPPED"; complete: boolean };
  receipts: ReceiptAssertion[];
  pubkey_hex?: string;
}

// ── Write vector files ────────────────────────────────────────────────────────

function writeVectorFiles(
  gvId: string,
  receipts: SignedReceipt[],
  expected: ExpectedJson,
  tsaRecords?: object[]
): void {
  const dir = path.join(OUTPUT_DIR, gvId);
  fs.mkdirSync(dir, { recursive: true });

  const ndjson = receipts.map((r) => JSON.stringify(r)).join("\n") + "\n";
  fs.writeFileSync(path.join(dir, "receipt.ndjson"), ndjson, "utf8");

  if (tsaRecords && tsaRecords.length > 0) {
    const tsaNdjson = tsaRecords.map((r) => JSON.stringify(r)).join("\n") + "\n";
    fs.writeFileSync(path.join(dir, "receipt.ndjson.tsa"), tsaNdjson, "utf8");
  }

  fs.writeFileSync(
    path.join(dir, "expected.json"),
    JSON.stringify(expected, null, 2) + "\n",
    "utf8"
  );

  const assertionDocs = expected.receipts
    .map((r) => {
      const rtype = (receipts[r.index] as unknown as Record<string, unknown>)?.record_type ?? "?";
      const fields = Object.entries(r.assertions)
        .map(([k, v]) => `- ${k}: \`${JSON.stringify(v)}\``)
        .join("\n");
      return `### receipts[${r.index}] (${rtype})\n\n${fields}`;
    })
    .join("\n\n");

  const readme = `# ${gvId} — ${expected.description}

## Summary

- Receipts: ${receipts.length} (${receipts.map((r) => (r as unknown as Record<string, unknown>).record_type).join(" → ")})
- L1: ${expected.chain.l1}
- L2: ${expected.chain.l2}
- L3: ${expected.chain.l3}
- Chain complete: ${expected.chain.complete}

## Assertions

${assertionDocs}
`;
  fs.writeFileSync(path.join(dir, "README.md"), readme, "utf8");
}

// ── Vector generator functions ────────────────────────────────────────────────

async function generateGV01(): Promise<void> {
  console.log("[GV-01] manifest_normal");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [],
    expectedReceiptCount: 2,
  });

  writeVectorFiles("GV-01", receipts, {
    id: "GV-01",
    description: "manifest_normal — proxy starts, no tool calls, graceful close",
    receipt_count: 2,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 0,
        assertions: {
          record_type: "workflow_manifest",
          agent_id: AGENT_ID,
          spec_version: "var/1.0",
          sequence_number: 0,
          prev_receipt_hash: null,
          initiator_id: INITIATOR_ID,
          workflow_owner: WORKFLOW_OWNER,
        },
      },
      {
        index: 1,
        assertions: { record_type: "workflow_closed", total_calls: 0 },
      },
    ],
  });
}

async function generateGV02(): Promise<void> {
  console.log("[GV-02] manifest_tools_list_fail");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson", failToolsList: true }),
    toolCalls: [],
    expectedReceiptCount: 2,
  });

  const manifest = receipts[0] as unknown as Record<string, unknown>;
  if (!manifest.declared_tools_fetch_failed) {
    throw new Error(`[GV-02] Expected declared_tools_fetch_failed=true`);
  }

  writeVectorFiles("GV-02", receipts, {
    id: "GV-02",
    description: "manifest_tools_list_fail — tools/list throws; declared_tools=[], declared_tools_fetch_failed=true",
    receipt_count: 2,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 0,
        assertions: {
          record_type: "workflow_manifest",
          declared_tools: [],
          declared_tools_fetch_failed: true,
        },
      },
    ],
  });
}

async function generateGV03(): Promise<void> {
  console.log("[GV-03] allow_call");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [{ name: "echo", arguments: { message: "gv03-hello" } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-03", receipts, {
    id: "GV-03",
    description: "allow_call — echo ALLOW; upstream_call_initiated=true; response_hash=null",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          record_type: "action_receipt",
          tool_name: "echo",
          decision: "ALLOW",
          queue_status: "COMPLETED",
          upstream_call_initiated: true,
          response_hash: null,
        },
      },
    ],
  });
}

async function generateGV04(): Promise<void> {
  console.log("[GV-04] block_policy");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      policyRules: [
        { tool: "echo", decision: "BLOCK", reason: "blocked by gv policy", blast_radius: "HIGH", reversible: false },
      ],
    }),
    toolCalls: [{ name: "echo", arguments: { message: "gv04" } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-04", receipts, {
    id: "GV-04",
    description: "block_policy — echo BLOCK by policy rule; upstream NOT called",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          tool_name: "echo",
          decision: "BLOCK",
          queue_status: "COMPLETED",
          upstream_call_initiated: false,
        },
      },
    ],
  });
}

async function generateGV05(): Promise<void> {
  console.log("[GV-05] block_undeclared");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      declaredTools: ["echo", "noop", "slow_tool", "transfer_funds"],
    }),
    toolCalls: [{ name: "any_tool", arguments: {} }],
    expectedReceiptCount: 3,
  });

  const action = receipts[1] as unknown as Record<string, unknown>;
  const reason = String(action.decision_reason ?? "");
  if (!reason.toLowerCase().includes("undeclared")) {
    throw new Error(`[GV-05] Expected undeclared in decision_reason, got: ${reason}`);
  }

  writeVectorFiles("GV-05", receipts, {
    id: "GV-05",
    description: "block_undeclared — any_tool not in declared_tools override; BLOCK undeclared_tool",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 0,
        assertions: { declared_tools: ["echo", "noop", "slow_tool", "transfer_funds"] },
      },
      {
        index: 1,
        assertions: { tool_name: "any_tool", decision: "BLOCK", upstream_call_initiated: false },
      },
    ],
  });
}

async function generateGV06(): Promise<void> {
  console.log("[GV-06] block_declared_tools_unavailable");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson", failToolsList: true }),
    toolCalls: [{ name: "echo", arguments: { message: "gv06" } }],
    expectedReceiptCount: 3,
  });

  const action = receipts[1] as unknown as Record<string, unknown>;
  if (action.decision_reason !== "declared_tools_unavailable") {
    throw new Error(`[GV-06] Expected decision_reason=declared_tools_unavailable`);
  }

  writeVectorFiles("GV-06", receipts, {
    id: "GV-06",
    description: "block_declared_tools_unavailable — tools/list failed; all calls BLOCK; blast_radius=CRITICAL",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          decision: "BLOCK",
          decision_reason: "declared_tools_unavailable",
          blast_radius: "CRITICAL",
          upstream_call_initiated: false,
        },
      },
    ],
  });
}

async function generateGV07(): Promise<void> {
  console.log("[GV-07] block_params_rule");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      policyRules: [
        {
          tool: "transfer_funds",
          decision: "BLOCK",
          reason: "amount exceeds limit",
          blast_radius: "CRITICAL",
          reversible: false,
          params: { conditions: [{ field: "amount", op: "gt", value: 9999 }] },
        },
      ],
    }),
    toolCalls: [{ name: "transfer_funds", arguments: { amount: 999999 } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-07", receipts, {
    id: "GV-07",
    description: "block_params_rule — transfer_funds amount=999999 > 9999; BLOCK by params condition",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: { tool_name: "transfer_funds", decision: "BLOCK", upstream_call_initiated: false },
      },
    ],
  });
}

async function generateGV08(): Promise<void> {
  console.log("[GV-08] block_params_type_error");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      policyDefault: "BLOCK",
      policyRules: [
        {
          tool: "transfer_funds",
          decision: "ALLOW",
          reason: "allow valid amounts",
          blast_radius: "LOW",
          reversible: true,
          params: { conditions: [{ field: "amount", op: "gt", value: 0 }] },
        },
      ],
    }),
    toolCalls: [{ name: "transfer_funds", arguments: { amount: "not-a-number" } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-08", receipts, {
    id: "GV-08",
    description: "block_params_type_error — amount=string; params evaluator type error; ALLOW rule misses → default BLOCK",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: { tool_name: "transfer_funds", decision: "BLOCK", upstream_call_initiated: false },
      },
    ],
  });
}

async function generateGV09(): Promise<void> {
  console.log("[GV-09] block_params_too_large");
  const largeMessage = "x".repeat(2 * 1024 * 1024); // 2 MiB
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [{ name: "echo", arguments: { message: largeMessage } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-09", receipts, {
    id: "GV-09",
    description: "block_params_too_large — echo 2MiB params > 1MiB limit; BLOCK params_too_large",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          tool_name: "echo",
          decision: "BLOCK",
          decision_reason: "params_too_large",
          upstream_call_initiated: false,
        },
      },
    ],
  });
}

async function generateGV10(): Promise<void> {
  console.log("[GV-10] step_up");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      policyRules: [
        { tool: "transfer_funds", decision: "STEP_UP", reason: "requires approval", blast_radius: "CRITICAL", reversible: false },
      ],
    }),
    toolCalls: [{ name: "transfer_funds", arguments: { amount: 100 } }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-10", receipts, {
    id: "GV-10",
    description: "step_up — transfer_funds STEP_UP; Phase 0 treats as BLOCK; upstream NOT called",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          tool_name: "transfer_funds",
          decision: "STEP_UP",
          queue_status: "COMPLETED",
          upstream_call_initiated: false,
        },
      },
    ],
  });
}

async function generateGV11(): Promise<void> {
  console.log("[GV-11] fail_open");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      policyRules: [
        { tool: "any_tool", decision: "FAIL_OPEN", reason: "fail open", blast_radius: "LOW", reversible: true },
      ],
    }),
    toolCalls: [{ name: "any_tool", arguments: {} }],
    expectedReceiptCount: 3,
  });

  writeVectorFiles("GV-11", receipts, {
    id: "GV-11",
    description: "fail_open — any_tool FAIL_OPEN; upstream called; decision=FAIL_OPEN, queue_status=COMPLETED",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          tool_name: "any_tool",
          decision: "FAIL_OPEN",
          queue_status: "COMPLETED",
          upstream_call_initiated: true,
        },
      },
    ],
  });
}

async function generateGV12(): Promise<void> {
  console.log("[GV-12] dead_letter_vcb");
  const receipts = await runProxyScenario({
    yaml: makeYaml({
      receiptFile: "receipts.ndjson",
      velocityLimits: [{ tool: "echo", max_calls: 1, window: "workflow" }],
    }),
    toolCalls: [
      { name: "echo", arguments: { message: "first" } },
      { name: "echo", arguments: { message: "second" } },
    ],
    expectedReceiptCount: 4,
  });

  writeVectorFiles("GV-12", receipts, {
    id: "GV-12",
    description: "dead_letter_vcb — echo × 2, velocity limit=1/workflow; second DEAD_LETTER/FAIL_CLOSED",
    receipt_count: 4,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: { tool_name: "echo", decision: "ALLOW", queue_status: "COMPLETED" },
      },
      {
        index: 2,
        assertions: {
          tool_name: "echo",
          decision: "FAIL_CLOSED",
          queue_status: "DEAD_LETTER",
          failure_reason: "velocity_limit_exceeded",
          upstream_call_initiated: false,
        },
      },
    ],
  });
}

async function generateGV13(): Promise<void> {
  console.log("[GV-13] dead_letter_timeout");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson", queueTimeoutMs: 500 }),
    toolCalls: [{ name: "slow_tool", arguments: {} }],
    expectedReceiptCount: 3,
    maxWaitMs: 12000,
  });

  writeVectorFiles("GV-13", receipts, {
    id: "GV-13",
    description: "dead_letter_timeout — slow_tool hangs; DEAD_LETTER after queue_timeout_ms=500; upstream_call_initiated=true",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          tool_name: "slow_tool",
          queue_status: "DEAD_LETTER",
          failure_reason: "queue_timeout",
          upstream_call_initiated: true,
        },
      },
    ],
  });
}

async function generateGV14(): Promise<void> {
  console.log("[GV-14] workflow_closed_graceful");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [{ name: "noop", arguments: {} }],
    expectedReceiptCount: 3,
  });

  const closed = receipts[2] as unknown as Record<string, unknown>;
  const closeReason = closed.close_reason as string;

  writeVectorFiles("GV-14", receipts, {
    id: "GV-14",
    description: "workflow_closed_graceful — noop call + close; workflow_closed with total_calls=1",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 2,
        assertions: {
          record_type: "workflow_closed",
          total_calls: 1,
          close_reason: closeReason,
        },
      },
    ],
  });
}

async function generateGV15(): Promise<void> {
  console.log("[GV-15] workflow_closed_ttl (programmatic)");
  const { receipts, pubKeyHex } = await buildProgrammaticTtlChain();

  writeVectorFiles("GV-15", receipts, {
    id: "GV-15",
    description: "workflow_closed_ttl — programmatic; workflow_closed close_reason=ttl_expired (HTTP session TTL)",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    pubkey_hex: pubKeyHex,
    receipts: [
      {
        index: 2,
        assertions: { record_type: "workflow_closed", close_reason: "ttl_expired", total_calls: 1 },
      },
    ],
  });
}

async function generateGV16(): Promise<void> {
  console.log("[GV-16] complete_chain");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [
      { name: "echo", arguments: { message: "first" } },
      { name: "noop", arguments: {} },
      { name: "echo", arguments: { message: "third" } },
    ],
    expectedReceiptCount: 5,
  });

  writeVectorFiles("GV-16", receipts, {
    id: "GV-16",
    description: "complete_chain — 3 tool calls; verifyChain valid=true, complete=true, gaps=[]",
    receipt_count: 5,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      { index: 0, assertions: { record_type: "workflow_manifest", sequence_number: 0 } },
      { index: 4, assertions: { record_type: "workflow_closed", total_calls: 3 } },
    ],
  });
}

async function generateGV17(): Promise<void> {
  console.log("[GV-17] tsa_sidecar");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [{ name: "echo", arguments: { message: "gv17-tsa" } }],
    expectedReceiptCount: 3,
  });

  const tsaRecords = receipts.map((r) => ({
    receipt_id: r.receipt_id,
    tsa_id: "digicert",
    rfc3161_token: buildRfc3161Token(r),
    timestamped_at: "2026-03-02T10:00:00Z",
  }));

  writeVectorFiles(
    "GV-17",
    receipts,
    {
      id: "GV-17",
      description: "tsa_sidecar — echo ALLOW + synthetic RFC 3161 tokens; L3 PASS with digicert allowlist",
      receipt_count: 3,
      chain: { l1: "PASS", l2: "PASS", l3: "PASS", complete: true },
      receipts: [
        { index: 1, assertions: { tool_name: "echo", decision: "ALLOW" } },
      ],
    },
    tsaRecords
  );
}

async function generateGV18(): Promise<void> {
  console.log("[GV-18] response_hash_null");
  const receipts = await runProxyScenario({
    yaml: makeYaml({ receiptFile: "receipts.ndjson" }),
    toolCalls: [{ name: "noop", arguments: {} }],
    expectedReceiptCount: 3,
  });

  const action = receipts[1] as unknown as Record<string, unknown>;
  if (!("response_hash" in action) || action.response_hash !== null) {
    throw new Error(`[GV-18] response_hash must be null (not absent), got: ${JSON.stringify(action.response_hash)}`);
  }

  writeVectorFiles("GV-18", receipts, {
    id: "GV-18",
    description: "response_hash_null — ALLOW receipt; response_hash:null is a signed field present as null; L1 validates null-value signed fields",
    receipt_count: 3,
    chain: { l1: "PASS", l2: "PASS", l3: "SKIPPED", complete: true },
    receipts: [
      {
        index: 1,
        assertions: {
          record_type: "action_receipt",
          decision: "ALLOW",
          response_hash: null,
        },
      },
    ],
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  preflight();

  console.log(`[generate-golden-vectors] Output: ${OUTPUT_DIR}`);
  console.log("[generate-golden-vectors] Generating 18 vectors...\n");

  await generateGV01();
  await generateGV02();
  await generateGV03();
  await generateGV04();
  await generateGV05();
  await generateGV06();
  await generateGV07();
  await generateGV08();
  await generateGV09();
  await generateGV10();
  await generateGV11();
  await generateGV12();
  await generateGV13();
  await generateGV14();
  await generateGV15();
  await generateGV16();
  await generateGV17();
  await generateGV18();

  console.log("\n[generate-golden-vectors] Done. 18 vectors written to test/golden-vectors/");
}

main().catch((err) => {
  console.error("[generate-golden-vectors] Fatal:", err);
  process.exit(1);
});
