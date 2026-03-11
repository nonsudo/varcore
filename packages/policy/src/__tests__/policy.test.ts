import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { loadPolicy, evaluatePolicy } from "../index";
import type { PolicyConfig } from "../index";

// ── Helpers ───────────────────────────────────────────────────────────────────

function writeYaml(dir: string, content: string, name = "nonsudo.yaml"): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
}

const FULL_POLICY_YAML = `
version: "1.0"
proxy:
  upstream_command: "node"
  upstream_args: []
  receipt_file: "/tmp/receipts.ndjson"
  key_id: "auto"
workflow:
  agent_id: "test"
  initiator_id: "test"
  workflow_owner: "test"
  session_budget:
    api_calls: 100
policy:
  default: ALLOW
  rules:
    - tool: "delete_file"
      decision: BLOCK
      reason: "destructive op"
      blast_radius: HIGH
      reversible: false
    - tool: "write_file"
      decision: ALLOW
      reason: "write allowed"
      blast_radius: MED
      reversible: true
    - tool: "read_file"
      decision: ALLOW
      reason: "read-only op"
      blast_radius: LOW
      reversible: true
    - tool: "*"
      decision: ALLOW
      reason: "default allow"
      blast_radius: LOW
      reversible: true
`;

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("evaluatePolicy", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-policy-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── Test 1: exact match → BLOCK ───────────────────────────────────────────

  test("1. exact match — delete_file → BLOCK with HIGH blast_radius", () => {
    const policy = loadPolicy(writeYaml(tmpDir, FULL_POLICY_YAML));
    const result = evaluatePolicy("delete_file", policy);

    expect(result.decision).toBe("BLOCK");
    expect(result.blast_radius).toBe("HIGH");
    expect(result.reversible).toBe(false);
    expect(result.decision_reason).toBe("destructive op");
  });

  // ── Test 2: exact match → ALLOW with correct blast_radius ─────────────────

  test("2. exact match — read_file → ALLOW with LOW blast_radius", () => {
    const policy = loadPolicy(writeYaml(tmpDir, FULL_POLICY_YAML));
    const result = evaluatePolicy("read_file", policy);

    expect(result.decision).toBe("ALLOW");
    expect(result.blast_radius).toBe("LOW");
    expect(result.reversible).toBe(true);
    expect(result.decision_reason).toBe("read-only op");
  });

  // ── Test 3: wildcard match ────────────────────────────────────────────────

  test("3. wildcard match — unknown tool matches '*' rule", () => {
    const policy = loadPolicy(writeYaml(tmpDir, FULL_POLICY_YAML));
    const result = evaluatePolicy("some_unknown_tool", policy);

    expect(result.decision).toBe("ALLOW");
    expect(result.matched_rule).toBe("*");
    expect(result.decision_reason).toBe("default allow");
  });

  // ── Test 4: default fallback — BLOCK ─────────────────────────────────────

  test("4. default fallback — no rules, no wildcard, default: BLOCK → BLOCK", () => {
    const policy: PolicyConfig = { default: "BLOCK", rules: [] };
    const result = evaluatePolicy("any_tool", policy);

    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("default");
  });

  // ── Test 5: default fallback — ALLOW ─────────────────────────────────────

  test("5. default fallback — no rules, no wildcard, default: ALLOW → ALLOW", () => {
    const policy: PolicyConfig = { default: "ALLOW", rules: [] };
    const result = evaluatePolicy("any_tool", policy);

    expect(result.decision).toBe("ALLOW");
    expect(result.matched_rule).toBe("default");
  });

  // ── Test 6: rule order — first match wins ─────────────────────────────────

  test("6. rule order — first matching rule wins, not last", () => {
    const policy: PolicyConfig = {
      default: "ALLOW",
      rules: [
        {
          tool: "write_file",
          decision: "BLOCK",
          reason: "first rule",
          blast_radius: "HIGH",
          reversible: false,
        },
        {
          tool: "write_file",
          decision: "ALLOW",
          reason: "second rule",
          blast_radius: "LOW",
          reversible: true,
        },
      ],
    };
    const result = evaluatePolicy("write_file", policy);

    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("first rule");
  });

  // ── Test 7: matched_rule field ────────────────────────────────────────────

  test("7a. matched_rule — exact match returns tool name", () => {
    const policy = loadPolicy(writeYaml(tmpDir, FULL_POLICY_YAML));
    expect(evaluatePolicy("delete_file", policy).matched_rule).toBe("delete_file");
  });

  test("7b. matched_rule — wildcard returns '*'", () => {
    const policy = loadPolicy(writeYaml(tmpDir, FULL_POLICY_YAML));
    expect(evaluatePolicy("unknown_tool", policy).matched_rule).toBe("*");
  });

  test("7c. matched_rule — default fallback returns 'default'", () => {
    const policy: PolicyConfig = { default: "ALLOW", rules: [] };
    expect(evaluatePolicy("any_tool", policy).matched_rule).toBe("default");
  });
});

describe("loadPolicy", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-policy-load-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── Test 8: missing file ──────────────────────────────────────────────────

  test("8. loadPolicy throws on missing file", () => {
    expect(() =>
      loadPolicy(path.join(tmpDir, "nonexistent.yaml"))
    ).toThrow(/Policy file not found/);
  });

  // ── Test 9: invalid schema ────────────────────────────────────────────────

  test("9. loadPolicy throws on invalid schema (missing decision field on a rule)", () => {
    const badYaml = `
policy:
  default: ALLOW
  rules:
    - tool: "delete_file"
      reason: "missing decision field"
      blast_radius: HIGH
      reversible: false
`;
    expect(() =>
      loadPolicy(writeYaml(tmpDir, badYaml))
    ).toThrow(/validation failed/);
  });

  // ── Test 10: evaluatePolicy never throws ─────────────────────────────────

  test("10. evaluatePolicy never throws — fuzz with edge-case tool names", () => {
    const policy: PolicyConfig = { default: "ALLOW", rules: [] };

    const edgeCases = ["", "  ", "*", "null", "undefined", "BLOCK", "__proto__", "a".repeat(1000)];
    for (const tc of edgeCases) {
      expect(() => evaluatePolicy(tc, policy)).not.toThrow();
    }
  });
});
