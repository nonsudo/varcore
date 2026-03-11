/**
 * Tests for evaluateParams (PE1–PE16).
 *
 * PE1  eq matches exact value
 * PE2  gt returns true when field exceeds threshold
 * PE3  gt on non-number — logs warning, returns false
 * PE4  match returns true on regex match
 * PE5  not_match returns true when regex does not match
 * PE6  not_match with invalid regex — logs warning, returns false
 * PE7  in returns true when field in value array
 * PE8  not_in returns true when field absent from array
 * PE9  exists returns true when field present and non-null
 * PE10 not_exists returns true when field absent
 * PE11 AND logic — all conditions true → true
 * PE12 AND logic — one condition false → false
 * PE13 Dot notation — address.country resolves nested value
 * PE14 Dot notation — missing intermediate key → false
 * PE15 Engine integration — rule fires when tool AND params match
 * PE16 Engine integration — rule does not fire when tool matches but params do not
 */

import { evaluateParams } from "../params-evaluator";
import type { ConditionResult } from "../params-evaluator";
import { evaluatePolicy } from "../index";
import type { PolicyConfig, ParamsCondition } from "../index";

// ── Helpers ───────────────────────────────────────────────────────────────────

function args(obj: Record<string, unknown>): Record<string, unknown> {
  return obj;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("evaluateParams", () => {
  // PE1: eq matches exact value
  test("PE1: eq matches exact value", () => {
    const result = evaluateParams(
      { conditions: [{ field: "currency", op: "eq", value: "USD" }] },
      args({ currency: "USD" })
    );
    expect(result).toBe("match");
  });

  // PE2: gt returns "match" when field exceeds threshold
  test("PE2: gt returns 'match' when field exceeds threshold", () => {
    const result = evaluateParams(
      { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
      args({ amount: 75000 })
    );
    expect(result).toBe("match");
  });

  // PE3: gt on non-number field — logs warning, returns "type_error"
  test("PE3: gt on non-number field — logs warning, returns 'type_error'", () => {
    const warnChunks: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: string | Uint8Array) => {
      warnChunks.push(typeof chunk === "string" ? chunk : chunk.toString());
      return true;
    };

    let result: ConditionResult = "no_match";
    try {
      result = evaluateParams(
        { conditions: [{ field: "amount", op: "gt", value: 100 }] },
        args({ amount: "not-a-number" })
      );
    } finally {
      process.stderr.write = orig;
    }

    expect(result).toBe("type_error");
    expect(warnChunks.join("")).toMatch(/gt/);
  });

  // PE4: match returns "match" on regex match
  test("PE4: match returns 'match' on regex match", () => {
    const result = evaluateParams(
      { conditions: [{ field: "path", op: "match", value: "^/tmp/" }] },
      args({ path: "/tmp/file.txt" })
    );
    expect(result).toBe("match");
  });

  // PE5: not_match returns "match" when regex does not match
  test("PE5: not_match returns 'match' when regex does not match", () => {
    const result = evaluateParams(
      { conditions: [{ field: "to", op: "not_match", value: "@company\\.com$" }] },
      args({ to: "external@gmail.com" })
    );
    expect(result).toBe("match");
  });

  // PE6: not_match with invalid regex — logs warning, returns "no_match" (config error, not type_error)
  test("PE6: not_match with invalid regex — logs warning, returns 'no_match'", () => {
    const warnChunks: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: string | Uint8Array) => {
      warnChunks.push(typeof chunk === "string" ? chunk : chunk.toString());
      return true;
    };

    let result: ConditionResult = "match";
    try {
      result = evaluateParams(
        { conditions: [{ field: "path", op: "not_match", value: "[invalid(regex" }] },
        args({ path: "/tmp/test" })
      );
    } finally {
      process.stderr.write = orig;
    }

    expect(result).toBe("no_match");
    expect(warnChunks.join("")).toMatch(/invalid regex/i);
  });

  // PE7: in returns "match" when field in value array
  test("PE7: in returns 'match' when field in value array", () => {
    const result = evaluateParams(
      { conditions: [{ field: "currency", op: "in", value: ["USD", "EUR", "GBP"] }] },
      args({ currency: "EUR" })
    );
    expect(result).toBe("match");
  });

  // PE8: not_in returns "match" when field absent from array
  test("PE8: not_in returns 'match' when field absent from array", () => {
    const result = evaluateParams(
      { conditions: [{ field: "currency", op: "not_in", value: ["USD", "EUR", "GBP"] }] },
      args({ currency: "JPY" })
    );
    expect(result).toBe("match");
  });

  // PE9: exists returns "match" when field present and non-null
  test("PE9: exists returns 'match' when field present and non-null", () => {
    const result = evaluateParams(
      { conditions: [{ field: "api_key", op: "exists" }] },
      args({ api_key: "sk-123" })
    );
    expect(result).toBe("match");
  });

  // PE10: not_exists returns "match" when field absent
  test("PE10: not_exists returns 'match' when field absent", () => {
    const result = evaluateParams(
      { conditions: [{ field: "api_key", op: "not_exists" }] },
      args({ amount: 100 })
    );
    expect(result).toBe("match");
  });

  // PE11: AND logic — all conditions match → "match"
  test("PE11: AND logic — all conditions match → 'match'", () => {
    const result = evaluateParams(
      {
        conditions: [
          { field: "amount", op: "gt", value: 10000 },
          { field: "currency", op: "in", value: ["USD", "EUR"] },
        ],
      },
      args({ amount: 50000, currency: "USD" })
    );
    expect(result).toBe("match");
  });

  // PE12: AND logic — one condition no_match → "no_match"
  test("PE12: AND logic — one condition no_match → 'no_match'", () => {
    const result = evaluateParams(
      {
        conditions: [
          { field: "amount", op: "gt", value: 10000 },
          { field: "currency", op: "in", value: ["USD", "EUR"] },
        ],
      },
      args({ amount: 50000, currency: "JPY" }) // JPY not in list
    );
    expect(result).toBe("no_match");
  });

  // PE13: Dot notation — address.country resolves nested value
  test("PE13: dot notation — address.country resolves nested value", () => {
    const result = evaluateParams(
      { conditions: [{ field: "address.country", op: "eq", value: "US" }] },
      args({ address: { country: "US", city: "NYC" } })
    );
    expect(result).toBe("match");
  });

  // PE14: Dot notation — missing intermediate key → "no_match"
  test("PE14: dot notation — missing intermediate key → 'no_match'", () => {
    const result = evaluateParams(
      { conditions: [{ field: "address.country", op: "eq", value: "US" }] },
      args({ name: "Alice" }) // no `address` key
    );
    expect(result).toBe("no_match");
  });
});

describe("evaluatePolicy — params integration", () => {
  // PE15: Engine integration — rule fires when tool AND params match
  test("PE15: rule fires when tool name and params conditions both match", () => {
    const policy: PolicyConfig = {
      default: "ALLOW",
      rules: [
        {
          tool: "stripe_charge",
          decision: "BLOCK",
          reason: "charges over $500 require review",
          blast_radius: "HIGH",
          reversible: false,
          params: {
            conditions: [{ field: "amount", op: "gt", value: 50000 }],
          },
        },
      ],
    };

    const result = evaluatePolicy("stripe_charge", policy, { amount: 75000 });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toMatch(/stripe_charge:param:amount gt 50000/);
    expect(result.matched_param_condition).toBeDefined();
    if (!result.matched_param_condition) throw new Error("Expected matched_param_condition to be defined");
    expect(result.matched_param_condition.field).toBe("amount");
  });

  // PE16: Engine integration — rule does not fire when tool matches but params do not
  test("PE16: rule does not fire when tool matches but params condition is not satisfied", () => {
    const policy: PolicyConfig = {
      default: "ALLOW",
      rules: [
        {
          tool: "stripe_charge",
          decision: "BLOCK",
          reason: "charges over $500 require review",
          blast_radius: "HIGH",
          reversible: false,
          params: {
            conditions: [{ field: "amount", op: "gt", value: 50000 }],
          },
        },
      ],
    };

    // amount is below threshold — params don't match, falls through to default ALLOW
    const result = evaluatePolicy("stripe_charge", policy, { amount: 100 });
    expect(result.decision).toBe("ALLOW");
    expect(result.matched_rule).toBe("default");
  });
});

// ── Operator Branch Coverage ───────────────────────────────────────────────────
// Adds coverage for branches not reached by PE1–PE16:
//   lines 24-27  (MAX_DEPTH exceeded)
//   line  69     (neq operator)
//   lines 79-82  (gt: non-number condition value)
//   lines 87-111 (gte, lt, lte operators entirely)
//   lines 118-121 (match: invalid regex catch block)
//   lines 141-144 (in: non-array condition value)
//   lines 150-153 (not_in: non-array condition value)
//   lines 158-162 (default: unknown operator)
//   lines 184-187 (evaluateParams safety net catch block)

describe("operator branch coverage", () => {
  // Helper — build a one-rule PolicyConfig with a single param condition.
  // Uses "BLOCK" as the rule decision so a true condition → decision: "BLOCK",
  // and a false condition falls through to default "ALLOW".
  function buildTestPolicy(opts: {
    tool: string;
    field: string;
    op: string;          // string (not the union) so we can pass invalid ops in tests
    value?: unknown;
    decision?: "ALLOW" | "BLOCK";
  }): PolicyConfig {
    return {
      default: "ALLOW",
      rules: [
        {
          tool: opts.tool,
          decision: (opts.decision ?? "BLOCK") as PolicyConfig["default"],
          reason: "test rule",
          blast_radius: "LOW",
          reversible: true,
          params: {
            conditions: [
              {
                field: opts.field,
                op: opts.op as ParamsCondition["op"],
                value: opts.value,
              },
            ],
          },
        },
      ],
    };
  }

  // Helper to capture stderr.write output during a callback
  function captureStderr(fn: () => void): string {
    const chunks: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: string | Uint8Array): boolean => {
      chunks.push(typeof chunk === "string" ? chunk : chunk.toString());
      return true;
    };
    try {
      fn();
    } finally {
      process.stderr.write = orig;
    }
    return chunks.join("");
  }

  // ── neq (line 69) ────────────────────────────────────────────────────────────

  test("neq: blocks when field value does NOT equal expected", () => {
    const policy = buildTestPolicy({ tool: "t", field: "status", op: "neq", value: "approved" });
    const result = evaluatePolicy("t", policy, { status: "pending" });
    expect(result.decision).toBe("BLOCK");
  });

  test("neq: does not block when field value equals expected", () => {
    const policy = buildTestPolicy({ tool: "t", field: "status", op: "neq", value: "approved" });
    const result = evaluatePolicy("t", policy, { status: "approved" });
    expect(result.decision).toBe("ALLOW");
  });

  test("neq: does not block when field is absent", () => {
    const policy = buildTestPolicy({ tool: "t", field: "status", op: "neq", value: "approved" });
    const result = evaluatePolicy("t", policy, { other: "value" });
    expect(result.decision).toBe("ALLOW"); // missing field → false → ALLOW
  });

  // ── gt: non-number condition value (lines 79-82) ──────────────────────────────
  // PE3 already covers gt with non-number fieldValue; this covers non-number *threshold*

  test("gt: non-number condition value logs warning and returns BLOCK (params_type_error)", () => {
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: "not-a-number" });
      result = evaluatePolicy("t", policy, { amount: 5000 });
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
    expect(warn).toMatch(/gt/);
  });

  test("gt: does not block when field is absent", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { other: 5000 });
    expect(result.decision).toBe("ALLOW");
  });

  test("gt: field is null → no_match (null treated as absent, not type_error)", () => {
    // null field: getField returns { found: false } → no_match → ALLOW (falls through to default)
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: null });
    expect(result.decision).toBe("ALLOW");
  });

  test("gt: field is string → BLOCK (params_type_error)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: "5000" });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
  });

  test("gt: blocks when numeric field exceeds threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: 5000 });
    expect(result.decision).toBe("BLOCK");
  });

  test("gt: does not block when value equals threshold (strict greater-than)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: 1000 });
    expect(result.decision).toBe("ALLOW");
  });

  // ── gte (lines 87-93) ────────────────────────────────────────────────────────

  test("gte: blocks when field exceeds threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gte", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: 5000 });
    expect(result.decision).toBe("BLOCK");
  });

  test("gte: blocks when field equals threshold (inclusive)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gte", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: 1000 });
    expect(result.decision).toBe("BLOCK");
  });

  test("gte: does not block when field is below threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gte", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: 500 });
    expect(result.decision).toBe("ALLOW");
  });

  test("gte: field is string → BLOCK (params_type_error)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "gte", value: 1000 });
    const result = evaluatePolicy("t", policy, { amount: "1000" });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
  });

  // ── lt (lines 95-102) ────────────────────────────────────────────────────────

  test("lt: blocks when field is below threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lt", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 5 });
    expect(result.decision).toBe("BLOCK");
  });

  test("lt: does not block when field equals threshold (strict less-than)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lt", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 10 });
    expect(result.decision).toBe("ALLOW");
  });

  test("lt: does not block when field exceeds threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lt", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 50 });
    expect(result.decision).toBe("ALLOW");
  });

  test("lt: field is string → BLOCK (params_type_error)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lt", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: "5" });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
  });

  // ── lte (lines 104-111) ──────────────────────────────────────────────────────

  test("lte: blocks when field is below threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lte", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 5 });
    expect(result.decision).toBe("BLOCK");
  });

  test("lte: blocks when field equals threshold (inclusive)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lte", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 10 });
    expect(result.decision).toBe("BLOCK");
  });

  test("lte: does not block when field exceeds threshold", () => {
    const policy = buildTestPolicy({ tool: "t", field: "quantity", op: "lte", value: 10 });
    const result = evaluatePolicy("t", policy, { quantity: 50 });
    expect(result.decision).toBe("ALLOW");
  });

  test("lte: field is boolean → BLOCK (params_type_error)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "amount", op: "lte", value: 100 });
    const result = evaluatePolicy("t", policy, { amount: true });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
  });

  // ── match: invalid regex catch block (lines 118-121) ─────────────────────────

  test("match: invalid regex logs warning and returns false", () => {
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      const policy = buildTestPolicy({ tool: "t", field: "path", op: "match", value: "[invalid(" });
      result = evaluatePolicy("t", policy, { path: "/tmp/test" });
    });
    expect(result.decision).toBe("ALLOW"); // invalid regex → false → ALLOW
    expect(warn).toMatch(/invalid regex/i);
  });

  test("match: non-string field value → BLOCK (params_type_error, not silent stringification)", () => {
    // Number field 42 should NOT be silently stringified to "42" — it's a type error
    const policy = buildTestPolicy({ tool: "t", field: "code", op: "match", value: "^42$" });
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      result = evaluatePolicy("t", policy, { code: 42 });
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
    expect(warn).toMatch(/match requires a string field/i);
  });

  test("match: field absent → no match", () => {
    const policy = buildTestPolicy({ tool: "t", field: "provider", op: "match", value: "^stripe_" });
    const result = evaluatePolicy("t", policy, { other: "stripe_live" });
    expect(result.decision).toBe("ALLOW");
  });

  // ── in: non-array condition value (lines 141-144) ────────────────────────────

  test("in: non-array condition value logs warning and returns false", () => {
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      // value is "USD" (string), not an array — misconfigured rule
      const policy = buildTestPolicy({ tool: "t", field: "currency", op: "in", value: "USD" });
      result = evaluatePolicy("t", policy, { currency: "USD" });
    });
    expect(result.decision).toBe("ALLOW"); // non-array → false → ALLOW
    expect(warn).toMatch(/in operator requires an array/i);
  });

  test("in: does not block when value is not in list", () => {
    const policy = buildTestPolicy({ tool: "t", field: "region", op: "in", value: ["us-east-1", "eu-west-1"] });
    const result = evaluatePolicy("t", policy, { region: "ap-southeast-1" });
    expect(result.decision).toBe("ALLOW");
  });

  test("in: does not block when list is empty", () => {
    const policy = buildTestPolicy({ tool: "t", field: "region", op: "in", value: [] });
    const result = evaluatePolicy("t", policy, { region: "us-east-1" });
    expect(result.decision).toBe("ALLOW");
  });

  test("in: type mismatch — number 1 vs list ['1'] does not match (strict equality)", () => {
    // Array.includes uses strict equality; 1 !== "1"
    const policy = buildTestPolicy({ tool: "t", field: "code", op: "in", value: ["1", "2", "3"] });
    const result = evaluatePolicy("t", policy, { code: 1 });
    expect(result.decision).toBe("ALLOW"); // current: strict equality, 1 !== "1"
  });

  test("in: does not block when field is absent", () => {
    const policy = buildTestPolicy({ tool: "t", field: "currency", op: "in", value: ["USD", "EUR"] });
    const result = evaluatePolicy("t", policy, { other: "USD" });
    expect(result.decision).toBe("ALLOW");
  });

  // ── not_in: non-array condition value (lines 150-153) ────────────────────────

  test("not_in: non-array condition value logs warning and returns false", () => {
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      // value is a string, not an array — misconfigured rule
      const policy = buildTestPolicy({ tool: "t", field: "currency", op: "not_in", value: "USD" });
      result = evaluatePolicy("t", policy, { currency: "EUR" });
    });
    expect(result.decision).toBe("ALLOW"); // non-array → false → ALLOW
    expect(warn).toMatch(/not_in operator requires an array/i);
  });

  test("not_in: blocks when value is not in exclusion list", () => {
    const policy = buildTestPolicy({ tool: "t", field: "currency", op: "not_in", value: ["USD", "EUR"] });
    const result = evaluatePolicy("t", policy, { currency: "JPY" });
    expect(result.decision).toBe("BLOCK"); // JPY not excluded → not_in = true → BLOCK
  });

  test("not_in: does not block when value is in exclusion list", () => {
    const policy = buildTestPolicy({ tool: "t", field: "currency", op: "not_in", value: ["USD", "EUR"] });
    const result = evaluatePolicy("t", policy, { currency: "USD" });
    expect(result.decision).toBe("ALLOW"); // USD is excluded → not_in = false → ALLOW
  });

  test("not_in: blocks when exclusion list is empty (nothing excluded)", () => {
    const policy = buildTestPolicy({ tool: "t", field: "region", op: "not_in", value: [] });
    const result = evaluatePolicy("t", policy, { region: "us-east-1" });
    expect(result.decision).toBe("BLOCK"); // not in empty list → true → BLOCK
  });

  // ── not_exists (additional paths beyond PE10) ─────────────────────────────────

  test("not_exists: does not block when field is present with a value", () => {
    const policy = buildTestPolicy({ tool: "t", field: "flag", op: "not_exists" });
    const result = evaluatePolicy("t", policy, { flag: "set" });
    expect(result.decision).toBe("ALLOW"); // field exists → not_exists = false → ALLOW
  });

  test("not_exists: field present but null is treated as not-existing — current behavior", () => {
    // getField returns { found: false, value: null } when value is null
    // so not_exists returns true for null-valued fields (null = treated as absent)
    const policy = buildTestPolicy({ tool: "t", field: "flag", op: "not_exists" });
    const result = evaluatePolicy("t", policy, { flag: null });
    expect(result.decision).toBe("BLOCK"); // current: null treated as absent → not_exists = true → BLOCK
  });

  test("not_exists: blocks when nested field path is absent", () => {
    const policy = buildTestPolicy({ tool: "t", field: "data.flag", op: "not_exists" });
    const result = evaluatePolicy("t", policy, { data: {} });
    expect(result.decision).toBe("BLOCK");
  });

  test("not_exists: does not block when nested field path is present", () => {
    const policy = buildTestPolicy({ tool: "t", field: "data.flag", op: "not_exists" });
    const result = evaluatePolicy("t", policy, { data: { flag: true } });
    expect(result.decision).toBe("ALLOW");
  });

  // ── Nested field path — array traversal dead-end ─────────────────────────────

  test("nested: blocks when nested field satisfies condition", () => {
    const policy = buildTestPolicy({ tool: "t", field: "data.amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { data: { amount: 5000 } });
    expect(result.decision).toBe("BLOCK");
  });

  test("nested: does not block when nested field does not satisfy condition", () => {
    const policy = buildTestPolicy({ tool: "t", field: "data.amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { data: { amount: 500 } });
    expect(result.decision).toBe("ALLOW");
  });

  test("nested: does not block when nested field is absent in otherwise present object", () => {
    const policy = buildTestPolicy({ tool: "t", field: "data.amount", op: "gt", value: 1000 });
    const result = evaluatePolicy("t", policy, { data: {} });
    expect(result.decision).toBe("ALLOW");
  });

  test("nested: intermediate field is an array → BLOCK (params_type_error, array traversal dead-end)", () => {
    // data: [{ amount: 5000 }] — traversing into array with "amount" key is a dead-end
    // Previously this silently returned ALLOW; now it returns BLOCK with params_type_error
    const policy = buildTestPolicy({ tool: "t", field: "data.amount", op: "gt", value: 1000 });
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      result = evaluatePolicy("t", policy, { data: [{ amount: 5000 }] });
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.decision_reason).toBe("params_type_error");
    expect(warn).toMatch(/array traversal dead-end/i);
  });

  test("nested: three levels deep — a.b.c gt 1 blocks when a.b.c = 5", () => {
    const policy = buildTestPolicy({ tool: "t", field: "a.b.c", op: "gt", value: 1 });
    const result = evaluatePolicy("t", policy, { a: { b: { c: 5 } } });
    expect(result.decision).toBe("BLOCK");
  });

  test("nested: three levels — path broken at innermost key → no match", () => {
    const policy = buildTestPolicy({ tool: "t", field: "a.b.c", op: "gt", value: 1 });
    const result = evaluatePolicy("t", policy, { a: { b: {} } });
    expect(result.decision).toBe("ALLOW");
  });

  // ── default case: unknown operator (lines 158-162) ───────────────────────────

  test("default: unknown operator logs warning and returns false", () => {
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      // Cast to bypass TypeScript exhaustive union — runtime path hits the switch default
      const policy = buildTestPolicy({ tool: "t", field: "x", op: "unknown_op", value: 1 });
      result = evaluatePolicy("t", policy, { x: 1 });
    });
    expect(result.decision).toBe("ALLOW"); // unknown op → false → ALLOW
    expect(warn).toMatch(/unknown operator/i);
  });

  // ── MAX_DEPTH exceeded (lines 24-27) ─────────────────────────────────────────

  test("getField: field path exceeding MAX_DEPTH (6 segments) returns false with warning", () => {
    // "a.b.c.d.e.f" has 6 parts; MAX_DEPTH = 5 → depth exceeded
    const policy = buildTestPolicy({ tool: "t", field: "a.b.c.d.e.f", op: "eq", value: "x" });
    let warn = "";
    let result = {} as ReturnType<typeof evaluatePolicy>;
    warn = captureStderr(() => {
      result = evaluatePolicy("t", policy, { a: { b: { c: { d: { e: { f: "x" } } } } } });
    });
    expect(result.decision).toBe("ALLOW"); // depth exceeded → found: false → eq false → ALLOW
    expect(warn).toMatch(/max depth/i);
  });

  test("getField: path at exactly MAX_DEPTH (5 segments) resolves correctly", () => {
    // "a.b.c.d.e" has 5 parts — exactly at limit, should work
    const policy = buildTestPolicy({ tool: "t", field: "a.b.c.d.e", op: "eq", value: "found" });
    const result = evaluatePolicy("t", policy, { a: { b: { c: { d: { e: "found" } } } } });
    expect(result.decision).toBe("BLOCK"); // exactly 5 levels deep → resolves → BLOCK
  });

  // ── evaluateParams safety net catch block (lines 184-187) ────────────────────

  test("evaluateParams safety net: catches unexpected error in evaluateCondition and returns 'type_error'", () => {
    // Pass null as a condition to trigger a TypeError in evaluateCondition's destructuring
    // evaluateCondition does: const { field, op, value } = condition — throws on null
    let warn = "";
    let result: ReturnType<typeof evaluateParams> = "no_match";
    warn = captureStderr(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- intentionally malformed input to test safety net
      result = evaluateParams({ conditions: [null as any] }, { amount: 100 });
    });
    expect(result).toBe("type_error"); // safety net catches TypeError, returns "type_error"
    expect(warn).toMatch(/unexpected error/i);
  });
});
