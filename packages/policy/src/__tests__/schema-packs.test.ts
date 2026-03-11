/**
 * SP1–SP16: Schema pack tests
 *
 * SP1   resolveSchemaPack("stripe/enforce") returns the pack
 * SP2   resolveSchemaPack("unknown/pack") throws PolicyLoadError
 * SP3   stripe/enforce: stripe_charge BLOCK when amount > 100000
 * SP4   stripe/enforce: stripe_charge STEP_UP when amount 50001–100000
 * SP5   stripe/enforce: stripe_charge BLOCK when currency not in approved list
 * SP6   stripe/enforce: stripe_charge ALLOW for valid amount + currency
 * SP7   github/enforce: github_push BLOCK when force=true
 * SP8   github/enforce: github_push STEP_UP when branch=main
 * SP9   github/enforce: github_delete_branch BLOCK when branch=production
 * SP10  aws-s3/enforce: s3_delete_object BLOCK when key not in tmp/
 * SP11  aws-s3/enforce: s3_delete_bucket BLOCK (tool-level, no params)
 * SP12  mergePackRules: no operator rule for tool → pack rule appended
 * SP13  mergePackRules: operator rule (no merge_schema_params) → pack rule NOT applied
 * SP14  mergePackRules: merge_schema_params: true → pack rules injected before operator rule
 * SP15  mergePackRules: merge_schema_params: false → pack rules NOT injected
 * SP16  computePolicyBundleHash: different merged policies → different hashes
 */

import {
  resolveSchemaPack,
  SCHEMA_PACKS,
  mergePackRules,
  computePolicyBundleHash,
  evaluatePolicy,
} from "../index";
import { PolicyLoadError } from "../types";
import type { PolicyConfig, PolicyRule } from "../types";

// ── SP1–SP2: resolveSchemaPack ────────────────────────────────────────────────

describe("resolveSchemaPack", () => {
  test("SP1: known pack ID returns SchemaPackDefinition", () => {
    const pack = resolveSchemaPack("stripe/enforce");
    expect(pack.id).toBe("stripe/enforce");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP2: unknown pack ID throws PolicyLoadError", () => {
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(PolicyLoadError);
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(/unknown\/pack/);
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(/nonsudo schemas list/);
  });
});

// ── SP3–SP6: stripe/enforce evaluation ───────────────────────────────────────

describe("stripe/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["stripe/enforce"].rules,
  };

  test("SP3: stripe_charge BLOCK when amount > 100000", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000, currency: "usd" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP4: stripe_charge STEP_UP when amount > 50000 and ≤ 100000", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 75000, currency: "usd" });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP5: stripe_charge BLOCK when currency not in approved list", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 10000, currency: "XYZ" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP6: stripe_charge ALLOW for valid low amount + approved currency", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 10000, currency: "usd" });
    expect(r.decision).toBe("ALLOW");
  });
});

// ── SP7–SP9: github/enforce evaluation ───────────────────────────────────────

describe("github/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["github/enforce"].rules,
  };

  test("SP7: github_push BLOCK when force=true", () => {
    const r = evaluatePolicy("github_push", policy, { force: true, branch: "feature/x" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP8: github_push STEP_UP when branch=main and force=false", () => {
    const r = evaluatePolicy("github_push", policy, { force: false, branch: "main" });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP9: github_delete_branch BLOCK when branch=production", () => {
    const r = evaluatePolicy("github_delete_branch", policy, { branch: "production" });
    expect(r.decision).toBe("BLOCK");
  });
});

// ── SP10–SP11: aws-s3/enforce evaluation ─────────────────────────────────────

describe("aws-s3/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["aws-s3/enforce"].rules,
  };

  test("SP10: s3_delete_object BLOCK when key is not in tmp/ prefix", () => {
    const r = evaluatePolicy("s3_delete_object", policy, { key: "data/important.txt" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP11: s3_delete_bucket BLOCK (tool-level, no params required)", () => {
    const r = evaluatePolicy("s3_delete_bucket", policy, {});
    expect(r.decision).toBe("BLOCK");
    expect(r.matched_rule).toBe("s3_delete_bucket");
  });
});

// ── SP12–SP15: mergePackRules ─────────────────────────────────────────────────

describe("mergePackRules", () => {
  const packRules: PolicyRule[] = [
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "large charge (pack)",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
  ];

  test("SP12: no operator rule for tool → pack rule appended and evaluated", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "read_file",
        decision: "ALLOW",
        reason: "reads are fine",
        blast_radius: "LOW",
        reversible: true,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack rule for stripe_charge is appended — should fire
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP13: operator rule without merge_schema_params → pack rule NOT applied (operator wins)", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator allows all charges",
        blast_radius: "LOW",
        reversible: true,
        // merge_schema_params: absent (default false)
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK is skipped; operator ALLOW fires
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("ALLOW");
    // Only the operator rule should be in merged (pack rule omitted)
    expect(merged.filter((r) => r.decision === "BLOCK")).toHaveLength(0);
  });

  test("SP14: merge_schema_params: true → pack rules injected before operator rule", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator catch-all allows charges",
        blast_radius: "LOW",
        reversible: true,
        merge_schema_params: true,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK is injected first → fires for amount=150000
    const r1 = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r1.decision).toBe("BLOCK");

    // For amount=30000 pack condition not satisfied → operator ALLOW fires
    const r2 = evaluatePolicy("stripe_charge", policy, { amount: 30000 });
    expect(r2.decision).toBe("ALLOW");

    // Merged order: [pack BLOCK rule, operator ALLOW rule]
    expect(merged[0].decision).toBe("BLOCK");
    expect(merged[1].decision).toBe("ALLOW");
  });

  test("SP15: merge_schema_params: false → pack rules NOT injected", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator allows all charges",
        blast_radius: "LOW",
        reversible: true,
        merge_schema_params: false,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK not injected; operator ALLOW fires
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("ALLOW");

    // Only the operator rule
    expect(merged).toHaveLength(1);
    expect(merged[0].decision).toBe("ALLOW");
  });
});

// ── SP16: computePolicyBundleHash ─────────────────────────────────────────────

describe("computePolicyBundleHash", () => {
  test("SP16: different merged policies produce different hashes", () => {
    const policy1: PolicyConfig = {
      default: "ALLOW",
      rules: SCHEMA_PACKS["stripe/enforce"].rules,
      schemas: ["stripe/enforce"],
    };
    const policy2: PolicyConfig = {
      default: "ALLOW",
      rules: SCHEMA_PACKS["github/enforce"].rules,
      schemas: ["github/enforce"],
    };

    const hash1 = computePolicyBundleHash(policy1);
    const hash2 = computePolicyBundleHash(policy2);

    expect(hash1).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hash2).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hash1).not.toBe(hash2);
  });
});
