import { evaluatePolicy } from "../index";
import type { PolicyConfig, EvaluationContext } from "../index";

// Minimal base policy — default ALLOW, no rules
const BASE: PolicyConfig = { default: "ALLOW", rules: [] };

// ── Network guard ─────────────────────────────────────────────────────────────

describe("Guard 1: Network egress", () => {
  test("blocked domain (exact match) → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, network: { blocked_domains: ["ngrok.io"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://ngrok.io/tunnel" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("network:blocked_domain");
  });

  test("blocked domain (subdomain suffix) → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, network: { blocked_domains: ["ngrok.io"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://evil.ngrok.io/tunnel" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("network:blocked_domain");
  });

  test("domain NOT matching subdomain pattern → not blocked", () => {
    const policy: PolicyConfig = { ...BASE, network: { blocked_domains: ["ngrok.io"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://notngrok.io/path" });
    expect(result.decision).toBe("ALLOW");
  });

  test("require_tls with http:// → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, network: { require_tls: true } };
    const result = evaluatePolicy("fetch", policy, { url: "http://example.com/api" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("network:require_tls");
  });

  test("allowed domain when allowlist set → ALLOW (continues to rule eval)", () => {
    const policy: PolicyConfig = { ...BASE, network: { allowed_domains: ["api.stripe.com"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://api.stripe.com/v1/charges" });
    expect(result.decision).toBe("ALLOW");
  });

  test("domain NOT in allowed_domains → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, network: { allowed_domains: ["api.stripe.com"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://evil.com/steal" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("network:allowed_domain");
  });

  test("no URL args → guard skipped, normal rule eval runs", () => {
    const policy: PolicyConfig = { ...BASE, network: { blocked_domains: ["evil.com"] } };
    const result = evaluatePolicy("fetch", policy, { message: "hello world" });
    expect(result.decision).toBe("ALLOW");
  });

  test("allowed_domains is exact: 'stripe.com' does NOT cover 'api.stripe.com' → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, network: { allowed_domains: ["stripe.com"] } };
    const result = evaluatePolicy("fetch", policy, { url: "https://api.stripe.com/v1" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("network:allowed_domain");
  });
});

// ── Filesystem guard ──────────────────────────────────────────────────────────

describe("Guard 2: Filesystem", () => {
  test("path matching blocked_paths prefix → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { blocked_paths: ["/etc/"] } };
    const result = evaluatePolicy("read", policy, { path: "/etc/shadow" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("filesystem:blocked_path");
  });

  test("path with blocked extension (.pem) → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { blocked_extensions: [".pem", ".env"] } };
    const result = evaluatePolicy("read", policy, { file: "/home/user/key.pem" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("filesystem:blocked_extension");
  });

  test("path not in allowed_paths → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { allowed_paths: ["/home/app/"] } };
    const result = evaluatePolicy("write", policy, { dest: "/tmp/evil.sh" });
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("filesystem:allowed_path");
  });

  test("path in allowed_paths → continues to rule eval", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { allowed_paths: ["/home/app/"] } };
    const result = evaluatePolicy("write", policy, { dest: "/home/app/data.json" });
    expect(result.decision).toBe("ALLOW");
  });

  test("non-path string arg ('hello world') → guard skipped", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { blocked_paths: ["/etc/"] } };
    const result = evaluatePolicy("echo", policy, { message: "hello world" });
    expect(result.decision).toBe("ALLOW");
  });
});

// ── Models guard ──────────────────────────────────────────────────────────────

describe("Guard 3: Models", () => {
  test("model_id in blocked → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, models: { blocked: ["gpt-4"] } };
    const ctx: EvaluationContext = { model_id: "gpt-4" };
    const result = evaluatePolicy("anything", policy, {}, ctx);
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("models:blocked");
    expect(result.blast_radius).toBe("CRITICAL");
  });

  test("model_id not in allowed → BLOCK", () => {
    const policy: PolicyConfig = { ...BASE, models: { allowed: ["claude-sonnet-4-6"] } };
    const ctx: EvaluationContext = { model_id: "gpt-4" };
    const result = evaluatePolicy("anything", policy, {}, ctx);
    expect(result.decision).toBe("BLOCK");
    expect(result.matched_rule).toBe("models:allowed");
  });

  test("model_id in allowed → continues to rule eval", () => {
    const policy: PolicyConfig = { ...BASE, models: { allowed: ["claude-sonnet-4-6"] } };
    const ctx: EvaluationContext = { model_id: "claude-sonnet-4-6" };
    const result = evaluatePolicy("anything", policy, {}, ctx);
    expect(result.decision).toBe("ALLOW");
  });

  test("no context → guard skipped entirely", () => {
    const policy: PolicyConfig = { ...BASE, models: { blocked: ["gpt-4"] } };
    const result = evaluatePolicy("anything", policy, {});
    expect(result.decision).toBe("ALLOW");
  });
});

// ── Tool annotations guard ────────────────────────────────────────────────────

describe("Guard 4: Tool annotations", () => {
  test("always_step_up fires BEFORE normal rule matching", () => {
    const policy: PolicyConfig = {
      ...BASE,
      rules: [
        { tool: "dangerous_tool", decision: "ALLOW", reason: "allowed by rule",
          blast_radius: "LOW", reversible: true },
      ],
      tool_annotations: { dangerous_tool: { always_step_up: true } },
    };
    // Rule says ALLOW, but annotation should short-circuit to STEP_UP
    const result = evaluatePolicy("dangerous_tool", policy, {});
    expect(result.decision).toBe("STEP_UP");
    expect(result.matched_rule).toBe("tool_annotation:always_step_up");
  });

  test("compliance_tier 'restricted' → STEP_UP", () => {
    const policy: PolicyConfig = {
      ...BASE,
      tool_annotations: { admin_tool: { compliance_tier: "restricted" } },
    };
    const result = evaluatePolicy("admin_tool", policy, {});
    expect(result.decision).toBe("STEP_UP");
    expect(result.matched_rule).toBe("tool_annotation:compliance_tier");
  });

  test("compliance_tier 'system' → STEP_UP", () => {
    const policy: PolicyConfig = {
      ...BASE,
      tool_annotations: { system_tool: { compliance_tier: "system" } },
    };
    const result = evaluatePolicy("system_tool", policy, {});
    expect(result.decision).toBe("STEP_UP");
  });

  test("compliance_tier 'public' → no override, normal rule eval runs", () => {
    const policy: PolicyConfig = {
      ...BASE,
      tool_annotations: { safe_tool: { compliance_tier: "public" } },
    };
    const result = evaluatePolicy("safe_tool", policy, {});
    expect(result.decision).toBe("ALLOW");
    expect(result.matched_rule).toBe("default");
  });

  test("tool not in tool_annotations → guard skipped", () => {
    const policy: PolicyConfig = {
      ...BASE,
      tool_annotations: { other_tool: { always_step_up: true } },
    };
    const result = evaluatePolicy("my_tool", policy, {});
    expect(result.decision).toBe("ALLOW");
    expect(result.matched_rule).toBe("default");
  });
});

// ── One-level-deep constraint ─────────────────────────────────────────────────

describe("Argument scanning is one level deep only", () => {
  test("nested URL inside an object is NOT scanned by network guard", () => {
    const policy: PolicyConfig = { ...BASE, network: { blocked_domains: ["evil.com"] } };
    // The URL is nested one level deeper — should not be caught
    const result = evaluatePolicy("fetch", policy, {
      config: { url: "https://evil.com/steal" },
    });
    expect(result.decision).toBe("ALLOW");
  });

  test("nested path inside an object is NOT scanned by filesystem guard", () => {
    const policy: PolicyConfig = { ...BASE, filesystem: { blocked_paths: ["/etc/"] } };
    const result = evaluatePolicy("read", policy, {
      options: { path: "/etc/shadow" },
    });
    expect(result.decision).toBe("ALLOW");
  });
});
