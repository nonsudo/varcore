import * as fs from "fs";
import * as yaml from "js-yaml";
import { canonicalHash } from "@varcore/core";
import { validatePolicyConfig } from "./schema";
import { evaluateParams, ConditionResult } from "./params-evaluator";
import { resolveSchemaPack } from "./schemas/index";

export type {
  PolicyRule,
  PolicyConfig,
  EvaluationResult,
  EvaluationContext,
  ParamsCondition,
  ParamsBlock,
  SchemaPackDefinition,
  NetworkPolicy,
  FilesystemPolicy,
  ModelsPolicy,
  ToolAnnotation,
} from "./types";
export { evaluateParams } from "./params-evaluator";
export type { ConditionResult } from "./params-evaluator";
export { PolicyLoadError } from "./types";
export { SCHEMA_PACKS, resolveSchemaPack } from "./schemas/index";

import type { PolicyConfig, PolicyRule, EvaluationResult, EvaluationContext } from "./types";

// ── Backward-compatible mode normalizer ──────────────────────────────────────

type DeploymentMode = "observe" | "enforce" | "attest";

const MODE_ALIASES: Record<string, DeploymentMode> = {
  crawl: "observe",
  walk: "enforce",
  run: "attest",
};

function normalizeMode(raw: string): DeploymentMode {
  if (raw in MODE_ALIASES) {
    const normalized = MODE_ALIASES[raw as keyof typeof MODE_ALIASES];
    process.stderr.write(`[nonsudo] mode "${raw}" deprecated. Use "${normalized}".\n`);
    return normalized;
  }
  return raw as DeploymentMode;
}

/**
 * Merge schema pack rules into the operator rule set.
 *
 * Algorithm:
 *   1. For each operator rule with merge_schema_params: true → inject
 *      pack rules for that tool BEFORE the first such operator rule.
 *   2. For operator rules with merge_schema_params absent/false → pack
 *      rules for that tool are skipped entirely (operator wins).
 *   3. Pack rules for tools NOT covered by any operator rule are
 *      appended at the end in the order they appear across packs.
 */
export function mergePackRules(
  operatorRules: PolicyRule[],
  allPackRules: PolicyRule[]
): PolicyRule[] {
  // Tools claimed by any operator rule (non-wildcard)
  const operatorToolSet = new Set<string>(
    operatorRules.filter((r) => r.tool !== "*").map((r) => r.tool)
  );

  const result: PolicyRule[] = [];
  const injectedPackToolSet = new Set<string>();

  for (const rule of operatorRules) {
    if (rule.merge_schema_params === true && !injectedPackToolSet.has(rule.tool)) {
      // Inject pack rules for this tool before the operator rule
      const packRulesForTool = allPackRules.filter((r) => r.tool === rule.tool);
      result.push(...packRulesForTool);
      injectedPackToolSet.add(rule.tool);
    }
    result.push(rule);
  }

  // Append pack rules for tools not covered by any operator rule
  for (const packRule of allPackRules) {
    if (!operatorToolSet.has(packRule.tool)) {
      result.push(packRule);
    }
  }

  return result;
}

/**
 * Compute a deterministic SHA-256 hash of the merged effective policy.
 * Uses JSON Canonicalization Scheme (RFC 8785) for determinism.
 * Returns "sha256:<hex>".
 */
export function computePolicyBundleHash(policy: PolicyConfig): string {
  return canonicalHash(policy);
}

/**
 * Load and validate a PolicyConfig from a nonsudo.yaml file.
 * Reads the `policy` block from the YAML document.
 * Merges schema packs specified in policy.schemas (throws PolicyLoadError
 * for unknown pack IDs at startup).
 * Throws with a clear message if the file is missing, malformed, or fails
 * schema validation.
 */
export function loadPolicy(yamlPath: string): PolicyConfig {
  if (!fs.existsSync(yamlPath)) {
    throw new Error(`Policy file not found: ${yamlPath}`);
  }

  let doc: unknown;
  try {
    doc = yaml.load(fs.readFileSync(yamlPath, "utf8"));
  } catch (err) {
    throw new Error(
      `Policy file parse error in ${yamlPath}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!doc || typeof doc !== "object") {
    throw new Error(`Policy file invalid: expected a YAML object in ${yamlPath}`);
  }

  const raw = doc as Record<string, unknown>;

  // Normalize deprecated mode values (crawl→observe, walk→enforce, run→attest)
  if (typeof raw["mode"] === "string") {
    raw["mode"] = normalizeMode(raw["mode"]);
  }

  const policyBlock = raw["policy"];

  if (!policyBlock || typeof policyBlock !== "object") {
    throw new Error(
      `Policy file missing 'policy' block in ${yamlPath}`
    );
  }

  const valid = validatePolicyConfig(policyBlock);
  if (!valid) {
    const errors = validatePolicyConfig.errors
      ?.map((e) => `${e.instancePath || "/"} ${e.message}`)
      .join("; ");
    throw new Error(`Policy config validation failed in ${yamlPath}: ${errors}`);
  }

  const config = policyBlock as unknown as PolicyConfig;

  // Merge schema packs if specified
  if (config.schemas && config.schemas.length > 0) {
    const packIds = [...new Set(config.schemas)]; // de-duplicate
    const allPackRules: PolicyRule[] = [];

    for (const id of packIds) {
      const pack = resolveSchemaPack(id); // throws PolicyLoadError if unknown
      allPackRules.push(...pack.rules);
    }

    config.rules = mergePackRules(config.rules, allPackRules);
  }

  return config;
}

/**
 * Evaluate a tool call against the policy config.
 * Pure synchronous function — no I/O, no async, never throws.
 *
 * Matching order:
 * 1. Exact tool name match (first match wins, top-to-bottom)
 *    - If rule has params: only fires when evaluateParams returns true
 *    - If no actionArguments provided: params rules are skipped (can't evaluate from hash)
 * 2. Wildcard "*" match (first matching wildcard rule, top-to-bottom)
 * 3. policy.default fallback
 */
export function evaluatePolicy(
  toolName: string,
  policy: PolicyConfig,
  actionArguments?: Record<string, unknown>,
  context?: EvaluationContext
): EvaluationResult {
  // ── Guard 1: Network egress ──────────────────────────────────────────────
  if (policy.network && actionArguments) {
    const net = policy.network;
    for (const val of Object.values(actionArguments)) {
      if (typeof val !== "string") continue;
      if (!val.startsWith("http://") && !val.startsWith("https://")) continue;

      const afterProtocol = val.slice(val.indexOf("://") + 3);
      const hostname = afterProtocol.split("/")[0].split("?")[0].split("#")[0];

      if (net.require_tls === true && val.startsWith("http://")) {
        return { decision: "BLOCK", decision_reason: "network: require_tls violated",
          blast_radius: "HIGH", reversible: false, matched_rule: "network:require_tls" };
      }

      for (const pattern of net.blocked_domains ?? []) {
        if (hostname === pattern || hostname.endsWith("." + pattern)) {
          return { decision: "BLOCK", decision_reason: "network: domain in blocklist",
            blast_radius: "HIGH", reversible: false, matched_rule: "network:blocked_domain" };
        }
      }

      const allowedDomains = net.allowed_domains ?? [];
      if (allowedDomains.length > 0) {
        if (!allowedDomains.includes(hostname)) {
          return { decision: "BLOCK", decision_reason: "network: domain not in allowlist",
            blast_radius: "HIGH", reversible: false, matched_rule: "network:allowed_domain" };
        }
      }
    }
  }

  // ── Guard 2: Filesystem ──────────────────────────────────────────────────
  if (policy.filesystem && actionArguments) {
    const fsp = policy.filesystem;
    for (const val of Object.values(actionArguments)) {
      if (typeof val !== "string") continue;
      if (!val.startsWith("/") && !val.startsWith("~/") && !val.startsWith("./") && !val.startsWith("../")) continue;

      for (const prefix of fsp.blocked_paths ?? []) {
        if (val.startsWith(prefix)) {
          return { decision: "BLOCK", decision_reason: "filesystem: path in blocklist",
            blast_radius: "HIGH", reversible: false, matched_rule: "filesystem:blocked_path" };
        }
      }

      for (const ext of fsp.blocked_extensions ?? []) {
        if (val.endsWith(ext)) {
          return { decision: "BLOCK", decision_reason: "filesystem: extension blocked",
            blast_radius: "HIGH", reversible: false, matched_rule: "filesystem:blocked_extension" };
        }
      }

      const allowedPaths = fsp.allowed_paths ?? [];
      if (allowedPaths.length > 0) {
        if (!allowedPaths.some((p) => val.startsWith(p))) {
          return { decision: "BLOCK", decision_reason: "filesystem: path not in allowlist",
            blast_radius: "HIGH", reversible: false, matched_rule: "filesystem:allowed_path" };
        }
      }
    }
  }

  // ── Guard 3: Models ──────────────────────────────────────────────────────
  if (policy.models && context?.model_id) {
    const modelId = context.model_id;
    const mdl = policy.models;

    for (const id of mdl.blocked ?? []) {
      if (modelId === id) {
        return { decision: "BLOCK", decision_reason: "models: model_id is blocked",
          blast_radius: "CRITICAL", reversible: false, matched_rule: "models:blocked" };
      }
    }

    const allowedModels = mdl.allowed ?? [];
    if (allowedModels.length > 0) {
      if (!allowedModels.includes(modelId)) {
        return { decision: "BLOCK", decision_reason: "models: model_id not in allowlist",
          blast_radius: "CRITICAL", reversible: false, matched_rule: "models:allowed" };
      }
    }
  }

  // ── Guard 4: Tool annotations ────────────────────────────────────────────
  if (policy.tool_annotations) {
    const annotation = policy.tool_annotations[toolName];
    if (annotation) {
      if (annotation.always_step_up === true) {
        return { decision: "STEP_UP", decision_reason: "tool_annotation: always_step_up",
          blast_radius: "HIGH", reversible: false, matched_rule: "tool_annotation:always_step_up" };
      }
      if (annotation.compliance_tier === "restricted" || annotation.compliance_tier === "system") {
        return { decision: "STEP_UP", decision_reason: "tool_annotation: compliance_tier requires approval",
          blast_radius: "HIGH", reversible: false, matched_rule: "tool_annotation:compliance_tier" };
      }
    }
  }

  /**
   * Helper: evaluate params and return the ConditionResult, or null if actionArguments
   * were not provided (historical replay mode — params rules are skipped).
   */
  function evalParams(params: NonNullable<typeof policy.rules[0]["params"]>): ConditionResult | null {
    if (!actionArguments) return null;
    return evaluateParams(params, actionArguments);
  }

  /**
   * When evaluateParams returns "type_error", return fail-closed BLOCK immediately.
   * This prevents type confusion attacks from silently bypassing params-constrained rules.
   */
  function typeErrorBlock(context: string): EvaluationResult {
    return {
      decision: "BLOCK",
      decision_reason: "params_type_error",
      blast_radius: "HIGH",
      reversible: false,
      matched_rule: `${context}:params_type_error`,
    };
  }

  // Pass 1: exact match
  for (const rule of policy.rules) {
    if (rule.tool === toolName) {
      if (rule.params) {
        const paramsResult = evalParams(rule.params);
        if (paramsResult === null) continue; // no actionArguments — skip in replay
        if (paramsResult === "type_error") return typeErrorBlock(toolName);
        if (paramsResult === "no_match") continue;
        // paramsResult === "match" — fire this rule
        const cond = rule.params.conditions[0];
        return {
          decision: rule.decision,
          decision_reason: rule.reason,
          blast_radius: rule.blast_radius,
          reversible: rule.reversible,
          matched_rule: `${toolName}:param:${cond.field} ${cond.op} ${String(cond.value)}`,
          matched_param_condition: cond,
          ...(rule.money_action ? { money_action: true } : {}),
        };
      }
      // No params — fire on tool name alone (existing behaviour)
      return {
        decision: rule.decision,
        decision_reason: rule.reason,
        blast_radius: rule.blast_radius,
        reversible: rule.reversible,
        matched_rule: rule.tool,
        ...(rule.money_action ? { money_action: true } : {}),
      };
    }
  }

  // Pass 2: wildcard match
  for (const rule of policy.rules) {
    if (rule.tool === "*") {
      if (rule.params) {
        const paramsResult = evalParams(rule.params);
        if (paramsResult === null) continue;
        if (paramsResult === "type_error") return typeErrorBlock("*");
        if (paramsResult === "no_match") continue;
        const cond = rule.params.conditions[0];
        return {
          decision: rule.decision,
          decision_reason: rule.reason,
          blast_radius: rule.blast_radius,
          reversible: rule.reversible,
          matched_rule: `*:param:${cond.field} ${cond.op} ${String(cond.value)}`,
          matched_param_condition: cond,
          ...(rule.money_action ? { money_action: true } : {}),
        };
      }
      return {
        decision: rule.decision,
        decision_reason: rule.reason,
        blast_radius: rule.blast_radius,
        reversible: rule.reversible,
        matched_rule: "*",
        ...(rule.money_action ? { money_action: true } : {}),
      };
    }
  }

  // Pass 3: default fallback
  return {
    decision: policy.default,
    decision_reason: "no matching rule — policy default applied",
    blast_radius: "LOW",
    reversible: true,
    matched_rule: "default",
  };
}
