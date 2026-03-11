import * as fs from "fs";
import * as crypto from "crypto";
import * as yaml from "js-yaml";
import canonicalize from "canonicalize";
import { validatePolicyConfig } from "./schema";
import { evaluateParams, ConditionResult } from "./params-evaluator";
import { resolveSchemaPack } from "./schemas/index";

export type {
  PolicyRule,
  PolicyConfig,
  EvaluationResult,
  ParamsCondition,
  ParamsBlock,
  SchemaPackDefinition,
} from "./types";
export { evaluateParams } from "./params-evaluator";
export type { ConditionResult } from "./params-evaluator";
export { PolicyLoadError } from "./types";
export { SCHEMA_PACKS, resolveSchemaPack } from "./schemas/index";

import type { PolicyConfig, PolicyRule, EvaluationResult } from "./types";

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
  const canonical = canonicalize(policy as unknown as object) ?? "{}";
  const hex = crypto.createHash("sha256").update(canonical).digest("hex");
  return "sha256:" + hex;
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
  actionArguments?: Record<string, unknown>
): EvaluationResult {
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
