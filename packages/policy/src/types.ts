export interface ParamsCondition {
  field: string;
  op:
    | "eq"
    | "neq"
    | "gt"
    | "gte"
    | "lt"
    | "lte"
    | "match"
    | "not_match"
    | "in"
    | "not_in"
    | "exists"
    | "not_exists";
  value?: unknown;
}

export interface ParamsBlock {
  conditions: ParamsCondition[];
}

export interface PolicyRule {
  tool: string;
  decision: "ALLOW" | "BLOCK" | "FAIL_OPEN" | "FAIL_CLOSED" | "STEP_UP";
  reason: string;
  blast_radius: "LOW" | "MED" | "HIGH" | "CRITICAL";
  reversible: boolean;
  /** Optional parameter conditions — AND logic, all must be satisfied for rule to fire. */
  params?: ParamsBlock;
  /**
   * When true and this rule overlaps with a schema pack rule for the same tool,
   * the pack's params-conditional rules are injected BEFORE this operator rule.
   * Defaults to false (operator rule wins; pack rules not applied for this tool).
   */
  merge_schema_params?: boolean;
  /**
   * VAR-Money v1.0: declares this tool call as a money action requiring budget
   * enforcement and outcome binding (Walk/Run mode only).
   */
  money_action?: boolean;
  /**
   * VAR-Money v1.0 RI-4: dot-path into action arguments (max depth 5) to extract
   * the amount in minor units. When set and money_action is true, absence or
   * invalidity of the field causes the proxy to force STEP_UP.
   */
  amount_field?: string;
  /**
   * VAR-Money v1.0 RI-6: maximum cumulative spend in minor units for the
   * spend_window. When exceeded, the proxy emits DEAD_LETTER with budget_exceeded.
   */
  max_spend?: number;
  /**
   * VAR-Money v1.0 RI-6: spend window for budget tracking. Defaults to "session".
   */
  spend_window?: "session" | "daily" | "monthly";
  /**
   * VAR-Money v1.0 RI-6: optional monthly cap in minor units, enforced
   * independently of max_spend.
   */
  monthly_cap?: number;
  /**
   * VAR-Money v1.0 RI-6: TTL hours for TIMEOUT reservations before they are
   * automatically released and a reservation_expired receipt is emitted. Default: 24.
   */
  reservation_ttl_hours?: number;
  /**
   * VAR-Money v1.0 RI-7: dot-path into action arguments to extract the idempotency
   * key. Duplicate (tool_name + key) within the same workflow session → DEAD_LETTER.
   */
  idempotency_key_field?: string;
  /**
   * VAR-Money v1.0 RI-8: built-in projection ID to compute a deterministic hash of
   * the upstream response. The hash is stored as projection_hash in the post_receipt.
   * Only applied on SUCCESS outcomes. Must be a key in BUILTIN_PROJECTIONS.
   */
  projection_id?: string;
}

export interface PolicyConfig {
  default: "ALLOW" | "BLOCK";
  rules: PolicyRule[];
  /**
   * Schema pack IDs to resolve and merge into the effective policy.
   * Example: ["stripe/enforce", "github/enforce"]
   * Unknown IDs throw PolicyLoadError at startup.
   */
  schemas?: string[];
}

export interface EvaluationResult {
  decision: "ALLOW" | "BLOCK" | "FAIL_OPEN" | "FAIL_CLOSED" | "STEP_UP";
  decision_reason: string;
  blast_radius: "LOW" | "MED" | "HIGH" | "CRITICAL";
  reversible: boolean;
  /** Tool name of matched rule, or "*" for wildcard, or "default", or "${tool}:param:..." for params match */
  matched_rule: string;
  /** Present when a param condition triggered the decision — first condition in the params block. */
  matched_param_condition?: ParamsCondition;
  /**
   * VAR-Money v1.0: true when the matched rule declares money_action: true.
   * Absent/false for non-money actions.
   */
  money_action?: boolean;
}

/**
 * A compiled schema pack — a named collection of PolicyRules covering specific tools.
 * Resolved at loadPolicy() time and merged into the effective policy.
 */
export interface SchemaPackDefinition {
  id: string;
  name: string;
  description: string;
  rules: PolicyRule[];
}

/** Thrown when a schema pack ID is unknown or when the policy YAML is invalid. */
export class PolicyLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyLoadError";
  }
}
