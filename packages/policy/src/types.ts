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

export interface NetworkPolicy {
  /**
   * If non-empty, agent may only contact these hostnames (exact match).
   * Note: allowlist is exact-match only — "stripe.com" does NOT cover "api.stripe.com".
   * Subdomain coverage requires explicit entries.
   */
  allowed_domains?: string[];
  /**
   * Hostnames always blocked. Matching is exact OR subdomain suffix:
   * "ngrok.io" blocks "ngrok.io" and "abc.ngrok.io" but not "notngrok.io".
   * Note: blocked_domains uses suffix matching; allowed_domains uses exact matching.
   * This asymmetry is intentional — blocklist is conservative, allowlist is strict.
   */
  blocked_domains?: string[];
  /** If true, any URL argument using http:// (not https://) is blocked. */
  require_tls?: boolean;
}

export interface FilesystemPolicy {
  /**
   * If non-empty, file path arguments must start with one of these prefixes.
   * Exact prefix match only — no glob.
   */
  allowed_paths?: string[];
  /** File path arguments matching any of these prefixes are blocked. */
  blocked_paths?: string[];
  /** File path arguments with any of these extensions are blocked, e.g. [".pem", ".env"]. */
  blocked_extensions?: string[];
}

export interface ModelsPolicy {
  /**
   * If non-empty, only these model IDs are permitted. Exact match only — no glob.
   * e.g. ["claude-sonnet-4-6", "claude-opus-4-6"]
   */
  allowed?: string[];
  /**
   * These model IDs are always blocked. Exact match only — no glob.
   */
  blocked?: string[];
}

export interface ToolAnnotation {
  /** Compliance tier — affects default step-up behavior. */
  compliance_tier?: "public" | "internal" | "restricted" | "system";
  /**
   * If true, always escalate to STEP_UP regardless of normal rule matching.
   * Short-circuits before Pass 1 (exact rule match) in evaluatePolicy.
   */
  always_step_up?: boolean;
}

export interface EvaluationContext {
  /** Model ID for the current session, e.g. "claude-sonnet-4-6". */
  model_id?: string;
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
  /** Network egress controls — evaluated before rule matching. */
  network?: NetworkPolicy;
  /** Filesystem access controls — evaluated before rule matching. */
  filesystem?: FilesystemPolicy;
  /** Model allowlist/blocklist — evaluated before rule matching. */
  models?: ModelsPolicy;
  /** Per-tool annotations keyed by exact tool name. */
  tool_annotations?: Record<string, ToolAnnotation>;
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
