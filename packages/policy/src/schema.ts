import Ajv from "ajv";

const ajv = new Ajv({ allErrors: true });

// Schema for a single params condition
const paramsConditionSchema = {
  type: "object",
  required: ["field", "op"],
  additionalProperties: false,
  properties: {
    field: { type: "string", minLength: 1 },
    op: {
      type: "string",
      enum: [
        "eq", "neq", "gt", "gte", "lt", "lte",
        "match", "not_match", "in", "not_in",
        "exists", "not_exists",
      ],
    },
    value: {}, // any type — validated at runtime by params-evaluator
  },
};

// Schema for the optional params block on a rule
const paramsBlockSchema = {
  type: "object",
  required: ["conditions"],
  additionalProperties: false,
  properties: {
    conditions: {
      type: "array",
      minItems: 1,
      items: paramsConditionSchema,
    },
  },
};

const networkSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    allowed_domains: { type: "array", items: { type: "string" } },
    blocked_domains: { type: "array", items: { type: "string" } },
    require_tls: { type: "boolean" },
  },
};

const filesystemSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    allowed_paths: { type: "array", items: { type: "string" } },
    blocked_paths: { type: "array", items: { type: "string" } },
    blocked_extensions: { type: "array", items: { type: "string" } },
  },
};

const modelsSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    allowed: { type: "array", items: { type: "string" } },
    blocked: { type: "array", items: { type: "string" } },
  },
};

const toolAnnotationSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    compliance_tier: { type: "string", enum: ["public", "internal", "restricted", "system"] },
    always_step_up: { type: "boolean" },
  },
};

const toolAnnotationsSchema = {
  type: "object",
  additionalProperties: toolAnnotationSchema,
};

// Plain JSON schema — avoids AJV's JSONSchemaType enum typing constraints
const policySchema = {
  type: "object",
  required: ["default", "rules"],
  additionalProperties: false,
  properties: {
    default: {
      type: "string",
      enum: ["ALLOW", "BLOCK"],
    },
    rules: {
      type: "array",
      items: {
        type: "object",
        required: ["tool", "decision", "reason", "blast_radius", "reversible"],
        additionalProperties: false,
        properties: {
          tool: { type: "string", minLength: 1 },
          decision: {
            type: "string",
            enum: ["ALLOW", "BLOCK", "FAIL_OPEN", "FAIL_CLOSED", "STEP_UP"],
          },
          reason: { type: "string", minLength: 1 },
          blast_radius: {
            type: "string",
            enum: ["LOW", "MED", "HIGH", "CRITICAL"],
          },
          reversible: { type: "boolean" },
          params: paramsBlockSchema,
          merge_schema_params: { type: "boolean" },
          money_action: { type: "boolean" },
          // VAR-Money v1.0 fields
          amount_field: { type: "string", minLength: 1 },
          max_spend: { type: "number", minimum: 0 },
          spend_window: { type: "string", enum: ["session", "daily", "monthly"] },
          monthly_cap: { type: "number", minimum: 0 },
          reservation_ttl_hours: { type: "number", minimum: 0 },
          idempotency_key_field: { type: "string", minLength: 1 },
          projection_id: { type: "string", minLength: 1 },
        },
      },
    },
    schemas: {
      type: "array",
      items: { type: "string", minLength: 1 },
    },
    network: networkSchema,
    filesystem: filesystemSchema,
    models: modelsSchema,
    tool_annotations: toolAnnotationsSchema,
  },
};

export const validatePolicyConfig = ajv.compile(policySchema);
