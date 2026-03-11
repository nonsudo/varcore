import type { SchemaPackDefinition } from "../types";

export const stripeEnforce: SchemaPackDefinition = {
  id: "stripe/enforce",
  name: "Stripe Enforce",
  description: "Stripe payment API safety — blocks large charges, flags $500+ for review",
  rules: [
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "charges over $1,000 require human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
    {
      tool: "stripe_charge",
      decision: "STEP_UP",
      reason: "charges over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "unsupported currency",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "currency", op: "not_in", value: ["usd", "eur", "gbp", "jpy", "cad", "aud"] },
        ],
      },
    },
    {
      tool: "stripe_create_charge",
      decision: "BLOCK",
      reason: "charges over $1,000 require human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
    {
      tool: "stripe_create_charge",
      decision: "STEP_UP",
      reason: "charges over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    {
      tool: "stripe_refund",
      decision: "STEP_UP",
      reason: "refunds over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    {
      tool: "stripe_update_customer",
      decision: "STEP_UP",
      reason: "production customer updates require review",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "metadata.env", op: "in", value: ["production", "prod"] },
        ],
      },
    },
  ],
};
