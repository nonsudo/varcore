import type { SchemaPackDefinition } from "../types";

export const pciDssStripe: SchemaPackDefinition = {
  id: "pci-dss/stripe",
  name: "PCI-DSS Stripe",
  description:
    "PCI-DSS overlay for Stripe — flags manual capture and production cardholder data",
  rules: [
    {
      tool: "stripe_charge",
      decision: "STEP_UP",
      reason: "manual capture requires PCI-DSS review",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "capture_method", op: "eq", value: "manual" }],
      },
    },
    {
      tool: "stripe_charge",
      decision: "STEP_UP",
      reason: "production cardholder data requires PCI-DSS review",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "metadata.cardholder_env", op: "eq", value: "production" },
        ],
      },
    },
    {
      tool: "stripe_create_customer",
      decision: "BLOCK",
      reason: "customer records require a valid email address",
      blast_radius: "MED",
      reversible: true,
      params: { conditions: [{ field: "email", op: "not_exists" }] },
    },
  ],
};
