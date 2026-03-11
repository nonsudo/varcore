import { stripeEnforce } from "./stripe";
import { githubEnforce } from "./github";
import { awsS3Enforce } from "./aws-s3";
import { pciDssStripe } from "./pci-dss";
import type { SchemaPackDefinition } from "../types";
import { PolicyLoadError } from "../types";

export const SCHEMA_PACKS: Record<string, SchemaPackDefinition> = {
  "stripe/enforce": stripeEnforce,
  "github/enforce": githubEnforce,
  "aws-s3/enforce": awsS3Enforce,
  "pci-dss/stripe": pciDssStripe,
};

export function resolveSchemaPack(id: string): SchemaPackDefinition {
  const pack = SCHEMA_PACKS[id];
  if (!pack) {
    throw new PolicyLoadError(
      `Unknown schema pack: "${id}". Run: nonsudo schemas list`
    );
  }
  return pack;
}
