import type { SchemaPackDefinition } from "../types";

export const awsS3Enforce: SchemaPackDefinition = {
  id: "aws-s3/enforce",
  name: "AWS S3 Enforce",
  description:
    "AWS S3 safety — blocks non-tmp object deletion, prohibits bucket deletion",
  rules: [
    {
      tool: "s3_delete_object",
      decision: "BLOCK",
      reason: "only objects in the tmp/ prefix may be deleted without review",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "key", op: "not_match", value: "^tmp/" }] },
    },
    {
      tool: "s3_delete_bucket",
      decision: "BLOCK",
      reason: "bucket deletion requires explicit human approval",
      blast_radius: "CRITICAL",
      reversible: false,
    },
    {
      tool: "s3_put_bucket_policy",
      decision: "STEP_UP",
      reason: "bucket policy changes require review",
      blast_radius: "HIGH",
      reversible: true,
    },
  ],
};
