import type { SchemaPackDefinition } from "../types";

export const githubEnforce: SchemaPackDefinition = {
  id: "github/enforce",
  name: "GitHub Enforce",
  description:
    "GitHub API safety — prevents force-push, protects main branch, gates webhook creation",
  rules: [
    {
      tool: "github_push",
      decision: "BLOCK",
      reason: "force push is prohibited",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "force", op: "eq", value: true }] },
    },
    {
      tool: "github_push",
      decision: "STEP_UP",
      reason: "push to protected branch requires review",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "branch", op: "in", value: ["main", "master", "production"] },
        ],
      },
    },
    {
      tool: "github_delete_branch",
      decision: "BLOCK",
      reason: "deletion of protected branches is prohibited",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "branch", op: "in", value: ["main", "master", "production"] },
        ],
      },
    },
    {
      tool: "github_create_webhook",
      decision: "STEP_UP",
      reason: "webhook creation requires review",
      blast_radius: "MED",
      reversible: true,
    },
  ],
};
