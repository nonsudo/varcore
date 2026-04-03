/**
 * nonsudo schemas list
 * nonsudo schemas show <pack-id>
 *
 * List available schema packs and inspect their rules.
 */

import { SCHEMA_PACKS } from "@varcore/policy";
import type { PolicyRule } from "@varcore/policy";

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

function formatRuleSummary(rule: PolicyRule): string {
  const tool = pad(rule.tool, 26);
  const decision = pad(rule.decision, 9);
  if (rule.params && rule.params.conditions.length > 0) {
    const cond = rule.params.conditions[0];
    const val = Array.isArray(cond.value)
      ? `[${(cond.value as unknown[]).join(",")}]`
      : String(cond.value ?? "");
    return `  ${tool}  ${decision}  ${cond.field} ${cond.op} ${val}`;
  }
  return `  ${tool}  ${decision}  (tool-level)`;
}

export function formatSchemasList(): string {
  const lines: string[] = [];
  lines.push("Available schema packs  (https://schemas.nonsudo.com)");
  lines.push("");

  for (const [id, pack] of Object.entries(SCHEMA_PACKS)) {
    lines.push(`  ${id}`);
    lines.push(`    ${pack.description}`);
    lines.push("");
  }

  lines.push("Add to nonsudo.yaml:");
  lines.push("  policy:");
  lines.push("    schemas:");
  lines.push("      - stripe/enforce");
  lines.push("    rules: []");

  return lines.join("\n");
}

export function formatSchemaShow(packId: string): string {
  const pack = SCHEMA_PACKS[packId];
  if (!pack) {
    return `error: unknown schema pack "${packId}"\nRun: nonsudo schemas list`;
  }

  const lines: string[] = [];
  lines.push(`${pack.id} — ${pack.name}`);
  lines.push(`  ${pack.description}`);
  lines.push("");
  lines.push(
    `  ${pad("tool", 26)}  ${pad("decision", 9)}  condition`
  );
  lines.push(
    `  ${pad("────", 26)}  ${pad("────────", 9)}  ─────────`
  );

  for (const rule of pack.rules) {
    lines.push(formatRuleSummary(rule));
  }

  return lines.join("\n");
}

export async function runSchemas(
  subcommand: string,
  args: string[]
): Promise<number> {
  if (!subcommand || subcommand === "list") {
    process.stdout.write(formatSchemasList() + "\n");
    return 0;
  }

  if (subcommand === "show") {
    const packId = args[0];
    if (!packId) {
      process.stderr.write("nonsudo schemas show: missing <pack-id>\n");
      process.stderr.write("Usage: nonsudo schemas show <pack-id>\n");
      return 1;
    }

    if (!SCHEMA_PACKS[packId]) {
      process.stderr.write(
        `nonsudo schemas show: unknown pack "${packId}"\nRun: nonsudo schemas list\n`
      );
      return 1;
    }

    process.stdout.write(formatSchemaShow(packId) + "\n");
    return 0;
  }

  process.stderr.write(
    `nonsudo schemas: unknown subcommand "${subcommand}"\n` +
      `Usage: nonsudo schemas list | nonsudo schemas show <pack-id>\n`
  );
  return 1;
}
