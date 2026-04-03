/**
 * nonsudo test <receipts-file> [--policy <yaml-file>]
 *
 * Offline policy replay: loads a receipt chain, runs pre-flight L1+L2
 * verification, then replays each action_receipt against the current policy
 * to detect drift between what the proxy decided and what the policy now says.
 *
 * Exit codes:
 *   0 — no drift (all decisions match, or observe mode with no would-blocks)
 *   1 — drift detected (enforcement mode) or would-block detected (observe mode)
 *   2 — pre-flight chain verification failed
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as yaml from "yaml";
import { SignedReceipt } from "@varcore/receipts";
import type { SignedActionReceipt, SignedDeadLetterReceipt } from "@varcore/receipts";
import type { PolicyConfig } from "@varcore/policy";
import { loadPolicy, evaluatePolicy } from "@varcore/policy";
import { readReceiptsFile } from "../receipts-reader";
import { verifyReceipts, loadPublicKeyFromJwk } from "./verify";

const OBSERVE_HASH = "sha256:" + "0".repeat(64);

// ── Velocity limit types (inlined from platform config) ─────────────────────

export interface VelocityLimit {
  tool: string;
  max_calls: number;
  window: "workflow" | string;
}

function loadVelocityLimits(configPath: string): VelocityLimit[] {
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = yaml.parse(raw) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== "object") return [];
    const velocity = parsed["velocity"] as { limits?: VelocityLimit[] } | undefined;
    return velocity?.limits ?? [];
  } catch {
    return [];
  }
}

// ── Result types ──────────────────────────────────────────────────────────────

export interface ReplayItemResult {
  sequenceNumber: number;
  toolName: string;
  originalDecision: string;
  replayDecision: string;
  replayReason: string;
  drifted: boolean;
}

export interface ReplayReport {
  observeMode: boolean;
  items: ReplayItemResult[];
  driftCount: number;
}

// ── Type guard ────────────────────────────────────────────────────────────────

function isActionReceipt(
  r: SignedReceipt
): r is SignedActionReceipt | SignedDeadLetterReceipt {
  return r.record_type === "action_receipt";
}

// ── Core replay logic ─────────────────────────────────────────────────────────

export function replayAgainstPolicy(
  receipts: SignedReceipt[],
  policy: PolicyConfig
): ReplayReport {
  const actionReceipts = receipts.filter(isActionReceipt);

  if (actionReceipts.length === 0) {
    return { observeMode: false, items: [], driftCount: 0 };
  }

  const observeMode = actionReceipts[0].policy_bundle_hash === OBSERVE_HASH;

  const items: ReplayItemResult[] = [];
  let driftCount = 0;

  for (const receipt of actionReceipts) {
    const toolName = receipt.tool_name;
    const originalDecision = receipt.decision;

    const result = evaluatePolicy(toolName, policy);

    const drifted = result.decision !== originalDecision;
    if (drifted) driftCount++;

    items.push({
      sequenceNumber: receipt.sequence_number,
      toolName,
      originalDecision,
      replayDecision: result.decision,
      replayReason: result.decision_reason,
      drifted,
    });
  }

  return { observeMode, items, driftCount };
}

// ── Formatting ────────────────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

export function formatTestOutput(
  filePath: string,
  report: ReplayReport,
  policyPath: string,
  policyHash: string,
  sinceDate?: Date
): string {
  const lines: string[] = [];

  lines.push(`nonsudo test — ${path.basename(filePath)}`);
  lines.push("");

  const modeLabel = report.observeMode
    ? "Observe mode: replaying against current policy"
    : "Enforcement mode: replaying against current policy";
  lines.push(`  ${modeLabel}`);
  if (sinceDate) {
    lines.push(`  Filtered to receipts since: ${sinceDate.toISOString()}`);
  }
  lines.push("");

  lines.push(
    `  ${pad("seq", 4)}  ${pad("tool", 22)}  ${pad("original", 12)}  ${pad("replay", 12)}  drift?`
  );
  lines.push(
    `  ${pad("────", 4)}  ${pad("──────────────────────", 22)}  ${pad("────────────", 12)}  ${pad("────────────", 12)}  ──────`
  );

  for (const item of report.items) {
    const seq = String(item.sequenceNumber);
    const tool = item.toolName;
    const orig = item.originalDecision;
    const replay = item.replayDecision;
    let driftAnnotation = "";
    if (item.drifted) {
      driftAnnotation = report.observeMode ? "← WOULD BLOCK" : "← DRIFT";
    }
    lines.push(
      `  ${pad(seq, 4)}  ${pad(tool, 22)}  ${pad(orig, 12)}  ${pad(replay, 12)}  ${driftAnnotation}`
    );
  }

  lines.push("");

  const count = report.items.length;
  const driftCount = report.driftCount;

  const rel = path.relative(process.cwd(), path.resolve(policyPath));
  const displayPath = rel.startsWith("..") ? path.resolve(policyPath) : `./${rel}`;
  const hashPrefix = policyHash.startsWith("sha256:") ? "sha256:" : "";
  const hexPart = policyHash.slice(hashPrefix.length);
  const truncatedHash = `${hashPrefix}${hexPart.slice(0, 16)}...`;

  if (report.observeMode) {
    const wouldBlockLabel = driftCount === 1 ? "1 would-block" : `${driftCount} would-blocks`;
    lines.push(
      `  ${count} action receipt${count !== 1 ? "s" : ""}  ·  ${wouldBlockLabel}`
    );
    lines.push("");
    lines.push(`  policy    ${displayPath}  (${truncatedHash})`);
    lines.push("");
    if (driftCount === 0) {
      lines.push("  RESULT: PASS (no policy drift)");
    } else {
      lines.push(
        `  RESULT: DRIFT (policy would block ${driftCount} of ${count} action${count !== 1 ? "s" : ""})`
      );
    }
  } else {
    const driftLabel = driftCount === 1 ? "1 drift" : `${driftCount} drifts`;
    lines.push(
      `  ${count} action receipt${count !== 1 ? "s" : ""}  ·  ${driftLabel}`
    );
    lines.push("");
    lines.push(`  policy    ${displayPath}  (${truncatedHash})`);
    lines.push("");
    if (driftCount === 0) {
      lines.push("  RESULT: PASS (no policy drift)");
    } else {
      lines.push(
        `  RESULT: DRIFT (${driftCount} of ${count} decision${driftCount !== 1 ? "s" : ""} changed)`
      );
    }
  }

  return lines.join("\n");
}

// ── Counterfactual simulation ─────────────────────────────────────────────────

export interface CounterfactualItemResult {
  sequenceNumber: number;
  toolName: string;
  originalDecision: string;
  counterfactualDecision: "ALLOW" | "BLOCK" | "UNKNOWN";
  blockReason?: string;
}

export interface CounterfactualReport {
  items: CounterfactualItemResult[];
  vcbBlockCount: number;
  paramsUnknownCount: number;
}

function parseWindowMs(window: string): number | null {
  if (window === "workflow") return null;
  const n = parseInt(window, 10);
  if (isNaN(n) || n <= 0) return null;
  if (window.endsWith("s")) return n * 1000;
  if (window.endsWith("m")) return n * 60 * 1000;
  return null;
}

function makeCounterKey(limitTool: string, window: string, calledAt: Date): string {
  if (window === "workflow") return `${limitTool}:workflow`;
  const windowMs = parseWindowMs(window) as number;
  const bucketKey = Math.floor(calledAt.getTime() / windowMs);
  return `${limitTool}:${bucketKey}`;
}

function hasParamsRule(toolName: string, policy: PolicyConfig): boolean {
  for (const rule of policy.rules) {
    if ((rule.tool === toolName || rule.tool === "*") && rule.params) {
      return true;
    }
  }
  return false;
}

export function runCounterfactualSimulation(
  receipts: SignedReceipt[],
  limits: VelocityLimit[],
  policy?: PolicyConfig
): CounterfactualReport {
  const actionReceipts = receipts.filter(isActionReceipt);
  const counters = new Map<string, number>();
  const items: CounterfactualItemResult[] = [];
  let vcbBlockCount = 0;
  let paramsUnknownCount = 0;

  for (const receipt of actionReceipts) {
    const toolName = receipt.tool_name;
    const originalDecision = receipt.decision;
    const calledAt = new Date(receipt.issued_at);

    const toolSpecific = limits.filter((l) => l.tool === toolName);
    const applicable =
      toolSpecific.length > 0
        ? toolSpecific
        : limits.filter((l) => l.tool === "*");

    let vcbBlockReason: string | undefined;
    if (applicable.length > 0) {
      for (const limit of applicable) {
        const key = makeCounterKey(limit.tool, limit.window, calledAt);
        const current = counters.get(key) ?? 0;
        if (current >= limit.max_calls) {
          vcbBlockReason = `velocity_limit_exceeded: ${limit.tool} max ${limit.max_calls}/${limit.window} (${current}/${limit.max_calls} used)`;
          break;
        }
      }
    }

    if (vcbBlockReason !== undefined) {
      items.push({
        sequenceNumber: receipt.sequence_number,
        toolName,
        originalDecision,
        counterfactualDecision: "BLOCK",
        blockReason: vcbBlockReason,
      });
      vcbBlockCount++;
    } else {
      for (const limit of applicable) {
        const key = makeCounterKey(limit.tool, limit.window, calledAt);
        counters.set(key, (counters.get(key) ?? 0) + 1);
      }

      const unknown = policy ? hasParamsRule(toolName, policy) : false;
      if (unknown) {
        items.push({
          sequenceNumber: receipt.sequence_number,
          toolName,
          originalDecision,
          counterfactualDecision: "UNKNOWN",
        });
        paramsUnknownCount++;
      } else {
        items.push({
          sequenceNumber: receipt.sequence_number,
          toolName,
          originalDecision,
          counterfactualDecision: "ALLOW",
        });
      }
    }
  }

  return { items, vcbBlockCount, paramsUnknownCount };
}

export function formatCounterfactualOutput(
  report: CounterfactualReport
): string {
  if (report.items.length === 0) return "";

  const lines: string[] = [];
  lines.push("  counterfactual simulation (VCB + params)");
  lines.push("");
  lines.push(
    `  ${pad("seq", 4)}  ${pad("tool", 22)}  ${pad("original", 12)}  counterfactual`
  );
  lines.push(
    `  ${pad("────", 4)}  ${pad("──────────────────────", 22)}  ${pad("────────────", 12)}  ──────────────`
  );

  for (const item of report.items) {
    let cfLabel: string = item.counterfactualDecision;
    if (item.counterfactualDecision === "BLOCK") cfLabel = "BLOCK (VCB)";
    if (item.counterfactualDecision === "UNKNOWN") cfLabel = "UNKNOWN (params)";
    lines.push(
      `  ${pad(String(item.sequenceNumber), 4)}  ${pad(item.toolName, 22)}  ${pad(item.originalDecision, 12)}  ${cfLabel}`
    );
  }

  lines.push("");
  if (report.vcbBlockCount > 0) {
    lines.push(
      `  VCB: ${report.vcbBlockCount} call${report.vcbBlockCount !== 1 ? "s" : ""} would have been blocked`
    );
  }
  if (report.paramsUnknownCount > 0) {
    lines.push(
      `  params: ${report.paramsUnknownCount} call${report.paramsUnknownCount !== 1 ? "s" : ""} use params-constrained rules (cannot evaluate from hash)`
    );
  }

  return lines.join("\n");
}

// ── Since filter ─────────────────────────────────────────────────────────────

export function filterReceiptsSince(
  receipts: SignedReceipt[],
  sinceDate: Date
): SignedReceipt[] {
  return receipts.filter((r) => {
    if (r.record_type !== "action_receipt") return true;
    const t = new Date(r.issued_at);
    return t >= sinceDate;
  });
}

// ── Command entry point ───────────────────────────────────────────────────────

export async function runTest(
  receiptsFile: string,
  policyFile?: string,
  opts?: { since?: string }
): Promise<number> {
  const resolved = path.resolve(receiptsFile);

  if (!fs.existsSync(resolved)) {
    process.stderr.write(`nonsudo test: file not found: ${resolved}\n`);
    return 2;
  }

  let receipts: SignedReceipt[];
  try {
    receipts = readReceiptsFile(resolved);
  } catch (err) {
    process.stderr.write(
      `nonsudo test: failed to read receipts: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 2;
  }

  if (receipts.length === 0) {
    process.stderr.write(`nonsudo test: file is empty: ${resolved}\n`);
    return 2;
  }

  let sinceDate: Date | undefined;
  if (opts?.since) {
    sinceDate = new Date(opts.since);
    if (isNaN(sinceDate.getTime())) {
      process.stderr.write(`nonsudo test: invalid --since date: ${opts.since}\n`);
      return 2;
    }
  }

  const firstKeyId = receipts[0].signature.key_id;
  let publicKey: Uint8Array;
  try {
    publicKey = loadPublicKeyFromJwk(firstKeyId);
  } catch (err) {
    process.stderr.write(
      `nonsudo test: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 2;
  }

  const verifyResult = await verifyReceipts(receipts, publicKey);
  if (!verifyResult.overallPass) {
    process.stderr.write(
      `nonsudo test: pre-flight chain verification failed — run 'nonsudo verify' for details\n`
    );
    return 2;
  }

  const policyPath = policyFile
    ? path.resolve(policyFile)
    : path.join(process.cwd(), "nonsudo.yaml");

  let policy: PolicyConfig;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    process.stderr.write(
      `nonsudo test: failed to load policy from ${policyPath}: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 2;
  }

  const rawPolicyBytes = fs.readFileSync(policyPath);
  const policyHash =
    "sha256:" + crypto.createHash("sha256").update(rawPolicyBytes).digest("hex");

  const replayReceipts = sinceDate ? filterReceiptsSince(receipts, sinceDate) : receipts;

  const report = replayAgainstPolicy(replayReceipts, policy);
  process.stdout.write(formatTestOutput(resolved, report, policyPath, policyHash, sinceDate) + "\n");

  const velocityLimits = loadVelocityLimits(policyPath);
  const cfReport = runCounterfactualSimulation(replayReceipts, velocityLimits, policy);
  if (cfReport.vcbBlockCount > 0 || cfReport.paramsUnknownCount > 0) {
    const cfOut = formatCounterfactualOutput(cfReport);
    if (cfOut) process.stdout.write("\n" + cfOut + "\n");
  }

  if (report.driftCount > 0 || cfReport.vcbBlockCount > 0) return 1;
  return 0;
}
