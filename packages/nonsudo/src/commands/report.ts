/**
 * nonsudo report [options]
 *
 * Two modes:
 * 1. File-based: --workflow <id> — reads ~/.nonsudo/receipts/<id>.ndjson, outputs Markdown report.
 * 2. Store-based: --workflow-id <id> | --all — uses receipt store (PlainTextReportRenderer).
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  ReceiptStore,
  ReceiptRow,
  WorkflowSummary,
  ReportRenderer,
} from "@varcore/store";
import { loadTsaSidecar } from "@varcore/receipts";
import type { SignedReceipt } from "@varcore/receipts";
import { readReceiptsFile } from "../receipts-reader";
import { resolvePublicKey, verifyReceipts } from "./verify";

const DEFAULT_DB = path.join(os.homedir(), ".nonsudo", "receipts.db");
const DEFAULT_RECEIPTS_DIR = path.join(os.homedir(), ".nonsudo", "receipts");
const DEFAULT_BUDGET_CAP_MINOR = 50_000;

// ── Plain text renderer ─────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

export class PlainTextReportRenderer implements ReportRenderer {
  readonly extension = "txt";

  async render(
    workflows: WorkflowSummary[],
    receipts: Map<string, ReceiptRow[]>
  ): Promise<void> {
    const lines: string[] = [];
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

    lines.push(`NonSudo Verifiable Action Receipt Report`);
    lines.push(`Generated: ${now} · NonSudo v1.0.0`);
    lines.push(``);
    lines.push(
      `NOTE: This report presents cryptographically verifiable evidence of AI agent tool call activity.`
    );
    lines.push(
      `It does not constitute legal compliance certification. To independently verify: nonsudo verify <receipts_file>`
    );

    const ruler = "─".repeat(77);

    for (const wf of workflows) {
      lines.push(``);
      lines.push(ruler);
      lines.push(`Workflow: ${wf.workflow_id}`);
      lines.push(`Agent:    ${wf.agent_id}`);
      lines.push(`Started:  ${wf.initiated_at}`);

      const closeStr = wf.closed_at
        ? `${wf.closed_at}${wf.close_reason ? ` (${wf.close_reason})` : ""}`
        : "open";
      lines.push(`Closed:   ${closeStr}`);

      const durationMs = wf.session_duration_ms ?? 0;
      const calls = wf.total_calls ?? "—";
      const blocked = wf.total_blocked ?? "—";
      lines.push(
        `Duration: ${durationMs.toLocaleString()}ms · Calls: ${calls} · Blocked: ${blocked} · Complete: ${wf.complete ? "yes" : "no"}`
      );
      lines.push(``);

      const wfReceipts = receipts.get(wf.workflow_id) ?? [];
      lines.push(
        `  ${pad("Seq", 5)}  ${pad("Type", 20)}  ${pad("Tool", 22)}  ${pad("Decision", 12)}  ${pad("L1", 6)}  ${pad("L2", 6)}  ${pad("L3", 6)}`
      );
      lines.push(
        `  ${pad("─".repeat(5), 5)}  ${pad("─".repeat(20), 20)}  ${pad("─".repeat(22), 22)}  ${pad("─".repeat(12), 12)}  ${pad("──────", 6)}  ${pad("──────", 6)}  ${pad("──────", 6)}`
      );

      for (const r of wfReceipts) {
        const rt = r.record_type;
        const tool = (rt === "action_receipt" ? r.tool_name : "—") ?? "—";
        const decision = (rt === "action_receipt" ? r.decision : "—") ?? "—";
        lines.push(
          `  ${pad(String(r.sequence_number), 5)}  ${pad(rt, 20)}  ${pad(tool, 22)}  ${pad(decision, 12)}  ${pad(r.l1_status, 6)}  ${pad(r.l2_status.split(":")[0], 6)}  ${pad(r.l3_status, 6)}`
        );
      }

      const allL1Pass = wfReceipts.every((r) => r.l1_status === "PASS");
      const allL2Pass = wfReceipts.every(
        (r) => r.l2_status === "PASS" || r.l2_status.startsWith("PASS")
      );
      const chainIntegrity = allL1Pass && allL2Pass ? "PASS" : "FAIL";
      lines.push(``);
      lines.push(`Chain integrity: ${chainIntegrity}`);
    }

    lines.push(ruler);
    process.stdout.write(lines.join("\n") + "\n");
  }
}

// ── File-based report helpers ───────────────────────────────────────────────

function formatAmount(minor: number | null | undefined, currency?: string): string {
  if (minor == null) return "—";
  const isUsd = (currency ?? "usd").toLowerCase() === "usd";
  const val = (minor / 100).toFixed(2);
  return isUsd ? `$${val}` : `${val} ${currency ?? ""}`;
}

function successfulPreReceiptIds(receipts: SignedReceipt[]): Set<string> {
  const ids = new Set<string>();
  for (const r of receipts) {
    if (r.record_type !== "post_receipt") continue;
    const rr = r as unknown as Record<string, unknown>;
    if (rr.terminal_outcome === "SUCCESS") {
      const preId = rr.pre_receipt_id as string | undefined;
      if (preId) ids.add(preId);
    }
  }
  return ids;
}

function upstreamNotCalled(r: Record<string, unknown>, successIds?: Set<string>): boolean {
  if (r.upstream_call_initiated === false) return true;
  if (r.decision === "BLOCK") return true;
  if (r.decision === "FAIL_CLOSED") return true;
  if (r.queue_status === "DEAD_LETTER") return true;
  if (r.decision === "STEP_UP") {
    const receiptId = r.receipt_id as string | undefined;
    if (successIds && receiptId && successIds.has(receiptId)) return false;
    return true;
  }
  return false;
}

function computeAmountProtected(receipts: SignedReceipt[]): number {
  const successIds = successfulPreReceiptIds(receipts);
  let sum = 0;
  for (const r of receipts) {
    if (r.record_type !== "action_receipt") continue;
    const rr = r as unknown as Record<string, unknown>;
    if (rr.money_action !== true) continue;
    if (!upstreamNotCalled(rr, successIds)) continue;
    const amt = rr.amount_minor_units;
    if (typeof amt === "number" && Number.isFinite(amt)) sum += amt;
  }
  return sum;
}

function computeAmountProcessed(receipts: SignedReceipt[]): number {
  const successIds = successfulPreReceiptIds(receipts);
  let sum = 0;
  for (const r of receipts) {
    if (r.record_type !== "action_receipt") continue;
    const rr = r as unknown as Record<string, unknown>;
    if (rr.money_action !== true) continue;
    const isAllow = rr.decision === "ALLOW";
    const isStepUpSuccess = rr.decision === "STEP_UP" &&
      successIds.has(rr.receipt_id as string);
    if (!isAllow && !isStepUpSuccess) continue;
    const amt = rr.amount_minor_units;
    if (typeof amt === "number" && Number.isFinite(amt)) sum += amt;
  }
  return sum;
}

function receiptIdShort(id: string | undefined): string {
  if (!id) return "—";
  return id.length > 12 ? id.slice(0, 12) + "..." : id;
}

const DEGRADED_RECORD_TYPES = new Set(["recovery_event", "budget_warning", "reservation_expired"]);

function buildEnforcementMarkdown(
  workflowId: string,
  receipts: SignedReceipt[],
  receiptFilePath: string,
  verifyResult: Awaited<ReturnType<typeof verifyReceipts>>,
  policyProvided: boolean
): string {
  const manifest = receipts[0] as unknown as Record<string, unknown>;
  const policyHash = (manifest.policy_bundle_hash as string) ?? "";
  const rawMode = (manifest.mode as string) ?? "enforce";
  const mode = rawMode === "crawl" ? "observe" : rawMode === "walk" ? "enforce" : rawMode;
  const keyId = receipts[0].signature.key_id;
  const manifestReceiptId = (manifest.receipt_id as string) ?? receipts[0].signature?.key_id ?? "";

  const actionReceipts = receipts.filter((r) => r.record_type === "action_receipt");
  const successIds = successfulPreReceiptIds(receipts);
  const allowed = actionReceipts.filter((r) => {
    const rr = r as unknown as Record<string, unknown>;
    if (rr.decision === "ALLOW") return true;
    if (rr.decision === "STEP_UP" && successIds.has(rr.receipt_id as string)) return true;
    return false;
  }).length;
  const blocked = actionReceipts.length - allowed;
  const amountProcessed = computeAmountProcessed(receipts);
  const amountProtected = computeAmountProtected(receipts);
  const policyHashShort = policyHash.slice(0, 16);

  const l4Result = verifyResult.l4Result;
  let l4Status: string;
  let l4Detail: string;
  if (!policyProvided) {
    l4Status = "WARN";
    l4Detail = "policy not provided, budget check skipped";
  } else if (l4Result?.status === "N/A") {
    l4Status = "N/A";
    l4Detail = "No money actions in chain";
  } else if (l4Result?.status === "PASS") {
    l4Status = "PASS";
    l4Detail = "All money actions have terminal posts";
  } else if (l4Result?.status === "FAIL") {
    l4Status = "FAIL";
    l4Detail = (l4Result.violations ?? []).map((v) => v.message).join("; ");
  } else if (l4Result?.status === "WARN") {
    l4Status = "WARN";
    l4Detail = (l4Result.violations ?? []).map((v) => v.message).join("; ");
  } else {
    l4Status = "WARN";
    l4Detail = "policy not provided, budget check skipped";
  }

  const lines: string[] = [];
  lines.push("# NonSudo Enforcement Report");
  lines.push("");
  lines.push(`**Workflow:** ${workflowId}`);
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push(`**Policy hash:** ${policyHash}`);
  lines.push(`**Mode:** ${mode}`);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Executive Summary");
  lines.push("");
  const n = actionReceipts.length;
  lines.push(
    `${n} tool call attempt${n !== 1 ? "s" : ""} were made in this session under policy ${policyHashShort}.`
  );
  lines.push(`${allowed} were allowed and executed. ${blocked} were blocked before reaching the upstream.`);
  lines.push(
    `${formatAmount(amountProcessed)} USD was processed. ${formatAmount(amountProtected)} USD was prevented by enforcement.`
  );
  const l2Pass = verifyResult.results.every((r) => r.l2.pass);
  lines.push(
    `The receipt chain is cryptographically verified: L1 PASS, L2 ${l2Pass ? "PASS" : "FAIL"}, L4 ${l4Status}.`
  );
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Enforcement Outcomes");
  lines.push("");
  lines.push("| # | Tool | Decision | Reason | Amount | Receipt ID |");
  lines.push("|---|------|----------|--------|--------|------------|");
  let rowNum = 1;
  for (const r of actionReceipts) {
    const rr = r as unknown as Record<string, unknown>;
    const tool = (rr.tool_name as string) ?? "—";
    const decision = (rr.decision as string) ?? "—";
    const queueStatus = rr.queue_status as string | undefined;
    const displayDecision = queueStatus === "DEAD_LETTER" ? "DEAD_LETTER" : decision;
    let reason = (rr.decision_reason as string) ?? (rr.failure_reason as string) ?? "—";
    if (reason === "velocity_limit_exceeded") reason = "velocity_exceeded";
    const amt = rr.amount_minor_units as number | null | undefined;
    const currency = rr.currency as string | undefined;
    const amountStr = formatAmount(amt, currency);
    const rid = (rr.receipt_id as string) ?? "";
    lines.push(`| ${rowNum} | ${tool} | ${displayDecision} | ${reason} | ${amountStr} | ${receiptIdShort(rid)} |`);
    rowNum++;
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Budget");
  lines.push("");

  const hasMoneyActions = actionReceipts.some((r) => (r as unknown as Record<string, unknown>).money_action === true);
  if (!hasMoneyActions) {
    lines.push("No money actions recorded.");
  } else {
    const mfst = receipts.find((r) => r.record_type === "workflow_manifest");
    const sessionBudget = (mfst as unknown as Record<string, unknown>)?.session_budget as Record<string, number> | undefined;
    const currencyEntry = sessionBudget
      ? Object.entries(sessionBudget).find(([k]) => /^[A-Z]{3}$/.test(k))
      : undefined;
    const capMinor = currencyEntry ? Math.round(currencyEntry[1] * 100) : DEFAULT_BUDGET_CAP_MINOR;
    const remaining = Math.max(0, capMinor - amountProcessed);
    lines.push("| Metric | Value |");
    lines.push("|--------|-------|");
    lines.push(`| Cap | ${formatAmount(capMinor)} USD |`);
    lines.push(`| Processed | ${formatAmount(amountProcessed)} USD |`);
    lines.push(`| Protected | ${formatAmount(amountProtected)} USD |`);
    lines.push(`| Remaining | ${formatAmount(remaining)} USD |`);
  }
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Verification");
  lines.push("");
  lines.push("| Tier | Status | Detail |");
  lines.push("|------|--------|--------|");
  const l1Pass = verifyResult.results.every((r) => r.l1.pass);
  lines.push(`| L1 Cryptographic integrity | ${l1Pass ? "PASS" : "FAIL"} | ${l1Pass ? "All signatures valid" : "Signature failure"} |`);
  lines.push(`| L2 Chain integrity | ${l2Pass ? "PASS" : "FAIL"} | ${l2Pass ? "No gaps, manifest-first" : "Chain error"} |`);
  const l3Status = verifyResult.l3Result.status;
  lines.push(
    `| L3 Timestamp | ${l3Status === "SKIPPED" ? "SKIPPED" : l3Status} | ${l3Status === "SKIPPED" ? "No TSA sidecar" : verifyResult.l3Result.reason ?? ""} |`
  );
  lines.push(`| L4 Outcome binding | ${l4Status} | ${l4Detail} |`);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Artifact References");
  lines.push("");
  lines.push("| Artifact | Value |");
  lines.push("|----------|-------|");
  lines.push(`| Receipt file | ${receiptFilePath} |`);
  lines.push(`| Policy hash | ${policyHash} |`);
  lines.push(`| Key ID | ${keyId} |`);
  lines.push(`| Manifest receipt | ${manifestReceiptId} |`);
  lines.push(`| Chain length | ${receipts.length} |`);
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Degraded Events");
  lines.push("");

  const degraded = receipts.filter((r) => DEGRADED_RECORD_TYPES.has(r.record_type));
  if (degraded.length === 0) {
    lines.push("No degraded events recorded.");
  } else {
    lines.push("| Receipt ID | Type | Reason | Sequence |");
    lines.push("|------------|------|--------|----------|");
    for (const r of degraded) {
      const rr = r as unknown as Record<string, unknown>;
      const id =
        (rr.recovery_event_id ?? rr.budget_warning_id ?? rr.reservation_expired_id ?? rr.receipt_id) as string;
      const recType = r.record_type;
      const reason = (rr.reason ?? rr.threshold_pct ?? "").toString();
      lines.push(`| ${id} | ${recType} | ${reason} | ${r.sequence_number} |`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

async function runReportFromFile(options: {
  workflow: string;
  receiptsDir?: string;
  output?: string;
  policy?: string;
}): Promise<number> {
  const rDir = options.receiptsDir ?? DEFAULT_RECEIPTS_DIR;
  const receiptFilePath = path.join(rDir, `${options.workflow}.ndjson`);
  if (!fs.existsSync(receiptFilePath)) {
    process.stderr.write(`Error: no receipt file found for workflow ${options.workflow}\n`);
    return 1;
  }

  let receipts: SignedReceipt[];
  try {
    receipts = readReceiptsFile(receiptFilePath);
  } catch (err) {
    process.stderr.write(
      `nonsudo report: failed to read receipts: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }
  if (receipts.length === 0) {
    process.stderr.write(`nonsudo report: receipt file is empty: ${receiptFilePath}\n`);
    return 1;
  }

  const firstKeyId = receipts[0].signature.key_id;
  let publicKey: Uint8Array;
  try {
    publicKey = await resolvePublicKey(firstKeyId, false);
  } catch (err) {
    process.stderr.write(
      `nonsudo report: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  const tsaPath = receiptFilePath + ".tsa";
  const tsaRecords = loadTsaSidecar(tsaPath);
  const verifyResult = await verifyReceipts(receipts, publicKey, tsaRecords, {
    policy: options.policy,
  });

  const markdown = buildEnforcementMarkdown(
    options.workflow,
    receipts,
    receiptFilePath,
    verifyResult,
    !!options.policy
  );

  if (options.output) {
    const resolvedOutput = path.resolve(options.output);
    fs.writeFileSync(resolvedOutput, markdown, "utf8");
  } else {
    process.stdout.write(markdown + "\n");
  }
  return 0;
}

// ── Export ───────────────────────────────────────────────────────────────────

export interface ReportOptions {
  workflow?: string;
  workflowId?: string;
  all?: boolean;
  from?: string;
  to?: string;
  output?: string;
  db?: string;
  receipts?: string;
  policy?: string;
  renderer?: ReportRenderer;
}

export async function runReport(options: ReportOptions = {}): Promise<number> {
  if (options.workflow) {
    return runReportFromFile({
      workflow: options.workflow,
      receiptsDir: options.receipts,
      output: options.output,
      policy: options.policy,
    });
  }

  if (!options.workflowId && !options.all) {
    process.stderr.write(
      `nonsudo report: requires --workflow <id> or exactly one of --workflow-id <id> or --all\n` +
        `Usage: nonsudo report --workflow <id> [--receipts <path>] [--output <path>] [--policy <path>]\n` +
        `   or: nonsudo report --workflow-id <id> | --all [--from <date>] [--to <date>] [--output <path>] [--db <path>]\n`
    );
    return 1;
  }
  if (options.workflowId && options.all) {
    process.stderr.write(
      `nonsudo report: cannot specify both --workflow-id and --all\n`
    );
    return 1;
  }

  const dbFilePath = options.db ?? DEFAULT_DB;
  let store: ReceiptStore;
  try {
    store = ReceiptStore.open(dbFilePath);
  } catch (err) {
    process.stderr.write(
      `nonsudo report: could not open database ${dbFilePath}: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  try {
    let workflows: WorkflowSummary[];

    if (options.workflowId) {
      const wf = store.getWorkflow(options.workflowId);
      if (!wf) {
        process.stderr.write(
          `nonsudo report: workflow not found: ${options.workflowId}\n`
        );
        return 1;
      }
      workflows = [wf];
    } else {
      const all = store.listWorkflows();
      workflows = all.filter((wf) => {
        if (options.from && wf.initiated_at < options.from) return false;
        if (options.to && wf.initiated_at > options.to + "T23:59:59Z") return false;
        return true;
      });
    }

    const receiptsMap = new Map<string, ReceiptRow[]>();
    for (const wf of workflows) {
      receiptsMap.set(wf.workflow_id, store.getWorkflowReceipts(wf.workflow_id));
    }

    const renderer = options.renderer ?? new PlainTextReportRenderer();
    const outputPath = options.output;

    if (outputPath) {
      const resolvedOutput = path.resolve(outputPath);
      const ws = fs.createWriteStream(resolvedOutput);
      const origWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = (chunk: string | Uint8Array) => {
        ws.write(chunk);
        return true;
      };
      try {
        await renderer.render(workflows, receiptsMap);
      } finally {
        process.stdout.write = origWrite;
        await new Promise<void>((resolve, reject) =>
          ws.close((err) => (err ? reject(err) : resolve()))
        );
      }
      process.stdout.write(
        `Report written to: ${resolvedOutput}\n`
      );
    } else {
      await renderer.render(workflows, receiptsMap);
    }
  } finally {
    store.close();
  }

  return 0;
}
