/**
 * nonsudo watch [file]
 *
 * Tails a live receipts.ndjson file and prints incoming receipts to stdout.
 * Uses plain-text output (no Ink/React TUI dependency).
 *
 * Behavior:
 *   - Seeds with existing receipts in the file
 *   - Watches for new appended content via fs.watch
 *   - If file doesn't exist yet, watches parent directory for creation
 *   - Prints a closure summary when workflow_closed is detected
 *   - Ctrl+C to exit
 */

import * as fs from "fs";
import * as path from "path";
import type { SignedReceipt } from "@varcore/receipts";

const DEFAULT_FILE = "./receipts.ndjson";

type AnyReceipt = SignedReceipt & Record<string, unknown>;

function parseReceiptsFromContent(content: string): AnyReceipt[] {
  return content
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as AnyReceipt);
}

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

function formatReceipt(r: AnyReceipt): string {
  const seq = pad(String(r.sequence_number), 4);
  const rt = pad(r.record_type, 20);
  const tool = pad((r["tool_name"] as string) ?? "—", 22);
  const decision = pad((r["decision"] as string) ?? "—", 10);
  return `  ${seq}  ${rt}  ${tool}  ${decision}`;
}

export function formatWorkflowClosedSummary(
  closed: AnyReceipt
): string {
  const ruler = "─".repeat(53);
  const closeReason = (closed["close_reason"] as string) ?? "unknown";
  const totalCalls = closed["total_calls"] as number;
  const totalBlocked = closed["total_blocked"] as number;
  const sessionDurationMs = closed["session_duration_ms"] as number;
  const durationSec = ((sessionDurationMs ?? 0) / 1000).toFixed(1);

  return [
    `  ${ruler}`,
    `  WORKFLOW CLOSED  ·  ${closeReason}`,
    `  ${totalCalls} calls  ·  ${totalBlocked} blocked  ·  ${durationSec}s`,
    `  ${ruler}`,
  ].join("\n");
}

export async function runWatch(fileArg?: string): Promise<void> {
  const filePath = path.resolve(fileArg ?? DEFAULT_FILE);

  // Print header
  process.stdout.write(`nonsudo watch — ${path.basename(filePath)}\n\n`);
  process.stdout.write(
    `  ${pad("seq", 4)}  ${pad("record_type", 20)}  ${pad("tool", 22)}  ${pad("decision", 10)}\n`
  );
  process.stdout.write(
    `  ${pad("───", 4)}  ${pad("──────────────────", 20)}  ${pad("──────────────────────", 22)}  ${pad("──────────", 10)}\n`
  );

  // Seed with existing receipts
  if (fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, "utf8");
      const receipts = parseReceiptsFromContent(content);
      for (const r of receipts) {
        process.stdout.write(formatReceipt(r) + "\n");
      }
    } catch {
      // File may be empty or not yet valid — start with empty
    }
  }

  let fileOffset = fs.existsSync(filePath) ? fs.statSync(filePath).size : 0;
  let activeWatcher: fs.FSWatcher | null = null;
  let stopped = false;

  function handleNewContent(): void {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size <= fileOffset) return;

      const fd = fs.openSync(filePath, "r");
      const newBytes = stat.size - fileOffset;
      const buf = Buffer.alloc(newBytes);
      fs.readSync(fd, buf, 0, newBytes, fileOffset);
      fs.closeSync(fd);
      fileOffset = stat.size;

      const newContent = buf.toString("utf8");
      let newReceipts: AnyReceipt[];
      try {
        newReceipts = parseReceiptsFromContent(newContent);
      } catch {
        return;
      }

      for (const r of newReceipts) {
        process.stdout.write(formatReceipt(r) + "\n");

        if (r.record_type === "workflow_closed") {
          process.stdout.write("\n" + formatWorkflowClosedSummary(r) + "\n");
          cleanup();
          return;
        }
      }
    } catch {
      // best-effort: watcher errors are non-fatal
    }
  }

  function startFileWatcher(): void {
    activeWatcher = fs.watch(filePath, { persistent: true }, (eventType) => {
      if (eventType !== "change" || stopped) return;
      handleNewContent();
    });
  }

  function cleanup(): void {
    if (stopped) return;
    stopped = true;
    if (activeWatcher) {
      try { activeWatcher.close(); } catch { /* ignore */ }
    }
  }

  // If file doesn't exist yet, watch parent directory for creation
  if (!fs.existsSync(filePath)) {
    const parentDir = path.dirname(filePath);
    fs.mkdirSync(parentDir, { recursive: true });

    process.stdout.write(`  (waiting for ${path.basename(filePath)} to appear...)\n`);

    await new Promise<void>((resolve) => {
      const dirWatcher = fs.watch(parentDir, { persistent: true }, (_eventType, filename) => {
        if (filename === path.basename(filePath) && fs.existsSync(filePath)) {
          dirWatcher.close();
          try {
            const content = fs.readFileSync(filePath, "utf8");
            const newReceipts = parseReceiptsFromContent(content);
            for (const r of newReceipts) {
              process.stdout.write(formatReceipt(r) + "\n");
            }
            fileOffset = fs.statSync(filePath).size;
          } catch { /* best-effort */ }
          startFileWatcher();
          resolve();
        }
      });

      process.on("SIGINT", () => {
        dirWatcher.close();
        cleanup();
        resolve();
      });
    });
  } else {
    startFileWatcher();
  }

  // Wait for Ctrl+C
  if (!stopped) {
    await new Promise<void>((resolve) => {
      process.on("SIGINT", () => {
        process.stdout.write("\n");
        cleanup();
        resolve();
      });
    });
  }
}
