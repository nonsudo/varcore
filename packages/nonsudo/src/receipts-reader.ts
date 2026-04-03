/**
 * NDJSON receipt file reader.
 *
 * Reads a newline-delimited JSON file and returns an array of SignedReceipt
 * objects. Malformed lines are skipped with a warning to stderr.
 *
 * This is the public-package equivalent of the platform proxy's
 * readReceiptsFile — no private dependencies required.
 */

import * as fs from "fs";
import type { SignedReceipt } from "@varcore/receipts";

/**
 * Read an NDJSON receipt file and return parsed SignedReceipt objects.
 * Malformed lines are skipped with a stderr warning.
 */
export function readReceiptsFile(filePath: string): SignedReceipt[] {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n");
  const receipts: SignedReceipt[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.length === 0) continue;
    try {
      receipts.push(JSON.parse(line) as SignedReceipt);
    } catch {
      process.stderr.write(
        `[nonsudo] WARN: skipping malformed NDJSON at line ${i + 1}: ${line.slice(0, 80)}\n`
      );
    }
  }
  return receipts;
}
