/**
 * Simple NDJSON receipt writer for the LangChain adapter.
 * Duplicates the pattern from packages/proxy/src/writer.ts.
 * TODO(refactor): extract to a shared @varcore/receipts utility.
 */

import * as fs from "fs";
import type { SignedReceipt } from "@varcore/receipts";

export class SimpleReceiptWriter {
  private fd: number;

  constructor(filePath: string) {
    this.fd = fs.openSync(filePath, "a");
  }

  append(receipt: SignedReceipt): void {
    fs.writeSync(this.fd, JSON.stringify(receipt) + "\n");
  }

  close(): void {
    try {
      fs.fsyncSync(this.fd);
      fs.closeSync(this.fd);
    } catch {
      /* best-effort */
    }
  }
}
