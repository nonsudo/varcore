/**
 * nonsudo verify <file>
 *
 * Reads an NDJSON receipt file, runs L1 (signature), L2 (chain), L3
 * (RFC 3161 timestamp), and L4 (outcome binding) on every receipt,
 * prints a formatted table, exits 0 on pass, 1 on any failure.
 *
 * Key resolution order:
 *   1. Local cache: ~/.nonsudo/key-cache/<key_id>.jwk
 *   2. Local store: ~/.nonsudo/keys/<key_id>.jwk (written by proxy)
 *   3. Remote fetch: https://schemas.nonsudo.com/.well-known/keys/<key_id>.json
 *      (result is cached to ~/.nonsudo/key-cache/<key_id>.jwk)
 *
 * L3 sidecar: <file>.tsa — NDJSON of TsaRecord entries. Missing = all SKIPPED.
 *
 * --offline: skip remote fetch; fail with KEY_NOT_CACHED if not in cache.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  verifySignature,
  verifyChain,
  verifyL3,
  verifyL4,
  loadTsaSidecar,
  isValidKeyId,
  SignedReceipt,
  TsaRecord,
  L3Status,
  L3Result,
  L4Result,
} from "@varcore/receipts";
import type { ChainError } from "@varcore/receipts";
import { readReceiptsFile } from "../receipts-reader";

// ── Key resolution ─────────────────────────────────────────────────────────────

const SCHEMAS_BASE = "https://schemas.nonsudo.com";

function keyCacheDir(): string {
  return path.join(os.homedir(), ".nonsudo", "key-cache");
}

function keysDir(): string {
  return path.join(os.homedir(), ".nonsudo", "keys");
}

function cachedJwkPath(keyId: string): string {
  return path.join(keyCacheDir(), `${keyId}.jwk`);
}

function localJwkPath(keyId: string): string {
  return path.join(keysDir(), `${keyId}.jwk`);
}

function parseJwkBytes(jwkStr: string): Uint8Array {
  const jwk = JSON.parse(jwkStr) as { kty: string; crv: string; x: string };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error(
      `Unexpected JWK format: kty=${jwk.kty} crv=${jwk.crv} — expected OKP/Ed25519`
    );
  }
  if (!jwk.x || typeof jwk.x !== "string") {
    throw new Error("Malformed JWK: missing or empty x field");
  }
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

/**
 * Load a public key from ~/.nonsudo/keys/<key_id>.jwk.
 */
export function loadPublicKeyFromJwk(keyId: string): Uint8Array {
  const jwkPath = localJwkPath(keyId);
  if (!fs.existsSync(jwkPath)) {
    throw new Error(`Public key JWK not found: ${jwkPath}`);
  }
  return parseJwkBytes(fs.readFileSync(jwkPath, "utf8"));
}

/**
 * Resolve a public key for the given key_id.
 *
 * Resolution order:
 *   1. ~/.nonsudo/key-cache/<key_id>.jwk  (permanent cache)
 *   2. ~/.nonsudo/keys/<key_id>.jwk       (proxy-written local key)
 *   3. Remote: https://schemas.nonsudo.com/.well-known/keys/<key_id>.json
 */
export async function resolvePublicKey(
  keyId: string,
  offline = false
): Promise<Uint8Array> {
  if (!isValidKeyId(keyId)) {
    const err = new Error(
      `INVALID_KEY_ID: key_id "${keyId}" contains disallowed characters (only [a-zA-Z0-9_-]{1,64} permitted)`
    );
    (err as NodeJS.ErrnoException).code = "INVALID_KEY_ID";
    throw err;
  }

  // 1. Check permanent cache
  const cachePath = cachedJwkPath(keyId);
  if (fs.existsSync(cachePath)) {
    return parseJwkBytes(fs.readFileSync(cachePath, "utf8"));
  }

  // 2. Check local proxy keys dir
  const localPath = localJwkPath(keyId);
  if (fs.existsSync(localPath)) {
    return parseJwkBytes(fs.readFileSync(localPath, "utf8"));
  }

  // 3. If offline mode, fail
  if (offline) {
    const err = new Error(
      `KEY_NOT_CACHED: public key not in local cache for key_id=${keyId}. ` +
        `Run without --offline to fetch from ${SCHEMAS_BASE}.`
    );
    (err as NodeJS.ErrnoException).code = "KEY_NOT_CACHED";
    throw err;
  }

  // 4. Remote fetch
  const keyUrl = `${SCHEMAS_BASE}/.well-known/keys/${keyId}.json`;
  let jwkStr: string;
  try {
    const resp = await fetch(keyUrl);
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
    }
    jwkStr = await resp.text();
  } catch (e) {
    const err = new Error(
      `KEY_FETCH_FAILED: could not fetch public key for key_id=${keyId} from ${keyUrl}: ` +
        `${e instanceof Error ? e.message : String(e)}`
    );
    (err as NodeJS.ErrnoException).code = "KEY_FETCH_FAILED";
    throw err;
  }

  // Save to cache
  fs.mkdirSync(keyCacheDir(), { recursive: true });
  fs.writeFileSync(cachePath, jwkStr);

  return parseJwkBytes(jwkStr);
}

// ── Verify result types ───────────────────────────────────────────────────────

export interface ReceiptVerifyResult {
  sequenceNumber: number;
  recordType: string;
  l1: { pass: boolean; reason: string };
  l2: { pass: boolean; reason: string };
  l3: { status: L3Status; reason?: string };
  keyId: string;
  keyIdMismatch: boolean;
}

export interface VerifyFileResult {
  results: ReceiptVerifyResult[];
  overallPass: boolean;
  receiptCount: number;
  l3Result: L3Result;
  chainComplete: boolean;
  l4Result?: L4Result;
}

// ── Core verify logic ─────────────────────────────────────────────────────────

const DEFAULT_ACCEPTING_TSA_IDS = ["digicert", "sectigo", "globalsign"];

function perReceiptL3Status(
  receipt: SignedReceipt,
  recordById: Map<string, TsaRecord>,
  acceptingTsaIds: string[]
): { status: L3Status; reason?: string } {
  const r = receipt as unknown as Record<string, unknown>;
  const primaryId = (r["receipt_id"] ?? r["post_receipt_id"] ?? r["recovery_event_id"] ??
    r["budget_warning_id"] ?? r["reservation_expired_id"]) as string | undefined;
  const record = primaryId ? recordById.get(primaryId) : undefined;
  if (!record) return { status: "SKIPPED" };
  if (!acceptingTsaIds.includes(record.tsa_id)) {
    return {
      status: "FAIL",
      reason: `TSA ID "${record.tsa_id}" is not in accepting_tsa_ids`,
    };
  }
  return { status: "PASS" };
}

export async function verifyReceipts(
  receipts: SignedReceipt[],
  publicKey: Uint8Array,
  tsaRecords?: TsaRecord[],
  options?: { accepting_tsa_ids?: string[]; policy?: string }
): Promise<VerifyFileResult> {
  if (receipts.length === 0) {
    return {
      results: [],
      overallPass: true,
      receiptCount: 0,
      l3Result: { status: "SKIPPED" },
      chainComplete: false,
    };
  }

  // L1: verify each signature individually
  const l1Results: Array<{ pass: boolean; reason: string }> = [];
  for (const receipt of receipts) {
    const r = await verifySignature(receipt, publicKey);
    l1Results.push({ pass: r.valid, reason: r.reason });
  }

  // L2: verify the full chain
  const chainResult = await verifyChain(receipts, publicKey);

  const l2ByIndex: Map<number, ChainError> = new Map();
  if (!chainResult.valid) {
    for (const err of chainResult.errors) {
      if (err.code === "L1_INVALID") continue;
      if (err.index >= 0) l2ByIndex.set(err.index, err);
    }
  }

  // L3: per-receipt status from TSA sidecar
  const acceptingTsaIds = options?.accepting_tsa_ids ?? DEFAULT_ACCEPTING_TSA_IDS;
  const recordById = new Map((tsaRecords ?? []).map((r) => [r.receipt_id, r]));

  const primaryKeyId = receipts[0].signature.key_id;

  const results: ReceiptVerifyResult[] = receipts.map((r, i) => {
    const l2Failure = l2ByIndex.get(i);
    const receiptKeyId = r.signature.key_id;
    return {
      sequenceNumber: r.sequence_number,
      recordType: r.record_type,
      l1: l1Results[i],
      l2: l2Failure
        ? { pass: false, reason: l2Failure.message }
        : { pass: true, reason: "chain valid" },
      l3: perReceiptL3Status(r, recordById, acceptingTsaIds),
      keyId: receiptKeyId,
      keyIdMismatch: receiptKeyId !== primaryKeyId,
    };
  });

  // Overall L3
  const l3Result = await verifyL3(receipts, tsaRecords ?? [], { accepting_tsa_ids: acceptingTsaIds });

  // L4: outcome binding verification
  const l4Result = await verifyL4(receipts);

  const overallPass =
    results.every((r) => r.l1.pass && r.l2.pass) &&
    l3Result.status !== "FAIL" &&
    l4Result.status !== "FAIL";

  return {
    results,
    overallPass,
    receiptCount: receipts.length,
    l3Result,
    chainComplete: chainResult.complete,
    l4Result,
  };
}

// ── Formatting ────────────────────────────────────────────────────────────────

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function cell(pass: boolean, label: string): string {
  return pass ? `✓ ${label}` : `✗ ${label}`;
}

function l3Cell(status: L3Status): string {
  if (status === "PASS") return "✓ PASS";
  if (status === "FAIL") return "✗ FAIL";
  if (status === "PENDING") return "~ PEND";
  return "- SKIP";
}

export function formatVerifyOutput(
  filePath: string,
  result: VerifyFileResult,
  receipts: SignedReceipt[]
): string {
  const lines: string[] = [];

  lines.push(`nonsudo verify ${path.basename(filePath)}`);
  lines.push("");

  lines.push(
    `  ${pad("seq", 4)}  ${pad("record_type", 18)}  ${pad("L1", 10)}  ${pad("L2", 10)}  ${pad("L3", 10)}`
  );
  lines.push(
    `  ${pad("───", 4)}  ${pad("──────────────────", 18)}  ${pad("────────", 10)}  ${pad("────────", 10)}  ${pad("────────", 10)}`
  );

  for (const r of result.results) {
    const seq = String(r.sequenceNumber);
    const rt = r.recordType;
    const l1 = cell(r.l1.pass, r.l1.pass ? "PASS" : "FAIL");
    const l2 = cell(r.l2.pass, r.l2.pass ? "PASS" : "FAIL");
    const l3 = l3Cell(r.l3.status);
    lines.push(
      `  ${pad(seq, 4)}  ${pad(rt, 18)}  ${pad(l1, 10)}  ${pad(l2, 10)}  ${pad(l3, 10)}`
    );
  }

  lines.push("");

  const { l3Result } = result;
  if (l3Result.status === "SKIPPED") {
    lines.push(
      "  L3: SKIPPED — no TSA sidecar found"
    );
  } else if (l3Result.status === "PASS") {
    lines.push("  L3: ✓ PASS — all timestamped receipts verified");
  } else if (l3Result.status === "PENDING") {
    lines.push("  L3: PENDING (batch open — not yet timestamped)");
  } else {
    lines.push(
      `  L3: ✗ FAIL — ${l3Result.reason ?? "timestamp verification failed"}`
    );
    if (l3Result.failed_receipt_id) {
      lines.push(`  failed receipt: ${l3Result.failed_receipt_id}`);
    }
  }

  if (result.l4Result && result.l4Result.status !== "N/A") {
    const { l4Result } = result;
    if (l4Result.status === "PASS") {
      lines.push("  L4: ✓ PASS — all outcome binding requirements satisfied");
    } else if (l4Result.status === "WARN") {
      for (const v of l4Result.violations) {
        lines.push(`  L4: WARN — ${v.message}`);
      }
    } else {
      for (const v of l4Result.violations.filter((v2: { code: string }) =>
        ["MISSING_POST_RECEIPT", "PROJECTION_HASH_MISMATCH", "PROJECTION_UNRESOLVABLE", "PROJECTION_UNKNOWN_OPERATION"].includes(v2.code)
      )) {
        lines.push(`  L4: ✗ FAIL (${v.code}) — ${v.message}`);
      }
    }
  }

  const mismatchedReceipts = result.results.filter((r) => r.keyIdMismatch);
  if (mismatchedReceipts.length > 0) {
    const pKeyId = result.results[0].keyId;
    for (const r of mismatchedReceipts) {
      lines.push(
        `  WARNING: seq ${r.sequenceNumber} key_id "${r.keyId}" differs from chain key_id "${pKeyId}"`
      );
    }
    lines.push("");
  }

  if (receipts.length > 0) {
    const workflowId = receipts[0].workflow_id;
    const keyId = receipts[0].signature.key_id;
    const firstIssued = receipts[0].issued_at;
    const lastIssued = receipts[receipts.length - 1].issued_at;
    lines.push(`  workflow  ${workflowId}`);
    lines.push(`  key       ${keyId}`);
    lines.push(`  issued    ${firstIssued} → ${lastIssued}`);
    lines.push("");
  }

  if (result.overallPass) {
    lines.push(
      `  RESULT: PASS  (${result.receiptCount} receipt${result.receiptCount !== 1 ? "s" : ""}, chain intact)`
    );
  } else {
    for (const r of result.results) {
      if (!r.l1.pass) {
        lines.push(`  seq ${r.sequenceNumber}  L1: FAIL — ${r.l1.reason}`);
      }
      if (!r.l2.pass) {
        lines.push(`  seq ${r.sequenceNumber}  L2: FAIL — ${r.l2.reason}`);
      }
      if (r.l3.status === "FAIL") {
        lines.push(`  seq ${r.sequenceNumber}  L3: FAIL — ${r.l3.reason ?? "timestamp verification failed"}`);
      }
    }
    lines.push("");
    lines.push("  RESULT: FAIL");
  }

  if (result.chainComplete) {
    const closedReceipt = receipts.find((r) => r.record_type === "workflow_closed") as
      | (SignedReceipt & Record<string, unknown>)
      | undefined;
    if (closedReceipt) {
      const totalCalls = closedReceipt["total_calls"] as number;
      const totalBlocked = closedReceipt["total_blocked"] as number;
      const durationMs = closedReceipt["session_duration_ms"] as number;
      const durationSec = (durationMs / 1000).toFixed(1);
      lines.push(
        `  chain complete  ·  ${totalCalls} calls  ·  ${totalBlocked} blocked  ·  ${durationSec}s`
      );
    } else {
      lines.push("  chain complete");
    }
  } else {
    lines.push("  chain open");
  }

  return lines.join("\n");
}

// ── Exit code computation ────────────────────────────────────────────────────

export function computeVerifyExitCode(
  result: VerifyFileResult,
  options: { requireComplete?: boolean; requireTimestamps?: boolean } = {}
): number {
  const l1l2Fail = result.results.some((r) => !r.l1.pass || !r.l2.pass);
  const l3Fail =
    result.l3Result.status === "FAIL" ||
    (options.requireTimestamps && result.l3Result.status === "SKIPPED");
  const l4Fail = result.l4Result?.status === "FAIL";

  if (l1l2Fail || l3Fail || l4Fail) return 1;
  if (!result.chainComplete) return 2;
  if (result.l4Result?.status === "WARN") return 3;
  return 0;
}

// ── Command entry point ───────────────────────────────────────────────────────

export interface RunVerifyOptions {
  offline?: boolean;
  requireComplete?: boolean;
  requireTimestamps?: boolean | string;
  policy?: string;
}

export async function runVerify(
  filePath: string,
  options: RunVerifyOptions = {}
): Promise<number> {
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    process.stderr.write(`nonsudo verify: file not found: ${resolved}\n`);
    return 1;
  }

  let receipts: SignedReceipt[];
  try {
    receipts = readReceiptsFile(resolved);
  } catch (err) {
    process.stderr.write(
      `nonsudo verify: failed to read receipts: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  if (receipts.length === 0) {
    process.stderr.write(`nonsudo verify: file is empty: ${resolved}\n`);
    return 1;
  }

  const firstKeyId = receipts[0].signature.key_id;
  let publicKey: Uint8Array;
  try {
    publicKey = await resolvePublicKey(firstKeyId, options.offline ?? false);
  } catch (err) {
    process.stderr.write(
      `nonsudo verify: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  const tsaFilePath = resolved + ".tsa";
  const tsaRecords = loadTsaSidecar(tsaFilePath);

  let staleTimestampFound = false;
  if (options.requireTimestamps && typeof options.requireTimestamps === "string") {
    const cutoff = new Date(options.requireTimestamps);
    if (isNaN(cutoff.getTime())) {
      process.stderr.write(
        `nonsudo verify: invalid --require-timestamps date: "${options.requireTimestamps}" (expected ISO 8601)\n`
      );
      return 1;
    }
    for (const rec of tsaRecords) {
      const ts = new Date(rec.timestamped_at);
      if (ts < cutoff) {
        process.stderr.write(
          `nonsudo verify: stale timestamp for receipt ${rec.receipt_id}: ` +
            `${rec.timestamped_at} is before required date ${options.requireTimestamps}\n`
        );
        staleTimestampFound = true;
      }
    }
  }

  const result = await verifyReceipts(receipts, publicKey, tsaRecords);
  process.stdout.write(formatVerifyOutput(resolved, result, receipts) + "\n");

  if (staleTimestampFound) return 2;
  return computeVerifyExitCode(result, {
    requireComplete: options.requireComplete,
    requireTimestamps: !!options.requireTimestamps,
  });
}
