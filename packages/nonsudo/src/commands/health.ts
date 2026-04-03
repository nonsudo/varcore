/**
 * nonsudo health
 *
 * Runs diagnostic checks across 6 groups (NS-KEY, NS-POL, NS-DB,
 * NS-CHN, NS-NET, NS-ENV) and prints a formatted table.
 *
 * Exit 0: all checks PASS or WARN only.
 * Exit 1: any check FAIL.
 *
 * Flags:
 *   --json   Output as JSON array
 *   --fix    Attempt to fix failures (create missing dirs, etc.)
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as yaml from "yaml";

// ── Types ─────────────────────────────────────────────────────────────────────

type CheckStatus = "PASS" | "FAIL" | "WARN" | "SKIP";

export interface CheckResult {
  check: string;
  status: CheckStatus;
  detail: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const NONSUDO_DIR = path.join(os.homedir(), ".nonsudo");

function keysDir(): string {
  return path.join(NONSUDO_DIR, "keys");
}

function receiptsDir(): string {
  return path.join(NONSUDO_DIR, "receipts");
}

function dbPath(): string {
  return path.join(NONSUDO_DIR, "receipts.db");
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function statusIcon(s: CheckStatus): string {
  switch (s) {
    case "PASS": return "✓ PASS";
    case "FAIL": return "✗ FAIL";
    case "WARN": return "⚠ WARN";
    case "SKIP": return "– SKIP";
  }
}

// ── Check implementations ─────────────────────────────────────────────────────

function checkKeyDir(fix: boolean): CheckResult {
  const dir = keysDir();
  if (fs.existsSync(dir)) {
    return { check: "NS-KEY-001", status: "PASS", detail: dir };
  }
  if (fix) {
    fs.mkdirSync(dir, { recursive: true });
    return { check: "NS-KEY-001", status: "PASS", detail: `created ${dir}` };
  }
  return { check: "NS-KEY-001", status: "FAIL", detail: `missing: ${dir}` };
}

function checkKeypairPresent(): CheckResult {
  const dir = keysDir();
  if (!fs.existsSync(dir)) {
    return { check: "NS-KEY-002", status: "FAIL", detail: "keys directory missing" };
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jwk"));
  if (files.length === 0) {
    return { check: "NS-KEY-002", status: "FAIL", detail: "no keypair files in keys/" };
  }
  return { check: "NS-KEY-002", status: "PASS", detail: `${files.length} keypair(s) found` };
}

function checkActiveKeyValid(): CheckResult {
  const dir = keysDir();
  if (!fs.existsSync(dir)) {
    return { check: "NS-KEY-003", status: "FAIL", detail: "keys directory missing" };
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jwk"));
  if (files.length === 0) {
    return { check: "NS-KEY-003", status: "SKIP", detail: "no keypairs to validate" };
  }
  const activeFile = files.sort()[0];
  const fullPath = path.join(dir, activeFile);
  try {
    const content = fs.readFileSync(fullPath, "utf8");
    const jwk = JSON.parse(content) as Record<string, unknown>;
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
      return { check: "NS-KEY-003", status: "FAIL", detail: `${activeFile}: invalid JWK format` };
    }
    return { check: "NS-KEY-003", status: "PASS", detail: `${activeFile}: valid OKP/Ed25519` };
  } catch (err) {
    return { check: "NS-KEY-003", status: "FAIL", detail: `${activeFile}: ${err instanceof Error ? err.message : String(err)}` };
  }
}

function findNonsudoYaml(): string | null {
  const cwdPath = path.join(process.cwd(), "nonsudo.yaml");
  if (fs.existsSync(cwdPath)) return cwdPath;
  const homePath = path.join(NONSUDO_DIR, "nonsudo.yaml");
  if (fs.existsSync(homePath)) return homePath;
  return null;
}

function checkPolicyExists(): CheckResult {
  const found = findNonsudoYaml();
  if (found) {
    return { check: "NS-POL-001", status: "PASS", detail: found };
  }
  return { check: "NS-POL-001", status: "FAIL", detail: "nonsudo.yaml not found in cwd or ~/.nonsudo/" };
}

function checkPolicySchema(): CheckResult {
  const found = findNonsudoYaml();
  if (!found) {
    return { check: "NS-POL-002", status: "SKIP", detail: "no nonsudo.yaml found" };
  }
  try {
    const content = fs.readFileSync(found, "utf8");
    const doc = yaml.parse(content) as Record<string, unknown>;
    if (!doc || typeof doc !== "object") {
      return { check: "NS-POL-002", status: "FAIL", detail: "nonsudo.yaml is not a valid YAML object" };
    }
    if (!doc.version) {
      return { check: "NS-POL-002", status: "FAIL", detail: "missing required field: version" };
    }
    if (!doc.mode) {
      return { check: "NS-POL-002", status: "FAIL", detail: "missing required field: mode" };
    }
    return { check: "NS-POL-002", status: "PASS", detail: "schema valid" };
  } catch (err) {
    return { check: "NS-POL-002", status: "FAIL", detail: `parse error: ${err instanceof Error ? err.message : String(err)}` };
  }
}

function checkSchemaPacksResolve(): CheckResult {
  const found = findNonsudoYaml();
  if (!found) {
    return { check: "NS-POL-003", status: "SKIP", detail: "no nonsudo.yaml found" };
  }
  try {
    const content = fs.readFileSync(found, "utf8");
    const doc = yaml.parse(content) as Record<string, unknown>;
    const policy = doc?.policy as Record<string, unknown> | undefined;
    const schemas = policy?.schemas as string[] | undefined;
    if (!schemas || !Array.isArray(schemas) || schemas.length === 0) {
      return { check: "NS-POL-003", status: "SKIP", detail: "no schema packs referenced in policy" };
    }
    let SCHEMA_PACKS: Record<string, unknown>;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      SCHEMA_PACKS = require("@varcore/policy").SCHEMA_PACKS;
    } catch {
      return { check: "NS-POL-003", status: "WARN", detail: "@varcore/policy not available for schema pack resolution" };
    }
    const missing = schemas.filter((s) => !SCHEMA_PACKS[s]);
    if (missing.length > 0) {
      return { check: "NS-POL-003", status: "FAIL", detail: `unresolvable packs: ${missing.join(", ")}` };
    }
    return { check: "NS-POL-003", status: "PASS", detail: `${schemas.length} pack(s) resolve` };
  } catch (err) {
    return { check: "NS-POL-003", status: "FAIL", detail: `${err instanceof Error ? err.message : String(err)}` };
  }
}

function checkDbExists(): CheckResult {
  const db = dbPath();
  if (!fs.existsSync(db)) {
    return { check: "NS-DB-001", status: "SKIP", detail: "receipts.db not found (never indexed)" };
  }
  return { check: "NS-DB-001", status: "PASS", detail: db };
}

function checkDbReadable(): CheckResult {
  const db = dbPath();
  if (!fs.existsSync(db)) {
    return { check: "NS-DB-002", status: "SKIP", detail: "receipts.db not found" };
  }
  try {
    const fd = fs.openSync(db, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    const magic = buf.toString("utf8", 0, 16);
    if (magic.startsWith("SQLite format 3")) {
      return { check: "NS-DB-002", status: "PASS", detail: "SQLite format valid" };
    }
    return { check: "NS-DB-002", status: "FAIL", detail: "file does not start with SQLite magic header" };
  } catch (err) {
    return { check: "NS-DB-002", status: "FAIL", detail: `unreadable: ${err instanceof Error ? err.message : String(err)}` };
  }
}

function checkDbLastTimestamp(): CheckResult {
  const db = dbPath();
  if (!fs.existsSync(db)) {
    return { check: "NS-DB-003", status: "SKIP", detail: "receipts.db not found" };
  }
  try {
    const stat = fs.statSync(db);
    return { check: "NS-DB-003", status: "PASS", detail: `last modified: ${stat.mtime.toISOString()}` };
  } catch {
    return { check: "NS-DB-003", status: "WARN", detail: "could not stat receipts.db" };
  }
}

function checkReceiptsDir(fix: boolean): CheckResult {
  const dir = receiptsDir();
  if (fs.existsSync(dir)) {
    return { check: "NS-CHN-001", status: "PASS", detail: dir };
  }
  if (fix) {
    fs.mkdirSync(dir, { recursive: true });
    return { check: "NS-CHN-001", status: "PASS", detail: `created ${dir}` };
  }
  return { check: "NS-CHN-001", status: "FAIL", detail: `missing: ${dir}` };
}

function checkRecentNdjson(): CheckResult {
  const dir = receiptsDir();
  if (!fs.existsSync(dir)) {
    return { check: "NS-CHN-002", status: "SKIP", detail: "receipts directory missing" };
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ndjson"));
  if (files.length === 0) {
    return { check: "NS-CHN-002", status: "SKIP", detail: "no NDJSON files found" };
  }
  let newest = files[0];
  let newestMtime = 0;
  for (const f of files) {
    const stat = fs.statSync(path.join(dir, f));
    if (stat.mtimeMs > newestMtime) {
      newestMtime = stat.mtimeMs;
      newest = f;
    }
  }
  const fullPath = path.join(dir, newest);
  try {
    const content = fs.readFileSync(fullPath, "utf8");
    if (content.trim().length === 0) {
      return { check: "NS-CHN-002", status: "WARN", detail: `${newest}: empty file` };
    }
    return { check: "NS-CHN-002", status: "PASS", detail: newest };
  } catch (err) {
    return { check: "NS-CHN-002", status: "FAIL", detail: `${newest}: ${err instanceof Error ? err.message : String(err)}` };
  }
}

function checkLastReceiptL1(): CheckResult {
  const dir = receiptsDir();
  if (!fs.existsSync(dir)) {
    return { check: "NS-CHN-003", status: "SKIP", detail: "receipts directory missing" };
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ndjson"));
  if (files.length === 0) {
    return { check: "NS-CHN-003", status: "SKIP", detail: "no NDJSON files found" };
  }
  let newest = files[0];
  let newestMtime = 0;
  for (const f of files) {
    const stat = fs.statSync(path.join(dir, f));
    if (stat.mtimeMs > newestMtime) {
      newestMtime = stat.mtimeMs;
      newest = f;
    }
  }
  const fullPath = path.join(dir, newest);
  try {
    const content = fs.readFileSync(fullPath, "utf8");
    const lines = content.trim().split("\n").filter((l) => l.trim());
    if (lines.length === 0) {
      return { check: "NS-CHN-003", status: "SKIP", detail: "no receipts in chain" };
    }
    const lastLine = lines[lines.length - 1];
    const receipt = JSON.parse(lastLine) as Record<string, unknown>;
    const sig = receipt.signature as Record<string, unknown> | undefined;
    if (!sig || !sig.alg || !sig.sig || !sig.key_id) {
      return { check: "NS-CHN-003", status: "FAIL", detail: "last receipt missing signature fields" };
    }
    const receiptId = (receipt.receipt_id ?? receipt.post_receipt_id ?? receipt.recovery_event_id ?? "unknown") as string;
    return { check: "NS-CHN-003", status: "PASS", detail: `last receipt: ${receiptId}` };
  } catch (err) {
    return { check: "NS-CHN-003", status: "FAIL", detail: `${err instanceof Error ? err.message : String(err)}` };
  }
}

async function checkSchemasReachable(): Promise<CheckResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const resp = await fetch("https://schemas.nonsudo.com", {
      method: "HEAD",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return { check: "NS-NET-001", status: "PASS", detail: `HTTP ${resp.status}` };
  } catch (err) {
    return {
      check: "NS-NET-001",
      status: "WARN",
      detail: `unreachable: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function checkTsaReachable(): Promise<CheckResult> {
  const found = findNonsudoYaml();
  if (!found) {
    return { check: "NS-NET-002", status: "SKIP", detail: "no nonsudo.yaml found" };
  }
  try {
    const content = fs.readFileSync(found, "utf8");
    const doc = yaml.parse(content) as Record<string, unknown>;
    const proxy = doc?.proxy as Record<string, unknown> | undefined;
    const tsaEndpoint = (proxy?.tsa_endpoint ?? proxy?.tsa_url) as string | undefined;
    if (!tsaEndpoint) {
      return { check: "NS-NET-002", status: "SKIP", detail: "no TSA endpoint configured" };
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const resp = await fetch(tsaEndpoint, {
      method: "HEAD",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return { check: "NS-NET-002", status: "PASS", detail: `${tsaEndpoint} — HTTP ${resp.status}` };
  } catch (err) {
    return {
      check: "NS-NET-002",
      status: "WARN",
      detail: `TSA unreachable: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function checkNodeVersion(): CheckResult {
  const version = process.versions.node;
  const major = parseInt(version.split(".")[0], 10);
  if (major >= 20) {
    return { check: "NS-ENV-001", status: "PASS", detail: `Node.js v${version}` };
  }
  return { check: "NS-ENV-001", status: "FAIL", detail: `Node.js v${version} — requires ≥ 20` };
}

function checkCliVersion(): CheckResult {
  try {
    const pkgPath = path.resolve(__dirname, "../../package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version: string };
    return { check: "NS-ENV-002", status: "PASS", detail: `nonsudo CLI v${pkg.version}` };
  } catch {
    return { check: "NS-ENV-002", status: "WARN", detail: "could not read package.json" };
  }
}

// ── Runner ────────────────────────────────────────────────────────────────────

export async function runHealth(options: { json?: boolean; fix?: boolean } = {}): Promise<number> {
  const fix = options.fix ?? false;
  const results: CheckResult[] = [];

  // NS-KEY group
  results.push(checkKeyDir(fix));
  results.push(checkKeypairPresent());
  results.push(checkActiveKeyValid());

  // NS-POL group
  results.push(checkPolicyExists());
  results.push(checkPolicySchema());
  results.push(checkSchemaPacksResolve());

  // NS-DB group
  results.push(checkDbExists());
  results.push(checkDbReadable());
  results.push(checkDbLastTimestamp());

  // NS-CHN group
  results.push(checkReceiptsDir(fix));
  results.push(checkRecentNdjson());
  results.push(checkLastReceiptL1());

  // NS-NET group (async)
  results.push(await checkSchemasReachable());
  results.push(await checkTsaReachable());

  // NS-ENV group
  results.push(checkNodeVersion());
  results.push(checkCliVersion());

  const hasFail = results.some((r) => r.status === "FAIL");

  if (options.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + "\n");
    return hasFail ? 1 : 0;
  }

  // Table output
  process.stdout.write("nonsudo health\n\n");
  process.stdout.write(
    `  ${pad("CHECK", 12)}  ${pad("STATUS", 8)}  DETAIL\n`
  );
  process.stdout.write(
    `  ${pad("─────", 12)}  ${pad("──────", 8)}  ──────\n`
  );

  for (const r of results) {
    process.stdout.write(
      `  ${pad(r.check, 12)}  ${pad(statusIcon(r.status), 8)}  ${r.detail}\n`
    );
  }

  process.stdout.write("\n");

  const passCount = results.filter((r) => r.status === "PASS").length;
  const failCount = results.filter((r) => r.status === "FAIL").length;
  const warnCount = results.filter((r) => r.status === "WARN").length;
  const skipCount = results.filter((r) => r.status === "SKIP").length;

  if (hasFail) {
    process.stdout.write(
      `  RESULT: FAIL  (${passCount} pass, ${failCount} fail, ${warnCount} warn, ${skipCount} skip)\n`
    );
  } else {
    process.stdout.write(
      `  RESULT: PASS  (${passCount} pass, ${warnCount} warn, ${skipCount} skip)\n`
    );
  }

  return hasFail ? 1 : 0;
}
