/**
 * nonsudo keys list
 * nonsudo keys export <kid>
 *
 * Manages the local Ed25519 keypairs stored in ~/.nonsudo/keys/.
 *
 *   list    — print all key_ids found in ~/.nonsudo/keys/
 *   export  — print public key as PEM and hex to stdout, write nonsudo.pub (PEM)
 *             in cwd, and add public_key to nonsudo.yaml when present
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { createPublicKey } from "crypto";
import * as yaml from "yaml";

function keysDir(): string {
  return path.join(os.homedir(), ".nonsudo", "keys");
}

export async function runKeysList(): Promise<number> {
  const dir = keysDir();
  if (!fs.existsSync(dir)) {
    process.stdout.write("nonsudo keys: no keys directory found (~/.nonsudo/keys/)\n");
    return 0;
  }

  const entries = fs.readdirSync(dir).filter((f) => f.endsWith(".key"));
  if (entries.length === 0) {
    process.stdout.write("nonsudo keys: no keypairs found. Run `nonsudo init` to create one.\n");
    return 0;
  }

  entries.sort();
  process.stdout.write("nonsudo keys list\n\n");
  for (const entry of entries) {
    const keyId = entry.replace(/\.key$/, "");
    const jwkPath = path.join(dir, `${keyId}.jwk`);
    const hasJwk = fs.existsSync(jwkPath);
    process.stdout.write(`  ${keyId}${hasJwk ? "" : "  (no .jwk)"}\n`);
  }
  process.stdout.write("\n");
  return 0;
}

interface Ed25519Jwk {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
  use?: string;
}

export async function runKeysExport(kid: string): Promise<number> {
  const dir = keysDir();
  const jwkPath = path.join(dir, `${kid}.jwk`);

  if (!fs.existsSync(jwkPath)) {
    process.stderr.write(
      `nonsudo keys export: JWK not found for key_id=${kid} (looked in ${jwkPath})\n`
    );
    return 1;
  }

  const jwkStr = fs.readFileSync(jwkPath, "utf8");
  let jwk: Ed25519Jwk;
  try {
    jwk = JSON.parse(jwkStr) as Ed25519Jwk;
  } catch {
    process.stderr.write(`nonsudo keys export: invalid JWK in ${jwkPath}\n`);
    return 1;
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x || typeof jwk.x !== "string") {
    process.stderr.write(
      `nonsudo keys export: unexpected JWK format (expected OKP/Ed25519 with x) in ${jwkPath}\n`
    );
    return 1;
  }

  const publicKeyBytes = new Uint8Array(Buffer.from(jwk.x, "base64url"));
  const hex = Buffer.from(publicKeyBytes).toString("hex");

  const keyObj = createPublicKey({
    key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    format: "jwk",
  });
  const pem = keyObj.export({ type: "spki", format: "pem" }) as string;

  process.stdout.write("Public key (PEM):\n");
  process.stdout.write("─────────────────\n");
  process.stdout.write(pem);
  if (!pem.endsWith("\n")) process.stdout.write("\n");
  process.stdout.write("\nPublic key (hex):\n");
  process.stdout.write(hex + "\n");

  const cwd = process.cwd();
  const pubFilePath = path.join(cwd, "nonsudo.pub");
  fs.writeFileSync(pubFilePath, pem.endsWith("\n") ? pem : pem + "\n", { mode: 0o644 });

  const yamlPath = path.join(cwd, "nonsudo.yaml");
  if (fs.existsSync(yamlPath)) {
    try {
      const raw = fs.readFileSync(yamlPath, "utf8");
      const parsed = (yaml.parse(raw) as Record<string, unknown>) ?? {};
      parsed.public_key = `hex:${hex}`;
      const updated = yaml.stringify(parsed);
      fs.writeFileSync(yamlPath, updated);
    } catch (err) {
      process.stderr.write(
        `nonsudo keys export: could not update nonsudo.yaml: ${err instanceof Error ? err.message : String(err)}\n`
      );
    }
  }

  return 0;
}
