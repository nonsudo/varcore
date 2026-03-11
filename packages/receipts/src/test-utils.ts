/**
 * Test-only utilities for building synthetic RFC 3161 DER tokens.
 *
 * Used by scripts/generate-test-vectors.ts to produce valid DER tokens for TV-13/TV-14.
 * NOT part of the public receipts API (not exported from index.ts).
 *
 * The generated tokens are structurally valid RFC 3161 TimeStampResp DER but are
 * NOT signed by a real TSA — they are suitable only for conformance testing of
 * verifyL3 mechanics (PKIStatus check + messageImprint hash comparison).
 */

import { createHash } from "crypto";
import canonicalize from "canonicalize";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import {
  TimeStampResp,
  TimeStampToken,
  PKIStatusInfo,
  PKIStatus,
  TSTInfo,
  TSTInfoVersion,
  MessageImprint,
  id_ct_tstInfo,
} from "@peculiar/asn1-tsp";
import {
  SignedData,
  DigestAlgorithmIdentifiers,
  EncapsulatedContentInfo,
  EncapsulatedContent,
  SignerInfos,
  CMSVersion,
  id_signedData,
} from "@peculiar/asn1-cms";
import type { SignedReceipt } from "./types";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";

export interface BuildRfc3161TokenOptions {
  /**
   * Override the hash algorithm OID.
   * Default: SHA-256 OID "2.16.840.1.101.3.4.2.1".
   * Use to test C1 (verifyL3 OID check) — e.g., "1.2.840.113549.2.5" (MD5).
   */
  overrideOid?: string;
  /**
   * Override the genTime in TSTInfo.
   * Default: the receipt's own issued_at (so genTime >= issued_at is always satisfied).
   * Use to test C2 (verifyL3 genTime check) — e.g., new Date("2020-01-01T00:00:00Z").
   */
  overrideGenTime?: Date;
}

/**
 * Build a minimal but structurally valid RFC 3161 TimeStampResp DER for a signed receipt.
 *
 * The messageImprint.hashedMessage is SHA-256(JCS(signed_receipt)) — the same
 * computation that verifyL3 uses when validating the binding.
 *
 * Returns the DER bytes as a base64 string (ready for use as rfc3161_token in a TsaRecord).
 *
 * For test vector generation ONLY — not for production TSA calls.
 */
export function buildRfc3161Token(receipt: SignedReceipt, options?: BuildRfc3161TokenOptions): string {
  const canonical = canonicalize(receipt as object);
  if (!canonical) throw new Error("canonicalize returned undefined for receipt");

  const hashBytes = createHash("sha256").update(canonical).digest();

  // ── Build TSTInfo ──────────────────────────────────────────────────────────
  const tstInfo = new TSTInfo();
  tstInfo.version = TSTInfoVersion.v1;
  tstInfo.policy = "1.3.6.1.4.1.13762.3"; // arbitrary test policy OID

  const mi = new MessageImprint();
  const algId = new AlgorithmIdentifier();
  algId.algorithm = options?.overrideOid ?? SHA256_OID;
  mi.hashAlgorithm = algId;
  mi.hashedMessage = new OctetString(hashBytes);
  tstInfo.messageImprint = mi;

  // serialNumber: 4-byte fixed value (first 4 bytes of the receipt hash for uniqueness)
  const serialBuf = new ArrayBuffer(4);
  new Uint8Array(serialBuf).set(hashBytes.slice(0, 4));
  tstInfo.serialNumber = serialBuf;

  // Default genTime = receipt's own issued_at so the C2 check (genTime >= issued_at) is always
  // satisfied for well-formed test tokens. Use overrideGenTime to test the backdated-TSA path.
  const receiptIssuedAt = (receipt as unknown as Record<string, unknown>).issued_at as string | undefined;
  const defaultGenTime = receiptIssuedAt ? new Date(receiptIssuedAt) : new Date();
  tstInfo.genTime = options?.overrideGenTime ?? defaultGenTime;

  const tstInfoDer = AsnConvert.serialize(tstInfo);

  // ── Wrap TSTInfo in EncapsulatedContentInfo ────────────────────────────────
  const encContent = new EncapsulatedContent();
  encContent.single = new OctetString(tstInfoDer);

  const encapContentInfo = new EncapsulatedContentInfo();
  encapContentInfo.eContentType = id_ct_tstInfo;
  encapContentInfo.eContent = encContent;

  // ── Build minimal SignedData (no actual signers — test only) ───────────────
  const sd = new SignedData();
  sd.version = CMSVersion.v3;
  sd.digestAlgorithms = new DigestAlgorithmIdentifiers();
  sd.encapContentInfo = encapContentInfo;
  sd.signerInfos = new SignerInfos();
  const sdDer = AsnConvert.serialize(sd);

  // ── Wrap in TimeStampToken (ContentInfo) ──────────────────────────────────
  const tsToken = new TimeStampToken();
  tsToken.contentType = id_signedData;
  tsToken.content = sdDer;

  // ── Build TimeStampResp ───────────────────────────────────────────────────
  const resp = new TimeStampResp();
  const statusInfo = new PKIStatusInfo();
  statusInfo.status = PKIStatus.granted;
  resp.status = statusInfo;
  resp.timeStampToken = tsToken;

  const respDer = AsnConvert.serialize(resp);
  return Buffer.from(respDer).toString("base64");
}
