#!/usr/bin/env node
/**
 * Generator for test-vectors.json.
 * Uses compiled receipts dist + @noble/ed25519 ESM + test-utils.
 *
 * TV-01..TV-05: well-formed chains — expected L1=PASS, L2=PASS
 * TV-06: tampered signature — expected L1=FAIL, L2=PASS
 * TV-07..TV-12: structurally malformed chains — expected L1=PASS, L2=FAIL
 * TV-13: valid chain + allowlisted TSA token — expected L3=PASS
 * TV-14: valid chain + non-allowlisted TSA token — expected L3=FAIL
 * TV-15: chain starts with action_receipt (no manifest) — expected L2=FAIL (MISSING_MANIFEST)
 * TV-16: DER parsing supply-chain check — expected_messageimprint_sha256 verified
 * TV-17: C1 — wrong hash algorithm OID — expected L3=FAIL (tsa_hash_algorithm_not_sha256)
 * TV-18: C2 — genTime backdated before issued_at — expected L3=FAIL (tsa_gentime_before_issued_at)
 * TV-19: C3 — unknown spec_version — expected L2=FAIL (UNKNOWN_SPEC_VERSION)
 * TV-20: D1 — DEGRADED_SESSION billable_reason — expected L2=PASS (DEGRADED_STATE warning)
 * TV-21: D2 — post_receipt without money_action on action — expected L2=PASS (MONEY_ACTION_TAG_MISSING warning)
 */
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createHash } from 'crypto';
import fs from 'fs';
import * as ed from '../packages/receipts/node_modules/@noble/ed25519/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const receiptsLib = require('../packages/receipts/dist/index.js');
const testUtils = require('../packages/receipts/dist/test-utils.js');
const canonicalize = require('../packages/receipts/node_modules/canonicalize/lib/canonicalize.js');
const { createReceipt, signReceipt, chainReceipt } = receiptsLib;
const { buildRfc3161Token } = testUtils;

const KEY_ID = 'ns-test-01';
const ZERO_HASH = 'sha256:' + '0'.repeat(64);
const OUT_PATH = join(__dirname, '../deploy/schema-server/public/var/v1/test-vectors.json');
const SEED_HEX = 'dead'.repeat(16);
const PRIVATE_KEY = new Uint8Array(Buffer.from(SEED_HEX, 'hex'));

function nowish() { return '2026-02-28T00:00:00Z'; }

function manifestFields(workflowId, seq = 0, prevHash = null) {
  return { receipt_id: 'manifest-' + workflowId + '-' + seq, record_type: 'workflow_manifest', spec_version: 'var/1.0', workflow_id: workflowId, workflow_id_source: 'nonsudo_generated', agent_id: 'test-agent', issued_at: nowish(), prev_receipt_hash: prevHash, sequence_number: seq, policy_bundle_hash: ZERO_HASH, rfc3161_token: null, tsa_id: null, initiator_id: 'test-init', workflow_owner: 'test-team', session_budget: { api_calls: 100 }, declared_tools: [], capability_manifest_hash: null, parent_workflow_id: null, framework_ref: null };
}

function actionFields(workflowId, seq, prevHash) {
  return { receipt_id: 'action-' + workflowId + '-' + seq, record_type: 'action_receipt', spec_version: 'var/1.0', workflow_id: workflowId, workflow_id_source: 'nonsudo_generated', agent_id: 'test-agent', issued_at: nowish(), prev_receipt_hash: prevHash, sequence_number: seq, policy_bundle_hash: ZERO_HASH, rfc3161_token: null, tsa_id: null, tool_name: 'list_directory', params_canonical_hash: ZERO_HASH, decision: 'ALLOW', decision_reason: 'conformance test', decision_order: 1, queue_status: 'COMPLETED', queue_timeout_ms: 5000, blast_radius: 'LOW', reversible: true, state_version_before: seq - 1, state_version_after: seq, response_hash: null };
}

function closedFields(workflowId, seq) {
  return { receipt_id: 'closed-' + workflowId + '-' + seq, record_type: 'workflow_closed', spec_version: 'var/1.0', workflow_id: workflowId, workflow_id_source: 'nonsudo_generated', agent_id: 'test-agent', issued_at: nowish(), prev_receipt_hash: null, sequence_number: seq, policy_bundle_hash: ZERO_HASH, rfc3161_token: null, tsa_id: null, total_calls: seq - 1, total_blocked: 0, total_spend: null, session_duration_ms: 1000, close_reason: 'explicit_close' };
}

async function buildValidChain(workflowId) {
  const m = createReceipt(manifestFields(workflowId, 0, null));
  const sm = await signReceipt(m, PRIVATE_KEY, KEY_ID);
  const a = createReceipt(actionFields(workflowId, 1, null));
  const ca = chainReceipt(a, sm);
  const sa = await signReceipt(ca, PRIVATE_KEY, KEY_ID);
  const c = createReceipt(closedFields(workflowId, 2));
  const cc = chainReceipt(c, sa);
  const sc = await signReceipt(cc, PRIVATE_KEY, KEY_ID);
  return [sm, sa, sc];
}

async function main() {
  const pubKey = await ed.getPublicKeyAsync(PRIVATE_KEY);
  const pubKeyJwk = { kty: 'OKP', crv: 'Ed25519', kid: KEY_ID, x: Buffer.from(pubKey).toString('base64url'), use: 'sig' };

  const tv01 = await buildValidChain('TV01-wf');
  const tv02 = await buildValidChain('TV02-wf');
  const tv03 = await buildValidChain('TV03-wf');

  const m04 = createReceipt(manifestFields('TV04-wf', 0, null));
  const sm04 = await signReceipt(m04, PRIVATE_KEY, KEY_ID);

  const m05 = createReceipt(manifestFields('TV05-wf', 0, null));
  const sm05 = await signReceipt(m05, PRIVATE_KEY, KEY_ID);
  const a05a = createReceipt(actionFields('TV05-wf', 1, null));
  const ca05a = chainReceipt(a05a, sm05);
  const sa05a = await signReceipt(ca05a, PRIVATE_KEY, KEY_ID);
  const a05b = createReceipt(actionFields('TV05-wf', 2, null));
  const ca05b = chainReceipt(a05b, sa05a);
  const sa05b = await signReceipt(ca05b, PRIVATE_KEY, KEY_ID);

  const m06 = createReceipt(manifestFields('TV06-wf', 0, null));
  const sm06raw = await signReceipt(m06, PRIVATE_KEY, KEY_ID);
  const sig06bytes = Buffer.from(sm06raw.signature.sig, 'base64url');
  sig06bytes[0] ^= 0xff;
  const sm06 = { ...sm06raw, signature: { ...sm06raw.signature, sig: sig06bytes.toString('base64url') } };

  const m07 = createReceipt(manifestFields('TV07-wf', 0, null));
  const sm07 = await signReceipt(m07, PRIVATE_KEY, KEY_ID);
  const a07 = createReceipt(actionFields('TV07-wf', 2, null));
  const ca07 = chainReceipt(a07, sm07);
  ca07['sequence_number'] = 2;
  const sa07 = await signReceipt(ca07, PRIVATE_KEY, KEY_ID);

  const m08 = createReceipt(manifestFields('TV08-wf', 0, null));
  const sm08 = await signReceipt(m08, PRIVATE_KEY, KEY_ID);
  const a08 = createReceipt(actionFields('TV08-wf', 1, 'sha256:' + 'a'.repeat(64)));
  a08['sequence_number'] = 1;
  const sa08 = await signReceipt(a08, PRIVATE_KEY, KEY_ID);

  const m09fields = manifestFields('TV09-wf', 0, 'sha256:' + 'b'.repeat(64));
  const m09 = createReceipt(m09fields);
  const sm09 = await signReceipt(m09, PRIVATE_KEY, KEY_ID);

  const m10a = createReceipt(manifestFields('TV10-wf', 0, null));
  const sm10a = await signReceipt(m10a, PRIVATE_KEY, KEY_ID);
  const m10b = createReceipt(manifestFields('TV10-wf', 1, null));
  const cm10b = chainReceipt(m10b, sm10a);
  const sm10b = await signReceipt(cm10b, PRIVATE_KEY, KEY_ID);

  const m11 = createReceipt(manifestFields('TV11-wf', 0, null));
  const sm11 = await signReceipt(m11, PRIVATE_KEY, KEY_ID);
  const a11 = createReceipt(actionFields('TV11-wf', 1, 'sha256:' + '0'.repeat(64)));
  a11['sequence_number'] = 1;
  const sa11 = await signReceipt(a11, PRIVATE_KEY, KEY_ID);

  const m12 = createReceipt(manifestFields('TV12-wf', 0, null));
  const sm12 = await signReceipt(m12, PRIVATE_KEY, KEY_ID);
  const a12 = createReceipt(actionFields('TV12-wf', 0, null));
  const sa12 = await signReceipt(a12, PRIVATE_KEY, KEY_ID);

  // TV-13: valid chain + allowlisted TSA token
  const tv13 = await buildValidChain('TV13-wf');
  const tsa13Records = tv13.map(r => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: 'digicert',
    timestamped_at: nowish(),
  }));

  // TV-14: valid chain + non-allowlisted TSA token
  const tv14 = await buildValidChain('TV14-wf');
  const tsa14Records = tv14.map(r => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: 'evilcorp-tsa',
    timestamped_at: nowish(),
  }));

  // TV-15: action_receipt as first receipt (no workflow_manifest)
  const sa15 = await signReceipt(createReceipt(actionFields('TV15-wf', 0, null)), PRIVATE_KEY, KEY_ID);

  // TV-16: DER supply-chain check
  const tv16 = await buildValidChain('TV16-wf');
  const tsa16Records = tv16.map(r => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: 'digicert',
    timestamped_at: nowish(),
  }));
  const tv16FirstCanon = canonicalize(tv16[0]);
  if (!tv16FirstCanon) throw new Error('canonicalize returned undefined for TV16');
  const tv16ExpectedImprint = createHash('sha256').update(tv16FirstCanon).digest('hex');

  // TV-17: C1 — wrong hash algorithm OID (MD5 instead of SHA-256) → L3 FAIL
  const tv17 = await buildValidChain('TV17-wf');
  const tsa17Records = tv17.map(r => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r, { overrideOid: '1.2.840.113549.2.5' }), // MD5 OID
    tsa_id: 'digicert',
    timestamped_at: nowish(),
  }));

  // TV-18: C2 — genTime backdated before receipt issued_at → L3 FAIL
  const tv18 = await buildValidChain('TV18-wf');
  const tsa18Records = tv18.map(r => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r, { overrideGenTime: new Date('2020-01-01T00:00:00Z') }),
    tsa_id: 'digicert',
    timestamped_at: nowish(),
  }));

  // TV-19: C3 — receipt with unknown spec_version → L2 FAIL (UNKNOWN_SPEC_VERSION)
  // L1 passes (signature covers the bad spec_version value); C3 check in verifyChain fails.
  const m19 = createReceipt({ ...manifestFields('TV19-wf', 0, null), spec_version: 'var/99.0' });
  const sm19 = await signReceipt(m19, PRIVATE_KEY, KEY_ID);

  // TV-20: D1 — action_receipt with billable_reason=DEGRADED_SESSION → L2=PASS (DEGRADED_STATE warning)
  const sm20 = await signReceipt(createReceipt(manifestFields('TV20-wf', 0, null)), PRIVATE_KEY, KEY_ID);
  const a20 = createReceipt({ ...actionFields('TV20-wf', 1, null), billable: true, billable_reason: 'DEGRADED_SESSION' });
  const sa20 = await signReceipt(chainReceipt(a20, sm20), PRIVATE_KEY, KEY_ID);
  const sc20 = await signReceipt(chainReceipt(createReceipt(closedFields('TV20-wf', 2)), sa20), PRIVATE_KEY, KEY_ID);

  // TV-21: D2 — post_receipt whose action_receipt lacks money_action=true → L2=PASS (MONEY_ACTION_TAG_MISSING warning)
  const sm21 = await signReceipt(createReceipt(manifestFields('TV21-wf', 0, null)), PRIVATE_KEY, KEY_ID);
  const ca21 = chainReceipt(createReceipt(actionFields('TV21-wf', 1, null)), sm21);
  const sa21 = await signReceipt(ca21, PRIVATE_KEY, KEY_ID);
  // post_receipt linked via pre_receipt_id to the action_receipt above (no money_action → D2 warning)
  const post21 = {
    post_receipt_id: 'post-TV21-wf-2',
    record_type: 'post_receipt',
    spec_version: 'var/1.0',
    pre_receipt_id: 'action-TV21-wf-1',  // receipt_id from actionFields('TV21-wf', 1, null)
    workflow_id: 'TV21-wf',
    agent_id: 'test-agent',
    sequence_number: 2,   // placeholder — chainReceipt overrides
    prev_receipt_hash: 'placeholder',    // placeholder — chainReceipt overrides
    policy_bundle_hash: ZERO_HASH,
    tool_name: 'list_directory',
    terminal_outcome: 'SUCCESS',
    upstream_response_digest: null,
    projection_id: null,
    projection_hash: null,
    idempotency_key: null,
    tool_call_correlation_id: null,
    execution_start_ms: 0,
    execution_end_ms: 1,
    degraded_reason: null,
    billable: false,
    billable_reason: 'READ_ONLY',
    issued_at: nowish(),
    account_context: null,
    rfc3161_token: null,
    tsa_id: null,
  };
  const spost21 = await signReceipt(chainReceipt(createReceipt(post21), sa21), PRIVATE_KEY, KEY_ID);

  const vectors = [
    { id: 'TV-01', description: 'valid 3-receipt chain (manifest then action then closed)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: tv01, tsa_records: [] },
    { id: 'TV-02', description: 'valid 3-receipt chain (independent workflow)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: tv02, tsa_records: [] },
    { id: 'TV-03', description: 'valid 3-receipt chain (third independent workflow)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: tv03, tsa_records: [] },
    { id: 'TV-04', description: 'valid single-receipt manifest-only chain', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm04], tsa_records: [] },
    { id: 'TV-05', description: 'valid 4-receipt chain (manifest then 2 actions)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm05, sa05a, sa05b], tsa_records: [] },
    { id: 'TV-06', description: 'tampered signature on manifest - L1 FAIL', expected_l1: 'FAIL', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm06], tsa_records: [] },
    { id: 'TV-07', description: 'sequence gap between seq 0 and seq 2 - INCOMPLETE_CHAIN', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm07, sa07], tsa_records: [] },
    { id: 'TV-08', description: 'prev_receipt_hash mismatch on action - HASH_MISMATCH', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm08, sa08], tsa_records: [] },
    { id: 'TV-09', description: 'manifest with non-null prev_receipt_hash - NULL_HASH_EXPECTED', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm09], tsa_records: [] },
    { id: 'TV-10', description: 'two consecutive manifests - second manifest has wrong structure', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm10a, sm10b], tsa_records: [] },
    { id: 'TV-11', description: 'correct sequence numbers but wrong prev_hash - HASH_MISMATCH', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm11, sa11], tsa_records: [] },
    { id: 'TV-12', description: 'duplicate sequence number 0 - INCOMPLETE_CHAIN', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm12, sa12], tsa_records: [] },
    { id: 'TV-13', description: 'valid chain + allowlisted TSA token - L3 PASS', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'PASS', receipts: tv13, tsa_records: tsa13Records },
    { id: 'TV-14', description: 'valid chain + non-allowlisted TSA token - L3 FAIL', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'FAIL', receipts: tv14, tsa_records: tsa14Records },
    { id: 'TV-15', description: 'chain starts with action_receipt (not workflow_manifest) - MISSING_MANIFEST', expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sa15], tsa_records: [] },
    { id: 'TV-16', description: 'DER parsing supply-chain check - verifies @peculiar/asn1-* returns correct messageImprint bytes', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'PASS', expected_messageimprint_sha256: tv16ExpectedImprint, receipts: tv16, tsa_records: tsa16Records },
    { id: 'TV-17', description: 'C1: TSA token uses MD5 OID instead of SHA-256 - L3 FAIL (tsa_hash_algorithm_not_sha256)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'FAIL', receipts: tv17, tsa_records: tsa17Records },
    { id: 'TV-18', description: 'C2: TSA token genTime is before receipt issued_at - L3 FAIL (tsa_gentime_before_issued_at)', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'FAIL', receipts: tv18, tsa_records: tsa18Records },
    { id: 'TV-19', description: "C3: receipt has spec_version='var/99.0' (unknown) - L2 FAIL (UNKNOWN_SPEC_VERSION)", expected_l1: 'PASS', expected_l2: 'FAIL', expected_l3: 'SKIPPED', receipts: [sm19], tsa_records: [] },
    { id: 'TV-20', description: 'D1: action_receipt with billable_reason=DEGRADED_SESSION - chain valid, DEGRADED_STATE warning emitted', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm20, sa20, sc20], tsa_records: [] },
    { id: 'TV-21', description: 'D2: post_receipt linked to action_receipt without money_action=true - chain valid, MONEY_ACTION_TAG_MISSING warning emitted', expected_l1: 'PASS', expected_l2: 'PASS', expected_l3: 'SKIPPED', receipts: [sm21, sa21, spost21], tsa_records: [] },
  ];

  const output = { spec_version: 'var/1.0', generated_at: nowish(), key_id: KEY_ID, key_jwk: pubKeyJwk, vectors };
  fs.mkdirSync(dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2) + '\n');
  console.log('Written ' + vectors.length + ' test vectors to ' + OUT_PATH); // now 21 vectors
}

main().catch(e => { console.error(e); process.exit(1); });
