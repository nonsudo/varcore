#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const pkg = require('../package.json');
const sdk = require('../dist/index.js');

const program = new Command();

program
  .name('nonsudo')
  .description('Mandate enforcement and cryptographic receipts for AI agents')
  .version(pkg.version);

// ── verify ────────────────────────────────────────────────────────────────

program
  .command('verify')
  .description('Verify an NDJSON receipt chain (L1 + L2, optionally L3 + L4)')
  .argument('<file>', 'Path to NDJSON receipt file')
  .option('--l3', 'Include L3 RFC 3161 timestamp verification')
  .option('--full', 'Run all layers: L1 + L2 + L3 + L4')
  .option('--pubkey <hex>', 'Ed25519 public key as 64-char hex string (required)')
  .action(async (file, opts) => {
    // 1. --pubkey is required — verifyChain performs L1+L2 together
    if (!opts.pubkey) {
      console.error('\u2717  --pubkey is required for chain verification.');
      console.error('   verifyChain performs L1 (signature) and L2 (hash chain) together.');
      console.error('   Provide the Ed25519 public key used to sign these receipts as hex.');
      console.error('   Example: nonsudo verify receipts.ndjson --pubkey <64-char-hex>');
      process.exit(1);
    }

    // 2. Decode public key
    if (opts.pubkey.length !== 64 || !/^[0-9a-fA-F]+$/.test(opts.pubkey)) {
      console.error('Error: --pubkey must be a 64-character hex string');
      process.exit(1);
    }
    const pubKey = Uint8Array.from(Buffer.from(opts.pubkey, 'hex'));

    // 3. Read file
    const resolved = path.resolve(file);
    if (!fs.existsSync(resolved)) {
      console.error(`Error: file not found: ${resolved}`);
      process.exit(1);
    }
    const content = fs.readFileSync(resolved, 'utf8');

    // 4. Parse NDJSON
    const lines = content.split('\n').filter((l) => l.trim().length > 0);
    const receipts = [];
    for (let i = 0; i < lines.length; i++) {
      try {
        receipts.push(JSON.parse(lines[i]));
      } catch {
        console.warn(`Warning: skipping line ${i + 1} (invalid JSON)`);
      }
    }

    if (receipts.length === 0) {
      console.error('Error: no valid receipts found in file');
      process.exit(1);
    }

    // 5. L1 + L2: verifyChain
    const chain = await sdk.verifyChain(receipts, pubKey);

    let exitCode = 0;

    if (chain.valid) {
      console.log(
        `\u2713  Chain valid \u2014 ${receipts.length} receipts, complete: ${chain.complete ? 'yes' : 'no'}`
      );
    } else {
      console.log('\u2717  Chain INVALID');
      for (const err of chain.errors) {
        const seq = err.sequence_number != null ? `[seq ${err.sequence_number}] ` : '';
        console.log(`     ${seq}${err.code}: ${err.message}`);
      }
      exitCode = 1;
    }

    // 7. L3
    if (opts.l3 || opts.full) {
      const tsaPath = resolved + '.tsa';
      if (fs.existsSync(tsaPath)) {
        const tsaRecords = sdk.loadTsaSidecar(tsaPath);
        const l3 = await sdk.verifyL3(receipts, tsaRecords);
        if (l3.status === 'PASS') {
          console.log('L3: PASS');
        } else if (l3.status === 'SKIPPED') {
          console.log('L3: SKIPPED');
        } else {
          console.log(`L3: ${l3.status}${l3.reason ? ' \u2014 ' + l3.reason : ''}`);
          exitCode = 1;
        }
      } else {
        console.log('L3: SKIPPED (no .tsa sidecar found)');
      }
    }

    // 8. L4
    if (opts.full) {
      const l4 = await sdk.verifyL4(receipts);
      if (l4.status === 'PASS') {
        console.log('L4: PASS');
      } else if (l4.status === 'N/A') {
        console.log('L4: N/A (no money actions in chain)');
      } else if (l4.status === 'WARN') {
        console.log(`L4: WARN \u2014 ${l4.violations.length} violations`);
        for (const v of l4.violations) {
          console.log(`     [${v.code}] ${v.message}`);
        }
      } else {
        console.log(`L4: FAIL \u2014 ${l4.violations.length} violations`);
        for (const v of l4.violations) {
          console.log(`     [${v.code}] ${v.message}`);
        }
        exitCode = 1;
      }
    }

    process.exit(exitCode);
  });

// ── conform ───────────────────────────────────────────────────────────────

program
  .command('conform')
  .description('Run VAR-Core conformance test vectors from schemas.nonsudo.com')
  .action(async () => {
    let vectors;
    try {
      const res = await fetch('https://schemas.nonsudo.com/var/v1/test-vectors.json');
      if (!res.ok) {
        console.error(`\u2717  Could not fetch test vectors (HTTP ${res.status})`);
        console.error('   Requires network access to schemas.nonsudo.com');
        process.exit(1);
      }
      vectors = await res.json();
    } catch (err) {
      console.error(`\u2717  Could not fetch test vectors (${err.message})`);
      console.error('   Requires network access to schemas.nonsudo.com');
      process.exit(1);
    }

    if (!Array.isArray(vectors)) {
      console.error('Error: test vectors response is not an array');
      process.exit(1);
    }

    let passed = 0;
    let failed = 0;

    for (let i = 0; i < vectors.length; i++) {
      const v = vectors[i];
      const label = v.id || `vector-${i}`;
      try {
        const receipts = v.receipts || v.chain || [];
        if (receipts.length === 0) {
          console.log(`  \u2713  ${label} (empty chain)`);
          passed++;
          continue;
        }

        // Decode public key if present
        let pubKey;
        if (v.public_key_hex) {
          pubKey = Uint8Array.from(Buffer.from(v.public_key_hex, 'hex'));
        } else if (v.public_key) {
          pubKey = Uint8Array.from(Buffer.from(v.public_key, 'hex'));
        } else {
          pubKey = new Uint8Array(32);
        }

        const result = await sdk.verifyChain(receipts, pubKey);
        const expectedL1 = v.expected_l1 ?? (v.expected_valid !== undefined ? (v.expected_valid ? 'PASS' : 'FAIL') : null);

        if (expectedL1) {
          const actual = result.valid ? 'PASS' : 'FAIL';
          if (actual === expectedL1) {
            console.log(`  \u2713  ${label}`);
            passed++;
          } else {
            console.log(`  \u2717  ${label} (expected ${expectedL1}, got ${actual})`);
            failed++;
          }
        } else {
          console.log(`  \u2713  ${label} (no expectation — ran without error)`);
          passed++;
        }
      } catch (err) {
        console.log(`  \u2717  ${label} (threw: ${err.message})`);
        failed++;
      }
    }

    const total = passed + failed;
    console.log(`\n${passed}/${total} vectors passed${failed > 0 ? `, ${failed} failed` : ''}`);
    process.exit(failed > 0 ? 1 : 0);
  });

// ── init ─────────────────────────────────────────────────────────────────

program
  .command('init')
  .description('Generate keypair and scaffold nonsudo.yaml')
  .option('--config <path>', 'output path for nonsudo.yaml', './nonsudo.yaml')
  .action(async (opts) => {
    const { runInit } = require('../dist/init/index.js');
    await runInit(opts.config);
  });

// ── observe ───────────────────────────────────────────────────────────────

program
  .command('observe')
  .description('Start an observe-mode proxy that logs tool calls without enforcement')
  .option('--port <number>', 'Proxy listen port', '3100')
  .option('--upstream <url>', 'Upstream URL to forward requests to', 'http://localhost:3001')
  .option('--config <path>', 'Path to nonsudo.yaml config file')
  .option('--no-dashboard', 'Disable the live dashboard')
  .action(async (opts) => {
    const { loadObserveConfig, startObserveProxy } = require('../dist/index.js');
    const cfg = loadObserveConfig(opts.config);
    if (opts.port) cfg.port = parseInt(opts.port, 10);
    if (opts.upstream) cfg.upstream_url = opts.upstream;
    if (opts.dashboard === false) cfg.dashboard = false;
    await startObserveProxy(cfg);
  });

// ── proxy (deprecated alias) ──────────────────────────────────────────────

program
  .command('proxy', { hidden: true })
  .description('(deprecated) Alias for observe')
  .allowUnknownOption(true)
  .action(async () => {
    console.warn('\x1b[33m[nonsudo] "proxy" is deprecated. Use "nonsudo observe" instead.\x1b[0m');
    const { loadObserveConfig, startObserveProxy } = require('../dist/index.js');
    const cfg = loadObserveConfig();
    await startObserveProxy(cfg);
  });

// ── schemas ──────────────────────────────────────────────────────────────

const schemasCmd = program
  .command('schemas')
  .description('List and inspect NonSudo schema packs');

schemasCmd
  .command('list')
  .description('List all available schema packs')
  .action(async () => {
    const { runSchemas } = require('../dist/commands/schemas.js');
    const exitCode = await runSchemas('list', []);
    process.exit(exitCode);
  });

schemasCmd
  .command('show')
  .description('Show rules for a schema pack')
  .argument('<pack-id>', 'Schema pack ID')
  .action(async (packId) => {
    const { runSchemas } = require('../dist/commands/schemas.js');
    const exitCode = await runSchemas('show', [packId]);
    process.exit(exitCode);
  });

// ── keys ─────────────────────────────────────────────────────────────────

const keysCmd = program
  .command('keys')
  .description('Manage NonSudo signing keypairs in ~/.nonsudo/keys/');

keysCmd
  .command('list')
  .description('List all keypairs in ~/.nonsudo/keys/')
  .action(async () => {
    const { runKeysList } = require('../dist/commands/keys.js');
    const exitCode = await runKeysList();
    process.exit(exitCode);
  });

keysCmd
  .command('export')
  .description('Export the public key for a key_id')
  .argument('<kid>', 'Key ID to export')
  .action(async (kid) => {
    const { runKeysExport } = require('../dist/commands/keys.js');
    const exitCode = await runKeysExport(kid);
    process.exit(exitCode);
  });

// ── health ───────────────────────────────────────────────────────────────

program
  .command('health')
  .description('Run diagnostic checks across keys, policy, db, chain, network, env')
  .option('--json', 'Output as JSON array')
  .option('--fix', 'Attempt to fix failures (create missing directories, etc.)')
  .action(async (opts) => {
    const { runHealth } = require('../dist/commands/health.js');
    const exitCode = await runHealth(opts);
    process.exit(exitCode);
  });

// ── query ────────────────────────────────────────────────────────────────

program
  .command('query')
  .description('Query the receipt store')
  .option('--workflow-id <id>', 'Filter by workflow_id')
  .option('--agent <id>', 'Filter by agent_id')
  .option('--tool <name>', 'Filter by tool_name')
  .option('--decision <value>', 'Filter by decision')
  .option('--from <date>', 'YYYY-MM-DD lower bound on issued_at')
  .option('--to <date>', 'YYYY-MM-DD upper bound on issued_at')
  .option('--record-type <type>', 'Filter by record_type')
  .option('--limit <n>', 'Max results (default: 100)', parseInt)
  .option('--format <format>', 'Output format: table | json | csv')
  .option('--db <path>', 'Database path (default: ~/.nonsudo/receipts.db)')
  .action(async (opts) => {
    const { runQuery } = require('../dist/commands/query.js');
    const exitCode = await runQuery(opts);
    process.exit(exitCode);
  });

// ── index ────────────────────────────────────────────────────────────────

program
  .command('index')
  .description('Index an NDJSON receipt file into the receipt store')
  .argument('<file>', 'Path to NDJSON receipt file')
  .option('--db <path>', 'Database path (default: ~/.nonsudo/receipts.db)')
  .option('--reverify', 'Recompute L1/L2/L3 for all receipts from this file')
  .action(async (file, opts) => {
    const { runIndex } = require('../dist/commands/index-command.js');
    const exitCode = await runIndex(file, opts);
    process.exit(exitCode);
  });

// ── report ───────────────────────────────────────────────────────────────

program
  .command('report')
  .description('Generate a workflow summary report')
  .option('--workflow <id>', 'Read receipt NDJSON from ~/.nonsudo/receipts/<id>.ndjson')
  .option('--receipts <path>', 'Receipts directory for --workflow')
  .option('--output <path>', 'Write report to file instead of stdout')
  .option('--policy <path>', 'Policy file for L4 budget verification')
  .option('--workflow-id <id>', 'Generate report for a single workflow from store')
  .option('--all', 'Generate report for all workflows in store')
  .option('--from <date>', 'Workflows initiated after this date')
  .option('--to <date>', 'Workflows initiated before this date')
  .option('--db <path>', 'Database path for store')
  .action(async (opts) => {
    const { runReport } = require('../dist/commands/report.js');
    const exitCode = await runReport(opts);
    process.exit(exitCode);
  });

// ── test ─────────────────────────────────────────────────────────────────

program
  .command('test')
  .description('Replay receipt chain against current policy to detect drift')
  .argument('<receipts-file>', 'Path to NDJSON receipt file')
  .option('-p, --policy <yaml-file>', 'Path to nonsudo.yaml')
  .option('--since <date>', 'Only replay receipts issued at or after DATE (ISO 8601)')
  .action(async (receiptsFile, opts) => {
    const { runTest } = require('../dist/commands/test.js');
    const exitCode = await runTest(receiptsFile, opts.policy, { since: opts.since });
    process.exit(exitCode);
  });

// ── watch ─────────────────────────────────────────────────────────────────

program
  .command('watch')
  .description('Watch a live receipts.ndjson file and print receipts in real time')
  .argument('[file]', 'Path to NDJSON receipt file (default: ./receipts.ndjson)')
  .action(async (file) => {
    const { runWatch } = require('../dist/commands/watch.js');
    await runWatch(file);
  });

program.parse();
