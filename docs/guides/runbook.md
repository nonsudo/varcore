# NonSudo Proxy — Operational Runbook

> **VAR v1.0 — 2026-03-02**

This runbook covers five operational scenarios for the NonSudo proxy.  See also:
- [Key Management](key-management.md) for key rotation and compromise response
- [Data Handling](data-handling.md) for retention and storage policies
- [Trust Model](trust-model.md) for the verification contract

---

## Scenario 1: TSA Worker Queue Jammed

**Symptom:** `GET /health` returns `"tsa_worker_status": "degraded"` and/or
`"queue_depth"` is growing.  Log lines like:
```
[nonsudo] [ERROR] TSA timestamp failed for receipt <id> after 3 attempt(s): <reason>
```

**Cause:** The configured TSA endpoint is unreachable or returning errors.  The worker
retries with exponential back-off (1 s → 2 s → 4 s) before marking itself degraded.
Receipt signing and forwarding are **not** affected — TSA timestamping is asynchronous
and a degraded TSA worker never blocks tool calls.

**Resolution:**

1. Check the TSA endpoint URL in `nonsudo.yaml` (`tsa.url`):
   ```bash
   grep -A5 '^tsa:' nonsudo.yaml
   ```

2. Test reachability from the proxy host:
   ```bash
   curl -v <tsa_url>
   ```

3. If the endpoint is permanently unavailable, disable TSA timestamping temporarily:
   ```yaml
   tsa:
     enabled: false
   ```
   Restart the proxy.  Receipts already written to the `.tsa` sidecar are unaffected.

4. When the TSA recovers, re-enable and restart.  The worker clears the `degraded` status
   on its next successful timestamp.

5. **HTTP mode:** Monitor `GET /health` — the `tsa_worker_status` field returns to
   `"idle"` once the queue drains.

6. **Stdio mode:** There is no `/health` endpoint.  Monitor the NDJSON receipt file for
   continued growth, and watch `stderr` for `[ERROR] TSA timestamp failed` log lines.

---

## Scenario 2: Key Rotation

See [Key Management §2](key-management.md#2-key-rotation) for the full procedure.

**Quick reference (HTTP mode, zero downtime):**

```bash
# 1. Generate new key pair on proxy host
nonsudo init --force

# 2. Note the new key_id printed by init
# 3. Deploy the new .jwk to the schema server (if using remote key resolution)
# 4. Rolling-restart proxy replicas (one at a time)
# 5. Confirm new key_id appears in /health-adjacent log output
```

**After rotation:** Verify that existing receipt chains still validate:
```bash
nonsudo verify receipts-<old-workflow-id>.ndjson
```
Expected: L1 PASS (old key resolves from `~/.nonsudo/keys/` or key-cache).

---

## Scenario 3: Evidence Export for Auditor

An auditor requests signed receipts and verification evidence for a specific workflow or
time window.

**Step 1 — Locate the receipt files:**

```bash
ls -1 receipts-*.ndjson        # stdio mode: one file per invocation
ls -1 receipts-*.ndjson.tsa    # TSA sidecar files (if timestamping enabled)
```

HTTP mode writes one `receipts-<workflow_id>.ndjson` per session.

**Step 2 — Index into the receipt store** (if using `nonsudo index`):

```bash
nonsudo index receipts-*.ndjson --db audit.db
```

**Step 3 — Generate a human-readable report:**

```bash
nonsudo report --all --db audit.db --output audit-report.txt
```

Or per workflow:
```bash
nonsudo report --workflow-id <workflow_id> --db audit.db
```

**Step 4 — Verify the chain before handing it over:**

```bash
nonsudo verify receipts-<workflow_id>.ndjson --require-complete
echo "Exit code: $?"
# 0 = chain valid and complete
```

**Step 5 — Bundle for the auditor:**

```bash
tar czf evidence-<date>.tar.gz \
  receipts-<workflow_id>.ndjson \
  receipts-<workflow_id>.ndjson.tsa \
  audit-report.txt
```

Provide the auditor with the public JWK for the relevant `key_id` so they can perform
independent offline verification:
```bash
cat ~/.nonsudo/keys/<key_id>.jwk
```

---

## Scenario 4: Receipt Store Corrupted

**Symptom:** `nonsudo verify` or `nonsudo index` exits with a parse error on an NDJSON
file, or `nonsudo query` returns unexpected results from the SQLite database.

**NDJSON file corruption:**

NDJSON receipt files are append-only.  Corruption typically affects only the last
(in-flight) line if the proxy process was killed mid-write.

1. Identify the damaged line:
   ```bash
   python3 -c "
   import json, sys
   for i, line in enumerate(open(sys.argv[1])):
       try: json.loads(line)
       except Exception as e: print(f'Line {i+1}: {e}')
   " receipts-<workflow_id>.ndjson
   ```

2. If only the final line is truncated (partial write), remove it:
   ```bash
   # Inspect last line
   tail -1 receipts-<workflow_id>.ndjson
   # If invalid, remove it (keep a backup first)
   cp receipts-<workflow_id>.ndjson receipts-<workflow_id>.ndjson.bak
   head -n -1 receipts-<workflow_id>.ndjson > receipts-<workflow_id>.ndjson.tmp
   mv receipts-<workflow_id>.ndjson.tmp receipts-<workflow_id>.ndjson
   ```

3. Re-verify the truncated chain:
   ```bash
   nonsudo verify receipts-<workflow_id>.ndjson
   ```
   Expect `INCOMPLETE_CHAIN` if the removed line was a mid-session receipt.  This is
   correct — the chain is genuinely incomplete.

**SQLite store corruption:**

The store uses WAL mode (`PRAGMA journal_mode=WAL`), which reduces but does not eliminate
corruption risk on hard shutdown.

1. Check integrity:
   ```bash
   sqlite3 <db-path> "PRAGMA integrity_check;"
   ```

2. If integrity check fails, restore from backup and re-index:
   ```bash
   cp <db-path>.bak <db-path>
   nonsudo index receipts-*.ndjson --db <db-path>
   ```

3. If no backup exists, delete the corrupt database and re-index from the source NDJSON
   files (which are the source of truth):
   ```bash
   rm <db-path>
   nonsudo index receipts-*.ndjson --db <db-path>
   ```

---

## Scenario 5: Log Rotation

The NonSudo proxy writes structured logs to **stderr** only.  Log rotation is handled at
the process level by your log aggregation infrastructure (systemd journal, Docker, etc.).

**Format** (all modes):
```
[nonsudo] [workflow_id=<id>] [agent_id=<id>] [LEVEL] <message>
```

Startup-phase lines (before a session is established) omit the context fields:
```
[nonsudo] [INFO] HTTP server listening on port 4000
[nonsudo] [WARN] tools/list fetch failed — all calls will be blocked
```

**Stdio mode:** stderr is typically captured by the parent process (e.g., the AI agent
host).  Configure the host to rotate or drain stderr appropriately.

**HTTP mode (systemd):**
```ini
[Service]
StandardError=journal
```
Logs flow to the systemd journal automatically.  Use `journalctl -u nonsudo-proxy -f` to
follow in real time.

**HTTP mode (Docker):**
```bash
docker logs --tail 100 -f nonsudo-proxy
```
Docker captures stderr from PID 1.  Rotate with your log driver (`json-file` default
rotates via `max-size` / `max-file` options in `daemon.json`).

**Important — D-005:** Raw tool argument values (params) must **never** appear in log
output.  If you observe sensitive values in logs, this is a bug — please report it.
Logs contain only structural metadata (tool names, decision codes, hashes) and timing
information.
