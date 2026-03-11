import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ed from "@noble/ed25519";
import { LangChainAdapter } from "../adapter";
import type { LangChainToolCall, LangChainToolResult } from "../types";
import type { AgentActionResult } from "@varcore/core";
import { NonSudoCallbackHandler } from "../handler";
import { createNonSudoCallbacks } from "../index";

describe("LangChainAdapter", () => {
  let adapter: LangChainAdapter;

  beforeEach(() => {
    adapter = new LangChainAdapter();
  });

  // ── toAction ─────────────────────────────────────────────────────────────

  test("1. toAction maps name → tool_name", () => {
    const call: LangChainToolCall = { name: "search_web", args: { q: "hello" } };
    expect(adapter.toAction(call).tool_name).toBe("search_web");
  });

  test("2. toAction uses object args directly", () => {
    const args = { path: "/tmp/foo", encoding: "utf8" };
    const call: LangChainToolCall = { name: "read_file", args };
    expect(adapter.toAction(call).arguments).toEqual(args);
  });

  test("3. toAction parses JSON string args → object", () => {
    const call: LangChainToolCall = {
      name: "read_file",
      args: '{"path": "/tmp/foo"}',
    };
    expect(adapter.toAction(call).arguments).toEqual({ path: "/tmp/foo" });
  });

  test("4. toAction sets protocol: 'langchain'", () => {
    const call: LangChainToolCall = { name: "my_tool", args: {} };
    expect(adapter.toAction(call).protocol).toBe("langchain");
  });

  test("5. toAction throws SyntaxError on malformed JSON string args", () => {
    const call: LangChainToolCall = {
      name: "my_tool",
      args: "{bad: json}",
    };
    expect(() => adapter.toAction(call)).toThrow(SyntaxError);
  });

  // ── toResponse ───────────────────────────────────────────────────────────

  test("6. toResponse returns { content } on success", () => {
    const result: AgentActionResult = { success: true, content: "result text" };
    const response = adapter.toResponse(result) as LangChainToolResult;
    expect(response.content).toBe("result text");
    expect(response.isError).toBeUndefined();
  });

  test("7. toResponse returns { content: error, isError: true } on failure", () => {
    const result: AgentActionResult = { success: false, error: "BLOCKED" };
    const response = adapter.toResponse(result) as LangChainToolResult;
    expect(response.content).toBe("BLOCKED");
    expect(response.isError).toBe(true);
  });

  // ── NonSudoCallbackHandler ────────────────────────────────────────────────

  describe("NonSudoCallbackHandler", () => {
    let tmpDir: string;
    let keyFile: string;
    let receiptFile: string;

    beforeAll(async () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonsudo-lc-test-"));
      keyFile = path.join(tmpDir, "test-key.key");
      receiptFile = path.join(tmpDir, "receipts.ndjson");

      // Generate a private key and write it as hex
      const privateKey = ed.utils.randomPrivateKey();
      fs.writeFileSync(keyFile, Buffer.from(privateKey).toString("hex") + "\n");
    });

    afterAll(() => {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    });

    test("8. NonSudoCallbackHandler has name 'NonSudoCallbackHandler'", () => {
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-lc-1",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: receiptFile,
        key_path: keyFile,
      });
      expect(handler.name).toBe("NonSudoCallbackHandler");
    });

    test("9. handleToolStart writes a receipt to the receipt file", async () => {
      const testReceiptFile = path.join(tmpDir, "receipts-test9.ndjson");
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-lc-2",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: testReceiptFile,
        key_path: keyFile,
      });

      await handler.handleToolStart(
        { id: ["tools", "my_tool"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"query": "hello world"}',
        "run-id-1",
        undefined,
        undefined,
        undefined,
        "my_tool"
      );

      // Receipt file must exist and contain at least 2 lines (manifest + action_receipt)
      expect(fs.existsSync(testReceiptFile)).toBe(true);
      const lines = fs
        .readFileSync(testReceiptFile, "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0);
      expect(lines.length).toBeGreaterThanOrEqual(2);

      // Both lines must be valid JSON with the correct record types
      const manifest = JSON.parse(lines[0]) as { record_type: string };
      const actionReceipt = JSON.parse(lines[1]) as { record_type: string };
      expect(manifest.record_type).toBe("workflow_manifest");
      expect(actionReceipt.record_type).toBe("action_receipt");
    });

    test("10. createNonSudoCallbacks returns an array with a NonSudoCallbackHandler", () => {
      const callbacks = createNonSudoCallbacks({
        agent_id: "agent-lc-3",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: receiptFile,
        key_path: keyFile,
      });
      expect(Array.isArray(callbacks)).toBe(true);
      expect(callbacks.length).toBe(1);
      expect(callbacks[0]).toBeInstanceOf(NonSudoCallbackHandler);
    });
  });
});
