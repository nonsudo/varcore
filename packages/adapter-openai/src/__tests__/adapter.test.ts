import * as ed from "@noble/ed25519";
import { OpenAIAdapter } from "../adapter";
import type { OpenAIFunctionCall, OpenAIToolResult } from "../types";
import type { AgentActionResult } from "@varcore/core";
import { createActionReceipt } from "../receipt";
import { createReceipt, signReceipt } from "@varcore/receipts";
import type { ReceiptFields, SignedReceipt } from "@varcore/receipts";
import { ulid } from "ulid";

describe("OpenAIAdapter", () => {
  let adapter: OpenAIAdapter;

  beforeEach(() => {
    adapter = new OpenAIAdapter();
  });

  // ── toAction ─────────────────────────────────────────────────────────────

  test("1. toAction maps function.name → tool_name", () => {
    const call: OpenAIFunctionCall = {
      function: { name: "search_web", arguments: "{}" },
    };
    expect(adapter.toAction(call).tool_name).toBe("search_web");
  });

  test("2. toAction parses function.arguments JSON string → arguments object", () => {
    const call: OpenAIFunctionCall = {
      function: { name: "read_file", arguments: '{"path": "/tmp/foo"}' },
    };
    expect(adapter.toAction(call).arguments).toEqual({ path: "/tmp/foo" });
  });

  test("3. toAction sets protocol: 'openai'", () => {
    const call: OpenAIFunctionCall = {
      function: { name: "my_tool", arguments: "{}" },
    };
    expect(adapter.toAction(call).protocol).toBe("openai");
  });

  test("4. toAction preserves raw as the original call object", () => {
    const call: OpenAIFunctionCall = {
      function: { name: "my_tool", arguments: "{}" },
    };
    expect(adapter.toAction(call).raw).toBe(call);
  });

  test("5. toAction defaults arguments to {} when function.arguments is undefined", () => {
    const call: OpenAIFunctionCall = { function: { name: "my_tool" } };
    expect(adapter.toAction(call).arguments).toEqual({});
  });

  test("6. toAction uses object arguments directly (not a JSON string)", () => {
    const args = { key: "value", count: 42 };
    const call: OpenAIFunctionCall = {
      function: { name: "my_tool", arguments: args },
    };
    expect(adapter.toAction(call).arguments).toEqual(args);
  });

  test("7. toAction throws SyntaxError on malformed JSON string", () => {
    const call: OpenAIFunctionCall = {
      function: { name: "my_tool", arguments: "{bad: json}" },
    };
    expect(() => adapter.toAction(call)).toThrow(SyntaxError);
  });

  // ── toResponse ───────────────────────────────────────────────────────────

  test("8. toResponse returns { content } on success with string content", () => {
    const result: AgentActionResult = {
      success: true,
      content: "hello world",
    };
    const response = adapter.toResponse(result) as OpenAIToolResult;
    expect(response.content).toBe("hello world");
    expect(response.isError).toBeUndefined();
  });

  test("9. toResponse JSON-serializes non-string content", () => {
    const result: AgentActionResult = {
      success: true,
      content: [{ type: "text", text: "hi" }],
    };
    const response = adapter.toResponse(result) as OpenAIToolResult;
    expect(response.content).toBe(JSON.stringify([{ type: "text", text: "hi" }]));
  });

  test("10. toResponse returns { content: error, isError: true } on failure", () => {
    const result: AgentActionResult = { success: false, error: "Policy violation" };
    const response = adapter.toResponse(result) as OpenAIToolResult;
    expect(response.content).toBe("Policy violation");
    expect(response.isError).toBe(true);
  });

  // ── createActionReceipt ───────────────────────────────────────────────────

  describe("createActionReceipt", () => {
    let privateKey: Uint8Array;
    let prevReceipt: SignedReceipt;

    beforeAll(async () => {
      privateKey = ed.utils.randomPrivateKey();
      const keyId = "test-key-openai-1";

      const manifestFields: ReceiptFields = {
        receipt_id: ulid(),
        record_type: "workflow_manifest",
        spec_version: "var/1.0",
        workflow_id: "wf-openai-test-1",
        workflow_id_source: "nonsudo_generated",
        agent_id: "agent-openai-1",
        issued_at: "2026-01-01T00:00:00Z",
        prev_receipt_hash: null,
        sequence_number: 0,
        policy_bundle_hash: "sha256:abc123",
        rfc3161_token: null,
        tsa_id: null,
        initiator_id: "init-1",
        workflow_owner: "owner-1",
        session_budget: { api_calls: 100 },
        declared_tools: ["my_tool"],
        capability_manifest_hash: null,
        parent_workflow_id: null,
        framework_ref: null,
      };

      const unsigned = createReceipt(manifestFields);
      prevReceipt = await signReceipt(unsigned, privateKey, keyId);
    });

    test("11. createActionReceipt returns a SignedReceipt with record_type action_receipt", async () => {
      const receipt = await createActionReceipt({
        agentId: "agent-openai-1",
        workflowId: "wf-openai-test-1",
        toolName: "my_tool",
        args: { path: "/tmp" },
        decision: "ALLOW",
        decisionReason: "policy allows",
        blastRadius: "LOW",
        reversible: true,
        policyBundleHash: "sha256:abc123",
        prevReceipt,
        keypair: { privateKey, keyId: "test-key-openai-1" },
      });

      expect(receipt.record_type).toBe("action_receipt");
    });

    test("12. createActionReceipt chains correctly: sequence_number = prevReceipt.sequence_number + 1", async () => {
      const receipt = await createActionReceipt({
        agentId: "agent-openai-1",
        workflowId: "wf-openai-test-1",
        toolName: "my_tool",
        args: { query: "hello" },
        decision: "BLOCK",
        decisionReason: "blocked by policy",
        blastRadius: "HIGH",
        reversible: false,
        policyBundleHash: "sha256:abc123",
        prevReceipt,
        keypair: { privateKey, keyId: "test-key-openai-1" },
      });

      expect(receipt.sequence_number).toBe(prevReceipt.sequence_number + 1);
      expect((receipt as unknown as Record<string, unknown>).tool_name).toBe("my_tool");
    });
  });
});
