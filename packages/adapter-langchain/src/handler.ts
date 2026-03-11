import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { Serialized } from "@langchain/core/load/serializable";
import type { LangChainAdapterConfig } from "./types";
import { WorkflowSession } from "./session";

/**
 * NonSudoCallbackHandler — LangChain callback handler that emits VAR receipts
 * for every tool invocation.
 *
 * Usage:
 *   const handler = new NonSudoCallbackHandler(config);
 *   const llm = new ChatOpenAI({ callbacks: [handler] });
 *
 * Receipt file is written to config.receipt_file. The workflow manifest
 * is written lazily on the first tool call (async init via getSession()).
 *
 * Phase 0 behaviour:
 *   - handleToolStart → action_receipt (decision: ALLOW) or dead_letter_receipt
 *     (if args cannot be parsed as JSON)
 *   - handleToolEnd  → no-op (response_hash deferred to Phase 1)
 *   - handleToolError → dead_letter_receipt
 */
export class NonSudoCallbackHandler extends BaseCallbackHandler {
  name = "NonSudoCallbackHandler";

  private config: LangChainAdapterConfig;
  private _session: WorkflowSession | null = null;
  private _sessionInit: Promise<WorkflowSession> | null = null;

  constructor(config: LangChainAdapterConfig) {
    super();
    if (!config.agent_id) {
      throw new Error("LangChainAdapterConfig: agent_id is required");
    }
    this.config = config;
  }

  private getSession(): Promise<WorkflowSession> {
    if (this._session) return Promise.resolve(this._session);
    if (!this._sessionInit) {
      this._sessionInit = WorkflowSession.create(this.config).then((s) => {
        this._session = s;
        return s;
      });
    }
    return this._sessionInit;
  }

  override async handleToolStart(
    tool: Serialized,
    input: string,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    name?: string
  ): Promise<void> {
    // Resolve tool name: prefer the explicit name param, then tool.id last element
    const toolName =
      name ??
      ((tool as { id?: string[] }).id?.at(-1)) ??
      "unknown";

    const session = await this.getSession();

    let args: Record<string, unknown>;
    try {
      args = JSON.parse(input) as Record<string, unknown>;
    } catch {
      // Malformed arguments → emit dead_letter_receipt instead of throwing
      await session.emitDeadLetter(
        toolName,
        {},
        "Failed to parse tool arguments: " + input,
        "fail_closed"
      );
      return;
    }

    await session.emitActionReceipt(
      toolName,
      args,
      "ALLOW",
      "langchain tool call",
      "LOW",
      true
    );
  }

  override async handleToolEnd(
    _output: string,
    _runId: string
  ): Promise<void> {
    // TODO(phase-1): update response_hash in the last action_receipt
  }

  override async handleToolError(
    err: Error | unknown,
    _runId: string
  ): Promise<void> {
    const session = await this.getSession();
    const message = err instanceof Error ? err.message : String(err);
    await session.emitDeadLetter("unknown", {}, message, "fail_closed");
  }
}
