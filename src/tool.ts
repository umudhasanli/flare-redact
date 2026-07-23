import { redact, type RedactOptions } from './index.js';
import { createVault, type Vault, type VaultOptions } from './vault.js';

export interface ToolBoundary {
  /**
   * Mask an MCP/tool result before it is appended to model context. New
   * placeholders are added to this boundary's conversation-scoped vault.
   */
  redactForModel<T>(result: T): T;
  /** Restore placeholders in a model-produced tool call before execution. */
  restoreForTool<T>(call: T): T;
  /** Restore placeholders in the final model output before showing the app. */
  restoreForApp<T>(output: T): T;
  /** The conversation-scoped placeholder mapping. */
  readonly vault: Vault;
  readonly size: number;
  reset(): void;
}

/** One-way redaction for logging or persisting a tool call safely. */
export function redactToolCall<T>(call: T, opts: RedactOptions = {}): T {
  return redact(call, opts);
}

/** One-way redaction for logging or persisting a tool/MCP result safely. */
export function redactToolResult<T>(result: T, opts: RedactOptions = {}): T {
  return redact(result, opts);
}

/** One-way redaction for an arbitrary JSON-RPC/MCP message. */
export function redactMcpMessage<T>(message: T, opts: RedactOptions = {}): T {
  return redact(message, opts);
}

/**
 * Reversible boundary for agent loops:
 *
 * model tool call -> restoreForTool -> execute -> redactForModel -> model
 */
export function createToolBoundary(opts: VaultOptions = {}): ToolBoundary {
  let vault = createVault(opts);
  return {
    redactForModel: <T>(result: T): T => vault.redact(result),
    restoreForTool: <T>(call: T): T => vault.restore(call),
    restoreForApp: <T>(output: T): T => vault.restore(output),
    get vault() {
      return vault;
    },
    get size() {
      return vault.size;
    },
    reset() {
      vault = createVault(opts);
    },
  };
}
