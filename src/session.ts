import { createVault, buildStreamRestore, type Vault, type VaultOptions } from './vault.js';

export interface SessionOptions extends VaultOptions {}

interface ChatMessage {
  role?: string;
  content: unknown;
  [k: string]: unknown;
}

export interface StreamRestorer {
  /** Feed a streamed chunk, get back the safe-to-display text so far. */
  push(chunk: string): string;
  /** Flush any held-back tail once the stream ends. */
  flush(): string;
}

export interface Session {
  /** Mask a user message before it reaches the model. */
  redact<T>(input: T): T;
  /** Restore the model's reply before showing it to the user. */
  restore<T>(input: T): T;
  /** Mask a whole `[{ role, content }]` chat array in one call. */
  redactMessages<M extends ChatMessage>(messages: M[]): M[];
  /** A restorer for streamed replies — rebuilds originals even across chunk splits. */
  stream(): StreamRestorer;
  /** The underlying vault (placeholder ↔ original map). */
  readonly vault: Vault;
  /** How many distinct values have been masked this session. */
  readonly size: number;
  /** Start a fresh conversation — a new vault, no carried-over mappings. */
  reset(): void;
}

/**
 * A conversation-scoped redactor for chat/AI apps. One session keeps one vault,
 * so the same value maps to the same placeholder across every turn — mask the
 * user's message on the way in, restore the model's answer on the way out. Model
 * agnostic (works with a local model or any API), synchronous, and fast enough
 * that the cost disappears next to inference.
 *
 *   const session = createSession({ enable: ['pii'] });
 *   const safe = session.redact(userMessage);   // → send `safe` to the model
 *   const reply = session.restore(modelReply);  // → show `reply` to the user
 */
export function createSession(opts: SessionOptions = {}): Session {
  let vault = createVault(opts);

  return {
    redact: <T>(input: T): T => vault.redact(input),
    restore: <T>(input: T): T => vault.restore(input),
    redactMessages: <M extends ChatMessage>(messages: M[]): M[] => vault.redact(messages),
    stream(): StreamRestorer {
      return buildStreamRestore(vault.entries());
    },
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
