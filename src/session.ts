import { createVault, buildRestore, type Vault, type VaultOptions } from './vault.js';

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

function redactContent(content: unknown, vault: Vault): unknown {
  if (typeof content === 'string') return vault.redact(content);
  if (Array.isArray(content)) {
    return content.map((part) =>
      part && typeof part === 'object' && typeof (part as { text?: unknown }).text === 'string'
        ? { ...part, text: vault.redact((part as { text: string }).text) }
        : part,
    );
  }
  return content;
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
    redactMessages: <M extends ChatMessage>(messages: M[]): M[] =>
      messages.map((m) => ({ ...m, content: redactContent(m.content, vault) })),
    stream(): StreamRestorer {
      const restore = buildRestore(vault.entries());
      let buf = '';
      return {
        push(chunk: string): string {
          buf += chunk;
          const open = buf.lastIndexOf('[');
          const emitEnd = open !== -1 && buf.indexOf(']', open) === -1 ? open : buf.length;
          const emit = buf.slice(0, emitEnd);
          buf = buf.slice(emitEnd);
          return restore(emit);
        },
        flush(): string {
          const out = restore(buf);
          buf = '';
          return out;
        },
      };
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
