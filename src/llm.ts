import { createVault, buildRestore, type Vault, type VaultOptions } from './vault.js';

export type { Vault, VaultOptions } from './vault.js';
export { createVault } from './vault.js';

const WRAPPED = Symbol.for('flare-redact.wrapped');

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

function makeStreamRestorer(vault: Vault) {
  const restore = buildRestore(vault.entries());
  let buf = '';
  return {
    push(chunk: string): string {
      buf += chunk;
      // Hold back a trailing "[…" that could still be an unfinished placeholder.
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
}

/** Redact a prompt and hand back the vault so you can restore the reply yourself. */
export function redactPrompt(text: string, opts: VaultOptions = {}): { text: string; vault: Vault } {
  const vault = createVault(opts);
  return { text: vault.redact(text), vault };
}

/**
 * Wrap an OpenAI client so secrets and PII are stripped from every chat prompt
 * before it leaves your process, and restored in the reply. The model never
 * sees the real values; your app still gets the right answer. Streaming works,
 * and wrapping the same client twice is a no-op.
 *
 * Mutates and returns the client.
 */
export function wrapOpenAI<T extends OpenAILike>(client: T, opts: VaultOptions = {}): T {
  const completions = client?.chat?.completions as (OpenAICompletions & Marked) | undefined;
  if (!completions || typeof completions.create !== 'function') {
    throw new Error('wrapOpenAI: expected a client with chat.completions.create');
  }
  if (completions[WRAPPED]) return client;
  const original = completions.create.bind(completions);

  completions.create = (params: OpenAIParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const messages = Array.isArray(params?.messages)
      ? params.messages.map((m) => ({ ...m, content: redactContent(m.content, vault) }))
      : params?.messages;
    const result = original({ ...params, messages }, ...rest);
    if (params?.stream) return wrapOpenAIStream(result, vault);
    return Promise.resolve(result).then((res) => vault.restore(res));
  };
  completions[WRAPPED] = true;
  return client;
}

async function* wrapOpenAIStream(result: unknown, vault: Vault): AsyncGenerator<unknown> {
  const stream = (await result) as AsyncIterable<OpenAIChunk>;
  const r = makeStreamRestorer(vault);
  let last: OpenAIChunk | undefined;
  for await (const chunk of stream) {
    last = chunk;
    const content = chunk?.choices?.[0]?.delta?.content;
    if (typeof content === 'string') {
      const out = r.push(content);
      yield {
        ...chunk,
        choices: chunk.choices.map((c, i) => (i === 0 ? { ...c, delta: { ...c.delta, content: out } } : c)),
      };
    } else {
      yield chunk;
    }
  }
  const tail = r.flush();
  if (tail) {
    const base = last ? { id: last.id, object: last.object, model: last.model } : {};
    yield { ...base, choices: [{ index: 0, delta: { content: tail }, finish_reason: null }] };
  }
}

/**
 * Wrap an Anthropic client so secrets and PII are stripped from every message
 * and the system prompt before it's sent, and restored in the reply. Streaming
 * works, and wrapping the same client twice is a no-op.
 *
 * Mutates and returns the client.
 */
export function wrapAnthropic<T extends AnthropicLike>(client: T, opts: VaultOptions = {}): T {
  const messages = client?.messages as (AnthropicMessages & Marked) | undefined;
  if (!messages || typeof messages.create !== 'function') {
    throw new Error('wrapAnthropic: expected a client with messages.create');
  }
  if (messages[WRAPPED]) return client;
  const original = messages.create.bind(messages);

  messages.create = (params: AnthropicParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const redacted: AnthropicParams = {
      ...params,
      messages: Array.isArray(params?.messages)
        ? params.messages.map((m) => ({ ...m, content: redactContent(m.content, vault) }))
        : params?.messages,
    };
    if (params?.system !== undefined) redacted.system = redactContent(params.system, vault);
    const result = original(redacted, ...rest);
    if (params?.stream) return wrapAnthropicStream(result, vault);
    return Promise.resolve(result).then((res) => vault.restore(res));
  };
  messages[WRAPPED] = true;
  return client;
}

async function* wrapAnthropicStream(result: unknown, vault: Vault): AsyncGenerator<unknown> {
  const stream = (await result) as AsyncIterable<AnthropicEvent>;
  const r = makeStreamRestorer(vault);
  for await (const event of stream) {
    const text = event?.delta?.text;
    if (event?.type === 'content_block_delta' && typeof text === 'string') {
      yield { ...event, delta: { ...event.delta, text: r.push(text) } };
    } else {
      yield event;
    }
  }
  const tail = r.flush();
  if (tail) yield { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: tail } };
}

type Marked = { [WRAPPED]?: boolean };

interface OpenAIParams {
  messages?: Array<{ content: unknown; [k: string]: unknown }>;
  stream?: boolean;
  [k: string]: unknown;
}
interface OpenAIChunk {
  id?: unknown;
  object?: unknown;
  model?: unknown;
  choices: Array<{ delta?: { content?: unknown; [k: string]: unknown }; [k: string]: unknown }>;
  [k: string]: unknown;
}
interface OpenAICompletions {
  create: (params: OpenAIParams, ...rest: unknown[]) => unknown;
}
interface OpenAILike {
  chat: { completions: OpenAICompletions };
}

interface AnthropicParams {
  messages?: Array<{ content: unknown; [k: string]: unknown }>;
  system?: unknown;
  stream?: boolean;
  [k: string]: unknown;
}
interface AnthropicEvent {
  type?: string;
  delta?: { text?: unknown; [k: string]: unknown };
  [k: string]: unknown;
}
interface AnthropicMessages {
  create: (params: AnthropicParams, ...rest: unknown[]) => unknown;
}
interface AnthropicLike {
  messages: AnthropicMessages;
}
