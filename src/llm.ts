import { createVault, type Vault, type VaultOptions } from './index.js';

export type { Vault, VaultOptions } from './index.js';
export { createVault } from './index.js';

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
  const map = vault.entries();
  let buf = '';
  const restoreComplete = (s: string): string => {
    let out = s;
    for (const [ph, orig] of map) out = out.split(ph).join(orig);
    return out;
  };
  return {
    push(chunk: string): string {
      buf += chunk;
      // Hold back a trailing "[..." that might still be an unfinished placeholder.
      const open = buf.lastIndexOf('[');
      const emitEnd = open !== -1 && buf.indexOf(']', open) === -1 ? open : buf.length;
      const emit = buf.slice(0, emitEnd);
      buf = buf.slice(emitEnd);
      return restoreComplete(emit);
    },
    flush(): string {
      const out = restoreComplete(buf);
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
 * sees the real values; your app still gets the right answer. Streaming works.
 *
 * Mutates and returns the client.
 */
export function wrapOpenAI<T extends OpenAILike>(client: T, opts: VaultOptions = {}): T {
  const completions = client?.chat?.completions;
  if (!completions || typeof completions.create !== 'function') {
    throw new Error('wrapOpenAI: expected a client with chat.completions.create');
  }
  const original = completions.create.bind(completions);

  completions.create = ((params: OpenAIParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const messages = Array.isArray(params?.messages)
      ? params.messages.map((m) => ({ ...m, content: redactContent(m.content, vault) }))
      : params?.messages;
    const redacted = { ...params, messages };
    const result = original(redacted, ...rest);

    if (params?.stream) return wrapOpenAIStream(result, vault);
    return (Promise.resolve(result) as Promise<OpenAIResponse>).then((res) => {
      if (res && Array.isArray(res.choices)) {
        res.choices = res.choices.map((c) =>
          c && c.message ? { ...c, message: { ...c.message, content: vault.restore(c.message.content) } } : c,
        );
      }
      return res;
    });
  }) as typeof completions.create;

  return client;
}

async function* wrapOpenAIStream(result: unknown, vault: Vault): AsyncGenerator<unknown> {
  const stream = (await result) as AsyncIterable<OpenAIChunk>;
  const r = makeStreamRestorer(vault);
  for await (const chunk of stream) {
    const content = chunk?.choices?.[0]?.delta?.content;
    if (typeof content === 'string') {
      const out = r.push(content);
      yield {
        ...chunk,
        choices: chunk.choices.map((c, i) =>
          i === 0 ? { ...c, delta: { ...c.delta, content: out } } : c,
        ),
      };
    } else {
      yield chunk;
    }
  }
  const tail = r.flush();
  if (tail) yield { choices: [{ index: 0, delta: { content: tail }, finish_reason: null }] };
}

/**
 * Wrap an Anthropic client so secrets and PII are stripped from every message
 * (and the system prompt) before it's sent, and restored in the reply.
 *
 * Mutates and returns the client.
 */
export function wrapAnthropic<T extends AnthropicLike>(client: T, opts: VaultOptions = {}): T {
  const messages = client?.messages;
  if (!messages || typeof messages.create !== 'function') {
    throw new Error('wrapAnthropic: expected a client with messages.create');
  }
  const original = messages.create.bind(messages);

  messages.create = ((params: AnthropicParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const redacted: AnthropicParams = {
      ...params,
      messages: Array.isArray(params?.messages)
        ? params.messages.map((m) => ({ ...m, content: redactContent(m.content, vault) }))
        : params?.messages,
    };
    if (typeof params?.system === 'string') redacted.system = vault.redact(params.system);
    else if (Array.isArray(params?.system)) redacted.system = redactContent(params.system, vault) as unknown[];

    const result = original(redacted, ...rest);

    if (params?.stream) return wrapAnthropicStream(result, vault);
    return (Promise.resolve(result) as Promise<AnthropicResponse>).then((res) => {
      if (res && Array.isArray(res.content)) {
        res.content = res.content.map((block) =>
          block && typeof block.text === 'string' ? { ...block, text: vault.restore(block.text) } : block,
        );
      }
      return res;
    });
  }) as typeof messages.create;

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

interface OpenAIParams {
  messages?: Array<{ content: unknown; [k: string]: unknown }>;
  stream?: boolean;
  [k: string]: unknown;
}
interface OpenAIChunk {
  choices: Array<{ delta?: { content?: unknown; [k: string]: unknown }; [k: string]: unknown }>;
  [k: string]: unknown;
}
interface OpenAIResponse {
  choices?: Array<{ message?: { content: unknown; [k: string]: unknown }; [k: string]: unknown }>;
  [k: string]: unknown;
}
interface OpenAILike {
  chat: { completions: { create: (params: OpenAIParams, ...rest: unknown[]) => unknown } };
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
interface AnthropicResponse {
  content?: Array<{ text?: unknown; [k: string]: unknown }>;
  [k: string]: unknown;
}
interface AnthropicLike {
  messages: { create: (params: AnthropicParams, ...rest: unknown[]) => unknown };
}
