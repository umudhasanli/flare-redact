import {
  resolveDetectors,
  keyMatcher,
  allowMatcher,
  scanString,
  type RedactOptions,
} from './engine.js';

export interface Vault {
  redact<T>(input: T): T;
  restore<T>(input: T): T;
  entries(): Array<[string, string]>;
  readonly size: number;
}

export interface VaultOptions extends RedactOptions {
  placeholder?: (detectorId: string, index: number) => string;
  /** Human-readable counters are predictable; use only for trusted local flows. */
  placeholderStyle?: 'opaque' | 'readable';
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function opaqueToken(): string {
  const provider = globalThis.crypto;
  if (!provider?.getRandomValues) throw new Error('Web Crypto is required to create opaque vault placeholders.');
  const bytes = provider.getRandomValues(new Uint8Array(12));
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * Build a single-pass restorer from placeholder→original entries. Longest
 * placeholders match first so prefix-like custom tokens cannot clobber peers.
 */
export function buildRestore(entries: Array<[string, string]>): (text: string) => string {
  if (!entries.length) return (t) => t;
  const sorted = [...entries].sort((a, b) => b[0].length - a[0].length);
  const lookup = new Map(sorted);
  const re = new RegExp(sorted.map(([ph]) => escapeRe(ph)).join('|'), 'g');
  return (text) => text.replace(re, (m) => lookup.get(m) ?? m);
}

function walkStrings(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) return value.map((v) => walkStrings(v, fn));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = walkStrings(v, fn);
    return out;
  }
  return value;
}

/**
 * A reversible redactor. `redact()` swaps each secret for a stable opaque
 * placeholder and remembers the mapping; `restore()` puts the originals back.
 * The same value always gets the same placeholder, so references survive a
 * round trip — send the redacted text to an LLM, then restore its answer.
 */
export function createVault(opts: VaultOptions = {}): Vault {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const matchKey = keyMatcher(opts);
  const fmt = opts.placeholder ?? (opts.placeholderStyle === 'readable'
    ? ((id, n) => `[${id.toUpperCase()}_${n}]`)
    : ((id) => `[FR_${id.toUpperCase()}_${opaqueToken()}]`));

  const origToPh = new Map<string, string>();
  const phToOrig = new Map<string, string>();
  const counts = new Map<string, number>();

  const mint = (value: string, detId: string): string => {
    const existing = origToPh.get(value);
    if (existing) return existing;
    const n = (counts.get(detId) ?? 0) + 1;
    counts.set(detId, n);
    const ph = fmt(detId, n);
    const collision = phToOrig.get(ph);
    if (collision !== undefined && collision !== value) {
      throw new Error(`Placeholder generator produced a duplicate token for ${detId}.`);
    }
    origToPh.set(value, ph);
    phToOrig.set(ph, value);
    return ph;
  };

  const redactStr = (text: string): string => {
    const hits = scanString(text, dets, allow, opts);
    if (!hits.length) return text;
    let out = '';
    let cursor = 0;
    for (const h of hits) {
      out += text.slice(cursor, h.start);
      out += mint(h.value, h.det.id);
      cursor = h.end!;
    }
    return out + text.slice(cursor);
  };

  const redactWalk = (value: unknown): unknown => {
    if (typeof value === 'string') return redactStr(value);
    if (Array.isArray(value)) return value.map(redactWalk);
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        if (typeof v === 'string' && matchKey(k) && !allow(v)) out[k] = mint(v, 'sensitive_key');
        else out[k] = redactWalk(v);
      }
      return out;
    }
    return value;
  };

  return {
    redact: <T>(input: T) => redactWalk(input) as T,
    restore: <T>(input: T) => walkStrings(input, buildRestore([...phToOrig])) as T,
    entries: () => [...phToOrig],
    get size() {
      return phToOrig.size;
    },
  };
}

/** Put originals back into any text/object using a vault or a placeholder→value map. */
export function restore<T>(input: T, source: Vault | Map<string, string> | Record<string, string>): T {
  const entries: Array<[string, string]> =
    source instanceof Map
      ? [...source]
      : typeof (source as Vault).entries === 'function'
        ? (source as Vault).entries()
        : Object.entries(source as Record<string, string>);
  if (!entries.length) return input;
  return walkStrings(input, buildRestore(entries)) as T;
}
