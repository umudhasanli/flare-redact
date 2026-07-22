import { SENSITIVE_KEY_DETECTOR } from './detectors.js';
import { createVault } from './vault.js';
import {
  resolveDetectors,
  keyMatcher,
  allowMatcher,
  makeReplacer,
  scanString,
  redactString,
  type RedactOptions,
  type Finding,
  type Hit,
} from './engine.js';

export type { Mode, Risk, Finding, RedactOptions, SemanticFinding, SemanticProvider } from './engine.js';
export { RedactionLimitError } from './engine.js';
export type { Detector } from './detectors.js';
export {
  DETECTORS,
  SENSITIVE_KEY_RE,
  keepPrefix,
  keepLast,
  luhn,
  entropy,
  fnv1a,
} from './detectors.js';
export { pseudonymize, surrogate, fpe } from './transforms.js';
export { hmacFingerprint } from './crypto.js';
export { createVault, restore, buildRestore, type Vault, type VaultOptions } from './vault.js';
export {
  sealVault,
  openVault,
  isSealedVault,
  type SealedVaultV1,
  type SealVaultOptions,
} from './secure-vault.js';
export { createSession, type Session, type SessionOptions, type StreamRestorer } from './session.js';

export function redact<T>(input: T, opts: RedactOptions = {}): T {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const replace = makeReplacer(opts);
  const matchKey = keyMatcher(opts);

  const walk = (value: unknown): unknown => {
    if (typeof value === 'string') return redactString(value, dets, allow, replace, opts);
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        if (typeof v === 'string' && matchKey(k) && !allow(v)) {
          out[k] = replace(v, SENSITIVE_KEY_DETECTOR);
        } else {
          out[k] = walk(v);
        }
      }
      return out;
    }
    return value;
  };

  return walk(input) as T;
}

async function resolvedSemanticOptions(text: string, opts: RedactOptions): Promise<RedactOptions> {
  if (!opts.semanticProvider) return opts;
  const findings = await opts.semanticProvider.detect(text);
  return { ...opts, semanticProvider: { detect: () => findings } };
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
export async function redactAsync<T>(input: T, opts: RedactOptions = {}): Promise<T> {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const replace = makeReplacer(opts);
  const matchKey = keyMatcher(opts);

  const walk = async (value: unknown): Promise<unknown> => {
    if (typeof value === 'string') {
      const localOpts = await resolvedSemanticOptions(value, opts);
      return redactString(value, dets, allow, replace, localOpts);
    }
    if (Array.isArray(value)) return Promise.all(value.map(walk));
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        if (typeof v === 'string' && matchKey(k) && !allow(v)) out[k] = replace(v, SENSITIVE_KEY_DETECTOR);
        else out[k] = await walk(v);
      }
      return out;
    }
    return value;
  };

  return walk(input) as Promise<T>;
}

export function scan(input: unknown, opts: RedactOptions = {}): Finding[] {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const matchKey = keyMatcher(opts);
  const out: Finding[] = [];

  const push = (h: Hit, location: { line: number; column: number }, path?: string) => {
    const { det: _det, ...f } = h;
    out.push(path ? { ...f, ...location, path } : { ...f, ...location });
  };

  const walk = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      const hits = scanString(value, dets, allow, opts);
      let cursor = 0;
      let line = 1;
      let lineStart = 0;
      for (const h of hits) {
        const start = h.start ?? 0;
        while (cursor < start) {
          if (value.charCodeAt(cursor) === 10) {
            line++;
            lineStart = cursor + 1;
          }
          cursor++;
        }
        push(h, { line, column: start - lineStart + 1 }, path || undefined);
      }
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${path}[${i}]`));
    } else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) {
        const child = path ? `${path}.${k}` : k;
        if (typeof v === 'string' && matchKey(k) && !allow(v)) {
          out.push({
            detector: 'sensitive_key',
            label: 'Sensitive field',
            why: `Value stored under a sensitive field name ("${k}").`,
            value: v,
            path: child,
            risk: 'critical',
            confidence: 0.98,
          });
        } else {
          walk(v, child);
        }
      }
    }
  };

  walk(input, '');
  return out;
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
export async function scanAsync(input: unknown, opts: RedactOptions = {}): Promise<Finding[]> {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const matchKey = keyMatcher(opts);
  const out: Finding[] = [];

  const walk = async (value: unknown, path: string): Promise<void> => {
    if (typeof value === 'string') {
      const localOpts = await resolvedSemanticOptions(value, opts);
      const hits = scanString(value, dets, allow, localOpts);
      let cursor = 0;
      let line = 1;
      let lineStart = 0;
      for (const h of hits) {
        const start = h.start ?? 0;
        while (cursor < start) {
          if (value.charCodeAt(cursor) === 10) {
            line++;
            lineStart = cursor + 1;
          }
          cursor++;
        }
        const { det: _det, ...finding } = h;
        const located = { ...finding, line, column: start - lineStart + 1 };
        out.push(path ? { ...located, path } : located);
      }
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) await walk(value[i], `${path}[${i}]`);
    } else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) {
        const child = path ? `${path}.${k}` : k;
        if (typeof v === 'string' && matchKey(k) && !allow(v)) {
          out.push({
            detector: 'sensitive_key',
            label: 'Sensitive field',
            why: `Value stored under a sensitive field name ("${k}").`,
            value: v,
            path: child,
            risk: 'critical',
            confidence: 0.98,
          });
        } else {
          await walk(v, child);
        }
      }
    }
  };

  await walk(input, '');
  return out;
}

export async function isCleanAsync(input: unknown, opts: RedactOptions = {}): Promise<boolean> {
  return (await scanAsync(input, opts)).length === 0;
}

export function isClean(input: unknown, opts: RedactOptions = {}): boolean {
  return scan(input, opts).length === 0;
}

export function summary(
  input: unknown,
  opts: RedactOptions = {},
): { total: number; byDetector: Record<string, number>; byRisk: Record<string, number> } {
  const byDetector: Record<string, number> = {};
  const byRisk: Record<string, number> = {};
  const findings = scan(input, opts);
  for (const f of findings) {
    byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1;
    byRisk[f.risk] = (byRisk[f.risk] ?? 0) + 1;
  }
  return { total: findings.length, byDetector, byRisk };
}

/**
 * Bind one set of options into a policy you reuse everywhere — in code, on a
 * logger, in HTTP, in front of an LLM. `options` is the same object every
 * adapter (`flare-redact/pino`, `/winston`, `/http`, `/llm`) accepts, so a
 * secret is masked the same way across your whole system.
 */
export function createRedactor(opts: RedactOptions = {}) {
  return {
    options: opts,
    redact: <T>(input: T) => redact(input, opts),
    scan: (input: unknown) => scan(input, opts),
    isClean: (input: unknown) => isClean(input, opts),
    summary: (input: unknown) => summary(input, opts),
    vault: () => createVault(opts),
    wrapConsole: (target?: Console) => wrapConsole(opts, target),
  };
}

/** Alias for {@link createRedactor}, read as "define the masking policy once". */
export const definePolicy = createRedactor;

type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';
type LogFn = (...args: unknown[]) => void;

export function wrapConsole(opts: RedactOptions = {}, target: Console = console): () => void {
  const sink = target as unknown as Record<ConsoleMethod, LogFn>;
  const methods: ConsoleMethod[] = ['log', 'info', 'warn', 'error', 'debug'];
  const original = new Map<ConsoleMethod, LogFn>();
  for (const name of methods) {
    const fn = sink[name].bind(target) as LogFn;
    original.set(name, fn);
    sink[name] = (...args: unknown[]) => fn(...args.map((a) => redact(a, opts)));
  }
  return () => {
    for (const [name, fn] of original) sink[name] = fn;
  };
}
