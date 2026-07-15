import { SENSITIVE_KEY_DETECTOR } from './detectors.js';
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

export type { Mode, Finding, RedactOptions } from './engine.js';
export type { Detector } from './detectors.js';
export {
  DETECTORS,
  SENSITIVE_KEY_RE,
  keepPrefix,
  keepLast,
  luhn,
  entropy,
  fnv1a,
  fpe,
} from './detectors.js';
export { createVault, restore, buildRestore, type Vault, type VaultOptions } from './vault.js';

export function redact<T>(input: T, opts: RedactOptions = {}): T {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const replace = makeReplacer(opts);
  const matchKey = keyMatcher(opts);

  const walk = (value: unknown): unknown => {
    if (typeof value === 'string') return redactString(value, dets, allow, replace);
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

export function scan(input: unknown, opts: RedactOptions = {}): Finding[] {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const matchKey = keyMatcher(opts);
  const out: Finding[] = [];

  const push = (h: Hit, path?: string) => {
    const { det: _det, ...f } = h;
    out.push(path ? { ...f, path } : f);
  };

  const walk = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      for (const h of scanString(value, dets, allow)) push(h, path || undefined);
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

export function isClean(input: unknown, opts: RedactOptions = {}): boolean {
  return scan(input, opts).length === 0;
}

export function summary(
  input: unknown,
  opts: RedactOptions = {},
): { total: number; byDetector: Record<string, number> } {
  const byDetector: Record<string, number> = {};
  const findings = scan(input, opts);
  for (const f of findings) byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1;
  return { total: findings.length, byDetector };
}

export function createRedactor(opts: RedactOptions = {}) {
  return {
    redact: <T>(input: T) => redact(input, opts),
    scan: (input: unknown) => scan(input, opts),
    isClean: (input: unknown) => isClean(input, opts),
    summary: (input: unknown) => summary(input, opts),
  };
}

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
