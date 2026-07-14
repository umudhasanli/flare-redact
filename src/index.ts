import {
  DETECTORS,
  SENSITIVE_KEY_RE,
  SENSITIVE_KEY_DETECTOR,
  fnv1a,
  type Detector,
} from './detectors.js';

export {
  DETECTORS,
  SENSITIVE_KEY_RE,
  keepPrefix,
  keepLast,
  luhn,
  entropy,
  fnv1a,
  type Detector,
} from './detectors.js';

export type Mode = 'mask' | 'label' | 'hash';

export interface Finding {
  detector: string;
  label: string;
  why: string;
  value: string;
  start?: number;
  end?: number;
  path?: string;
}

export interface RedactOptions {
  only?: string[];
  enable?: string[];
  disable?: string[];
  custom?: Detector[];
  mode?: Mode;
  mask?: string | ((f: { value: string; detector: Detector }) => string);
  hashSalt?: string;
  redactKeys?: boolean | RegExp | string[];
  allow?: RegExp | string[];
}

interface Hit extends Finding {
  det: Detector;
}

function resolveDetectors(opts: RedactOptions): Detector[] {
  const all = [...DETECTORS, ...(opts.custom ?? [])];
  if (opts.only?.length) {
    const byId = new Map(all.map((d) => [d.id, d]));
    return opts.only.map((id) => byId.get(id)).filter((d): d is Detector => !!d);
  }
  const disabled = new Set(opts.disable ?? []);
  const enabled = new Set(opts.enable ?? []);
  return all.filter((d) => (d.default || enabled.has(d.id)) && !disabled.has(d.id));
}

function keyMatcher(opts: RedactOptions): (key: string) => boolean {
  const rk = opts.redactKeys;
  if (rk === false) return () => false;
  if (rk instanceof RegExp) return (k) => rk.test(k);
  if (Array.isArray(rk)) {
    const set = new Set(rk.map((s) => s.toLowerCase()));
    return (k) => set.has(k.toLowerCase());
  }
  return (k) => SENSITIVE_KEY_RE.test(k);
}

function allowMatcher(opts: RedactOptions): (value: string) => boolean {
  const a = opts.allow;
  if (!a) return () => false;
  if (a instanceof RegExp) return (v) => a.test(v);
  const set = new Set(a);
  return (v) => set.has(v);
}

function makeReplacer(opts: RedactOptions): (value: string, det: Detector) => string {
  const salt = opts.hashSalt ?? '';
  const mask = opts.mask;
  const mode = opts.mode ?? 'mask';
  return (value, det) => {
    if (typeof mask === 'string') return mask;
    if (typeof mask === 'function') return mask({ value, detector: det });
    if (mode === 'label') return `[REDACTED:${det.id}]`;
    if (mode === 'hash') return `${det.id}_${fnv1a(salt + value)}`;
    return det.mask ? det.mask(value) : '***';
  };
}

function withGlobal(re: RegExp): RegExp {
  return re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
}

function scanString(text: string, dets: Detector[], allow: (v: string) => boolean): Hit[] {
  const hits: Hit[] = [];
  for (const det of dets) {
    const re = withGlobal(det.pattern);
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      const value = m[0];
      if (!value) continue;
      if (det.validate && !det.validate(value)) continue;
      if (allow(value)) continue;
      hits.push({
        detector: det.id,
        label: det.label,
        why: det.why,
        value,
        start: m.index,
        end: m.index + value.length,
        det,
      });
    }
  }
  hits.sort((a, b) => a.start! - b.start! || b.end! - b.start! - (a.end! - a.start!));
  const kept: Hit[] = [];
  let lastEnd = -1;
  for (const h of hits) {
    if (h.start! >= lastEnd) {
      kept.push(h);
      lastEnd = h.end!;
    }
  }
  return kept;
}

function redactString(text: string, dets: Detector[], allow: (v: string) => boolean, replace: (v: string, d: Detector) => string): string {
  const hits = scanString(text, dets, allow);
  if (!hits.length) return text;
  let out = '';
  let cursor = 0;
  for (const h of hits) {
    out += text.slice(cursor, h.start);
    out += replace(h.value, h.det);
    cursor = h.end!;
  }
  return out + text.slice(cursor);
}

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
    const { det, ...f } = h;
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

export function summary(input: unknown, opts: RedactOptions = {}): { total: number; byDetector: Record<string, number> } {
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
