import { DETECTORS, fnv1a, fpe, SENSITIVE_KEY_RE, type Detector } from './detectors.js';
import { MULTILANG_KEY_SET } from './i18n.js';
import { buildTermsDetector, type TermSpec } from './terms.js';

export type Mode = 'mask' | 'label' | 'hash' | 'fpe';

export interface Finding {
  detector: string;
  label: string;
  why: string;
  value: string;
  start?: number;
  end?: number;
  /** One-based line within the scanned string. */
  line?: number;
  /** One-based UTF-16 column within the scanned string. */
  column?: number;
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
  /** Your own words/phrases to always catch — masked one-way, or reversible in a vault. */
  terms?: TermSpec[] | Record<string, string>;
  /** Match `terms` case-sensitively (default: false). */
  termsCaseSensitive?: boolean;
}

export interface Hit extends Finding {
  det: Detector;
}

export type Replace = (value: string, det: Detector) => string;

function matches(entry: string, d: Detector): boolean {
  return d.id === entry || (d.tags?.includes(entry) ?? false);
}

export function resolveDetectors(opts: RedactOptions): Detector[] {
  const all = opts.custom?.length ? [...DETECTORS, ...opts.custom] : DETECTORS;
  let chosen: Detector[];
  if (opts.only?.length) {
    chosen = all.filter((d) => opts.only!.some((e) => matches(e, d)));
  } else {
    const { enable, disable } = opts;
    chosen = all.filter((d) => {
      const on = d.default || (enable?.some((e) => matches(e, d)) ?? false);
      const off = disable?.some((e) => matches(e, d)) ?? false;
      return on && !off;
    });
  }
  const termsDet = buildTermsDetector(opts.terms, opts.termsCaseSensitive);
  return termsDet ? [termsDet, ...chosen] : chosen;
}

export function keyMatcher(opts: RedactOptions): (key: string) => boolean {
  const rk = opts.redactKeys;
  if (rk === false) return () => false;
  if (rk instanceof RegExp) return (k) => rk.test(k);
  if (Array.isArray(rk)) {
    const set = new Set(rk.map((s) => s.toLowerCase()));
    return (k) => set.has(k.toLowerCase());
  }
  return (k) => SENSITIVE_KEY_RE.test(k) || MULTILANG_KEY_SET.has(k.toLowerCase());
}

export function allowMatcher(opts: RedactOptions): (value: string) => boolean {
  const a = opts.allow;
  if (!a) return () => false;
  if (a instanceof RegExp) return (v) => a.test(v);
  const set = new Set(a);
  return (v) => set.has(v);
}

export function makeReplacer(opts: RedactOptions): Replace {
  const salt = opts.hashSalt ?? '';
  const mask = opts.mask;
  const mode = opts.mode ?? 'mask';
  if (typeof mask === 'string') return () => mask;
  if (typeof mask === 'function') return (value, det) => mask({ value, detector: det });
  if (mode === 'label') return (_value, det) => `[REDACTED:${det.id}]`;
  if (mode === 'hash') return (value, det) => `${det.id}_${fnv1a(salt + value)}`;
  if (mode === 'fpe') return (value) => fpe(value, salt);
  return (value, det) => (det.mask ? det.mask(value) : '***');
}

function withGlobal(re: RegExp): RegExp {
  return re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
}

export function scanString(
  text: string,
  dets: Detector[],
  allow: (v: string) => boolean,
): Hit[] {
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
  if (hits.length < 2) return hits;
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

export function redactString(
  text: string,
  dets: Detector[],
  allow: (v: string) => boolean,
  replace: Replace,
): string {
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
