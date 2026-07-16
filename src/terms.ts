import type { Detector } from './detectors.js';

export type TermSpec = string | { term: string; replace?: string };

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function normalizeTerms(
  input: TermSpec[] | Record<string, string> | undefined,
): Array<{ term: string; replace?: string }> {
  if (!input) return [];
  const list = Array.isArray(input)
    ? input.map((t) => (typeof t === 'string' ? { term: t } : t))
    : Object.entries(input).map(([term, replace]) => ({ term, replace }));
  return list.filter((t) => t.term && t.term.length > 0);
}

/**
 * Build a detector from a user-supplied word/phrase list. Terms are matched
 * literally (longest first) with Unicode-aware boundaries, so it works for
 * names and codewords in any language. In a vault/session the matches get
 * reversible placeholders; in a one-way `redact` they use each term's `replace`
 * text (or `***`).
 */
export function buildTermsDetector(
  input: TermSpec[] | Record<string, string> | undefined,
  caseSensitive = false,
): Detector | null {
  const list = normalizeTerms(input);
  if (!list.length) return null;

  const alt = [...list]
    .sort((a, b) => b.term.length - a.term.length)
    .map((t) => escapeRe(t.term))
    .join('|');
  const flags = caseSensitive ? 'gu' : 'giu';
  const pattern = new RegExp(`(?<![\\p{L}\\p{N}_])(?:${alt})(?![\\p{L}\\p{N}_])`, flags);

  const key = (s: string) => (caseSensitive ? s : s.toLowerCase());
  const replaceMap = new Map(list.map((t) => [key(t.term), t.replace ?? '***']));

  return {
    id: 'custom_term',
    label: 'Custom term',
    why: 'A term you configured as sensitive.',
    pattern,
    mask: (m) => replaceMap.get(key(m)) ?? '***',
    default: true,
    tags: ['custom'],
  };
}
