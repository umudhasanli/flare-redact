// Secret-confidence classifier.
//
// A tiny logistic-regression model that scores how likely a matched string is a
// real secret rather than a benign look-alike (a UUID, git SHA, digest, slug,
// or dictionary word). It exists because pattern-only detection over-fires on
// high-entropy text, and confidence should reflect that.
//
// The model is trained offline by scripts/train-confidence-model.mjs and shipped
// as fixed weights in confidence-model.ts, so this stays zero-dependency,
// synchronous, deterministic, and safe on edge and browser runtimes. Inference
// is one pass to build the feature vector plus a dot product — no matrix
// library, no async, no network.
//
// The feature list here MUST match scripts/train-confidence-model.mjs exactly;
// test/ml.test.mjs asserts the count and order against the shipped model.

import { CONFIDENCE_MODEL, type ConfidenceModel } from './confidence-model.js';

export type { ConfidenceModel } from './confidence-model.js';
export { CONFIDENCE_MODEL } from './confidence-model.js';

/** Feature names in the exact order extractFeatures returns them. */
export const FEATURES = [
  'log2Len', 'entropy', 'fracLower', 'fracUpper', 'fracDigit', 'fracSymbol',
  'fracHex', 'vowelFrac', 'classTransitionRate', 'hasMixedClasses',
  'maxRunFrac', 'structuredHexId', 'ctxSecret', 'ctxBenign',
] as const;

export const FEATURE_COUNT = FEATURES.length;

const SECRET_CTX = /\b(secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)\b/i;
const BENIGN_CTX = /\b(uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id|version|colou?r|slug|filename)\b/i;
const STRUCTURED_HEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

/** Shannon entropy in bits per symbol, over Unicode code points. */
export function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  let total = 0;
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
    total++;
  }
  if (total === 0) return 0;
  let e = 0;
  for (const n of freq.values()) {
    const p = n / total;
    e -= p * Math.log2(p);
  }
  return e;
}

/**
 * Cheap character-level features for `value`, optionally informed by nearby
 * `context` text. Returns a fixed-length numeric vector aligned with FEATURES.
 */
export function extractFeatures(value: string, context = ''): number[] {
  const len = value.length || 1;
  let lower = 0, upper = 0, digit = 0, symbol = 0, hex = 0, vowel = 0, letters = 0;
  let transitions = 0, run = 1, maxRun = 1, prevClass = -1;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 97 && c <= 122) { lower++; letters++; }
    else if (c >= 65 && c <= 90) { upper++; letters++; }
    else if (c >= 48 && c <= 57) digit++;
    else symbol++;
    if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)) hex++;
    if (c === 97 || c === 101 || c === 105 || c === 111 || c === 117 ||
        c === 65 || c === 69 || c === 73 || c === 79 || c === 85) vowel++;
    const cls = c >= 48 && c <= 57 ? 1 : (c >= 97 && c <= 122) || (c >= 65 && c <= 90) ? 0 : 2;
    if (prevClass === -1) prevClass = cls;
    else {
      if (cls !== prevClass) { transitions++; run = 1; } else run++;
      if (run > maxRun) maxRun = run;
      prevClass = cls;
    }
  }
  const f = new Array<number>(FEATURE_COUNT).fill(0);
  f[0] = Math.log2(len);
  f[1] = shannonEntropy(value);
  f[2] = lower / len;
  f[3] = upper / len;
  f[4] = digit / len;
  f[5] = symbol / len;
  f[6] = hex / len;
  f[7] = letters ? vowel / letters : 0;
  f[8] = len > 1 ? transitions / (len - 1) : 0;
  f[9] = lower > 0 && upper > 0 && digit > 0 ? 1 : 0;
  f[10] = maxRun / len;
  f[11] = STRUCTURED_HEX.test(value) ? 1 : 0;
  f[12] = SECRET_CTX.test(context) ? 1 : 0;
  f[13] = BENIGN_CTX.test(context) ? 1 : 0;
  return f;
}

const sigmoid = (z: number): number => (z >= 0
  ? 1 / (1 + Math.exp(-z))
  : Math.exp(z) / (1 + Math.exp(z)));

/**
 * Probability in [0, 1] that `value` is a real secret rather than a benign
 * high-entropy string. `context` is the surrounding text, which lets nearby
 * labels such as `api_key=` or `commit:` shift the score.
 *
 * Pass an alternative `model` to score against a custom-trained classifier with
 * the same feature layout.
 */
export function secretProbability(
  value: string,
  context = '',
  model: ConfidenceModel = CONFIDENCE_MODEL,
): number {
  const x = extractFeatures(value, context);
  let z = model.bias;
  for (let j = 0; j < FEATURE_COUNT; j++) z += (model.weights[j] ?? 0) * x[j]!;
  return sigmoid(z);
}
