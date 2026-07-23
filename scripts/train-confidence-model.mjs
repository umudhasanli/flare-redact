// Offline trainer for the secret-confidence model shipped in src/confidence-model.ts.
//
// The library ships no ML runtime and takes no runtime dependency: this script
// runs once, learns a small logistic-regression model from synthetic labelled
// data, and prints a plain TypeScript file whose only content is fixed numbers.
// Inference at runtime is a single dot product over the features in src/ml.ts.
//
// It is deterministic. A seeded PRNG generates the data and initialises the
// weights, so `node scripts/train-confidence-model.mjs` produces the same model
// every time. Re-run it and diff src/confidence-model.ts to review any change.
//
//   node scripts/train-confidence-model.mjs            # print metrics + model
//   node scripts/train-confidence-model.mjs --write    # also overwrite the file
//
// Keep the feature list here in lockstep with FEATURE_COUNT / extractFeatures
// in src/ml.ts; a mismatch is caught by test/ml.test.mjs.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'src', 'confidence-model.ts');

// --- deterministic PRNG (mulberry32) -------------------------------------
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(0x9e3779b9);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const randInt = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
const HEX = '0123456789abcdef';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B64URL = B64 + '-_';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
function draw(alphabet, n) {
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[Math.floor(rand() * alphabet.length)];
  return s;
}

// --- feature extraction (mirror of src/ml.ts) ----------------------------
const SECRET_CTX = /\b(secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)\b/i;
const BENIGN_CTX = /\b(uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id|version|colou?r|slug|filename)\b/i;
const STRUCTURED_HEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;

function shannon(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / [...s].length;
    e -= p * Math.log2(p);
  }
  return e;
}

const FEATURES = [
  'log2Len', 'entropy', 'fracLower', 'fracUpper', 'fracDigit', 'fracSymbol',
  'fracHex', 'vowelFrac', 'classTransitionRate', 'hasMixedClasses',
  'maxRunFrac', 'structuredHexId', 'ctxSecret', 'ctxBenign',
];
const FEATURE_COUNT = FEATURES.length;

function classOf(code) {
  if ((code >= 97 && code <= 122) || (code >= 65 && code <= 90)) return 0; // letter
  if (code >= 48 && code <= 57) return 1; // digit
  return 2; // symbol
}

function extractFeatures(value, context = '') {
  const len = value.length || 1;
  let lower = 0, upper = 0, digit = 0, symbol = 0, hex = 0, vowel = 0, letters = 0;
  let transitions = 0, run = 1, maxRun = 1, prevClass = -1;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const ch = value[i];
    if (c >= 97 && c <= 122) { lower++; letters++; }
    else if (c >= 65 && c <= 90) { upper++; letters++; }
    else if (c >= 48 && c <= 57) digit++;
    else symbol++;
    if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)) hex++;
    if ('aeiouAEIOU'.includes(ch)) vowel++;
    const cls = classOf(c);
    if (prevClass === -1) prevClass = cls;
    else {
      if (cls !== prevClass) { transitions++; run = 1; } else run++;
      if (run > maxRun) maxRun = run;
      prevClass = cls;
    }
  }
  const f = new Array(FEATURE_COUNT).fill(0);
  f[0] = Math.log2(len);
  f[1] = shannon(value);
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

// --- labelled data generators --------------------------------------------
const SECRET_CTX_WORDS = ['api_key', 'apiKey', 'secret', 'token', 'authorization', 'bearer', 'access_key', 'client_secret', 'password', 'signing_key'];
const BENIGN_CTX_WORDS = ['uuid', 'commit', 'sha256', 'md5', 'etag', 'request_id', 'trace_id', 'object_id', 'version', 'checksum', 'filename', 'slug'];
const WORDS = ['configuration', 'deployment', 'authentication', 'repository', 'environment', 'controller', 'middleware', 'transaction', 'subscription', 'notification', 'serialization', 'orchestration', 'availability', 'dependencies', 'immutable', 'kubernetes', 'observability', 'idempotent'];

function wrap(value, ctxWords, p = 0.6) {
  if (rand() > p) return { value, context: value };
  const w = pick(ctxWords);
  const sep = pick([': ', '=', '="', ' = ', ':']);
  return { value, context: `${w}${sep}${value}` };
}

function genPositive() {
  const kind = randInt(0, 10);
  let value;
  switch (kind) {
    case 0: value = 'AKIA' + draw('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16); break; // aws access key id
    case 1: value = draw(B64, 40); break; // aws secret access key
    case 2: value = 'ghp_' + draw(B64, 36); break; // github pat
    case 3: value = 'xoxb-' + randInt(100000000000, 999999999999) + '-' + draw(B64, 24); break; // slack
    case 4: value = 'sk_live_' + draw(B64, 24); break; // stripe
    case 5: value = 'AIza' + draw(B64URL, 35); break; // google api key
    case 6: value = 'sk-' + draw(B64, 48); break; // openai
    case 7: value = draw(B64URL, randInt(27, 43)); break; // generic high-entropy token
    case 8: { // jwt-ish base64url triples
      value = draw(B64URL, randInt(18, 30)) + '.' + draw(B64URL, randInt(40, 90)) + '.' + draw(B64URL, randInt(30, 43));
      break;
    }
    case 9: value = draw(HEX, randInt(48, 64)); break; // long hex secret (not a standard digest length band edge)
    default: value = draw(B64, randInt(32, 50)); break;
  }
  // real secrets most often appear next to a secret-ish label
  return wrap(value, SECRET_CTX_WORDS, 0.7);
}

function genNegative() {
  const kind = randInt(0, 13);
  let value, ctxWords = BENIGN_CTX_WORDS, p = 0.6;
  switch (kind) {
    case 0: // uuid v4
      value = `${draw(HEX, 8)}-${draw(HEX, 4)}-4${draw(HEX, 3)}-${pick('89ab')}${draw(HEX, 3)}-${draw(HEX, 12)}`;
      break;
    case 1: value = draw(HEX, 40); break; // git commit sha
    case 2: value = draw(HEX, 32); break; // md5 / mongo-ish
    case 3: value = draw(HEX, 64); break; // sha256 digest
    case 4: value = draw(HEX, 24); break; // mongo objectid
    case 5: value = draw(HEX, randInt(7, 12)); break; // short sha
    case 6: value = pick(WORDS) + pick(['', '_' + pick(WORDS), pick(WORDS)]); break; // identifiers / words
    case 7: { // camelCase identifier
      value = pick(WORDS);
      value = value[0] + value.slice(1) + pick(WORDS).replace(/^./, (c) => c.toUpperCase());
      ctxWords = ['function', 'const', 'variable', 'field'];
      break;
    }
    case 8: value = `${randInt(2018, 2026)}-${String(randInt(1, 12)).padStart(2, '0')}-${String(randInt(1, 28)).padStart(2, '0')}T${String(randInt(0, 23)).padStart(2, '0')}:${String(randInt(0, 59)).padStart(2, '0')}:${String(randInt(0, 59)).padStart(2, '0')}Z`; break; // iso timestamp
    case 9: value = `${randInt(1, 20)}.${randInt(0, 40)}.${randInt(0, 99)}`; ctxWords = ['version', 'release']; break; // semver
    case 10: value = String(randInt(100000000000, 999999999999999)); ctxWords = ['order_id', 'user_id', 'account']; break; // numeric id
    case 11: value = Buffer.from(pick(WORDS) + ' ' + pick(WORDS)).toString('base64'); break; // base64 of words
    case 12: value = 'v' + randInt(1, 9) + '/' + pick(WORDS) + '/' + pick(WORDS) + '-' + draw(LOWER, 6); ctxWords = ['path', 'url', 'route']; break; // slug/path
    default: value = draw(HEX, 8); break; // hex color-ish
  }
  return wrap(value, ctxWords, p);
}

function buildDataset(nPer) {
  const rows = [];
  for (let i = 0; i < nPer; i++) {
    const pos = genPositive();
    rows.push({ x: extractFeatures(pos.value, pos.context), y: 1, value: pos.value });
    const neg = genNegative();
    rows.push({ x: extractFeatures(neg.value, neg.context), y: 0, value: neg.value });
  }
  return rows;
}

// --- standardisation ------------------------------------------------------
function standardiser(rows) {
  const mean = new Array(FEATURE_COUNT).fill(0);
  const std = new Array(FEATURE_COUNT).fill(0);
  for (const r of rows) for (let j = 0; j < FEATURE_COUNT; j++) mean[j] += r.x[j];
  for (let j = 0; j < FEATURE_COUNT; j++) mean[j] /= rows.length;
  for (const r of rows) for (let j = 0; j < FEATURE_COUNT; j++) std[j] += (r.x[j] - mean[j]) ** 2;
  for (let j = 0; j < FEATURE_COUNT; j++) std[j] = Math.sqrt(std[j] / rows.length) || 1;
  return { mean, std };
}
const applyStd = (x, s) => x.map((v, j) => (v - s.mean[j]) / s.std[j]);

// --- logistic regression (full-batch gradient descent + L2) --------------
const sigmoid = (z) => 1 / (1 + Math.exp(-z));

function train(rows, { epochs = 4000, lr = 0.3, l2 = 1e-4 } = {}) {
  const w = new Array(FEATURE_COUNT).fill(0).map(() => (rand() - 0.5) * 0.01);
  let b = 0;
  const n = rows.length;
  for (let e = 0; e < epochs; e++) {
    const gw = new Array(FEATURE_COUNT).fill(0);
    let gb = 0;
    for (const r of rows) {
      let z = b;
      for (let j = 0; j < FEATURE_COUNT; j++) z += w[j] * r.xs[j];
      const err = sigmoid(z) - r.y;
      for (let j = 0; j < FEATURE_COUNT; j++) gw[j] += err * r.xs[j];
      gb += err;
    }
    for (let j = 0; j < FEATURE_COUNT; j++) w[j] -= lr * (gw[j] / n + l2 * w[j]);
    b -= lr * (gb / n);
  }
  return { w, b };
}

function evaluate(rows, model, thr = 0.5) {
  let tp = 0, fp = 0, tn = 0, fn = 0, loss = 0;
  for (const r of rows) {
    let z = model.b;
    for (let j = 0; j < FEATURE_COUNT; j++) z += model.w[j] * r.xs[j];
    const p = sigmoid(z);
    loss += -(r.y * Math.log(p + 1e-12) + (1 - r.y) * Math.log(1 - p + 1e-12));
    const yhat = p >= thr ? 1 : 0;
    if (yhat === 1 && r.y === 1) tp++;
    else if (yhat === 1 && r.y === 0) fp++;
    else if (yhat === 0 && r.y === 0) tn++;
    else fn++;
  }
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  return {
    n: rows.length, tp, fp, tn, fn,
    accuracy: (tp + tn) / rows.length,
    precision, recall,
    f1: (2 * precision * recall) / (precision + recall || 1),
    logloss: loss / rows.length,
  };
}

// --- run ------------------------------------------------------------------
const trainRows = buildDataset(6000);
const holdoutRows = buildDataset(2000);
const std = standardiser(trainRows);
for (const r of trainRows) r.xs = applyStd(r.x, std);
for (const r of holdoutRows) r.xs = applyStd(r.x, std);

const model = train(trainRows);
const trainMetrics = evaluate(trainRows, model);
const holdoutMetrics = evaluate(holdoutRows, model);

const fmt = (m) => `acc=${(m.accuracy * 100).toFixed(2)}%  precision=${(m.precision * 100).toFixed(2)}%  recall=${(m.recall * 100).toFixed(2)}%  f1=${(m.f1 * 100).toFixed(2)}%  logloss=${m.logloss.toFixed(4)}  (n=${m.n}, fp=${m.fp}, fn=${m.fn})`;
console.log('features :', FEATURE_COUNT, FEATURES.join(', '));
console.log('train    :', fmt(trainMetrics));
console.log('holdout  :', fmt(holdoutMetrics));

// fold standardisation into raw weights so runtime needs no mean/std:
//   z = b + Σ w_j * (x_j - mean_j)/std_j = (b - Σ w_j*mean_j/std_j) + Σ (w_j/std_j) x_j
const rawW = model.w.map((wj, j) => wj / std.std[j]);
const rawB = model.b - model.w.reduce((acc, wj, j) => acc + (wj * std.mean[j]) / std.std[j], 0);

const round = (x) => Number(x.toFixed(6));
const ts = `// Generated by scripts/train-confidence-model.mjs — do not edit by hand.
// Logistic-regression weights for the secret-confidence classifier. Trained
// offline on synthetic labelled data; shipped as fixed numbers so the library
// keeps its zero-dependency, deterministic runtime. Regenerate with:
//   node scripts/train-confidence-model.mjs --write
//
// Holdout: ${fmt(holdoutMetrics)}

export interface ConfidenceModel {
  readonly version: number;
  readonly features: readonly string[];
  readonly weights: readonly number[];
  readonly bias: number;
}

export const CONFIDENCE_MODEL: ConfidenceModel = {
  version: 1,
  features: ${JSON.stringify(FEATURES)},
  weights: ${JSON.stringify(rawW.map(round))},
  bias: ${round(rawB)},
};
`;

if (process.argv.includes('--write')) {
  writeFileSync(OUT, ts);
  console.log('wrote    :', OUT);
} else {
  console.log('\n--- src/confidence-model.ts (preview, pass --write to save) ---\n');
  console.log(ts);
}
