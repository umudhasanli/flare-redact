import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  secretProbability,
  extractFeatures,
  shannonEntropy,
  FEATURES,
  FEATURE_COUNT,
  CONFIDENCE_MODEL,
  scan,
} from '../dist/index.js';
import { secretProbability as secretProbabilitySub } from '../dist/ml.js';

const REAL_SECRETS = [
  ['openai', 'sk-abcDEF1234567890ghIJKL7890mnOPqrST1234uvWXyz5678AB', 'api_key='],
  ['github pat', 'ghp_16CharsABCdef0123456789ABCDEFghijkl', 'token='],
  ['aws secret', 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYabcd', 'aws_secret_access_key='],
  ['generic token', 'Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv', 'authorization: Bearer '],
];

const BENIGN_LOOKALIKES = [
  ['uuid v4', '3f2504e0-4f89-41d3-9a0c-0305e82c3301', 'request_id='],
  ['git sha', '9fceb02d0ae598e95dc970b74767f19372d61af8', 'commit '],
  ['md5', 'd41d8cd98f00b204e9800998ecf8427e', 'etag: '],
  ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'checksum='],
  ['object id', '507f1f77bcf86cd799439011', 'object_id='],
  ['word', 'configurationDeployment', 'variable '],
];

test('feature layout matches the shipped model exactly', () => {
  assert.equal(FEATURE_COUNT, FEATURES.length);
  assert.equal(FEATURE_COUNT, CONFIDENCE_MODEL.weights.length);
  assert.deepEqual([...FEATURES], [...CONFIDENCE_MODEL.features]);
  assert.equal(extractFeatures('abc123', 'token=abc123').length, FEATURE_COUNT);
});

test('secretProbability separates real secrets from benign look-alikes', () => {
  for (const [name, value, ctx] of REAL_SECRETS) {
    const p = secretProbability(value, ctx + value);
    assert.ok(p >= 0.5, `${name} should read as a secret, got ${p.toFixed(3)}`);
  }
  for (const [name, value, ctx] of BENIGN_LOOKALIKES) {
    const p = secretProbability(value, ctx + value);
    assert.ok(p < 0.5, `${name} should read as benign, got ${p.toFixed(3)}`);
  }
});

test('secretProbability is bounded and deterministic', () => {
  const value = 'Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv';
  const a = secretProbability(value, 'token=' + value);
  const b = secretProbability(value, 'token=' + value);
  assert.equal(a, b);
  assert.ok(a >= 0 && a <= 1);
  assert.equal(secretProbability('', ''), secretProbability('', ''));
  assert.ok(secretProbability('', '') >= 0 && secretProbability('', '') <= 1);
});

test('subpath export ./ml matches the top-level export', () => {
  const value = '9fceb02d0ae598e95dc970b74767f19372d61af8';
  assert.equal(secretProbability(value, 'commit ' + value), secretProbabilitySub(value, 'commit ' + value));
});

test('shannonEntropy matches known values', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.equal(shannonEntropy('aaaa'), 0);
  assert.equal(shannonEntropy('ab'), 1);
  assert.equal(shannonEntropy('abcd'), 2);
});

test('nearby secret context raises probability, benign context lowers it', () => {
  const value = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
  const withSecret = secretProbability(value, 'api_key=' + value);
  const withBenign = secretProbability(value, 'md5 digest ' + value);
  assert.ok(withSecret > withBenign);
});

test('refineConfidence drops high-entropy false positives but keeps real secrets', () => {
  const gitSha = '9fceb02d0ae598e95dc970b74767f19372d61af8';               // benign, 40 hex
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // benign, 64 hex
  const token = 'Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv';                     // real-looking secret
  const text = [gitSha, sha256, token].map((v) => `"${v}"`).join(' ');
  const base = { enable: ['high_entropy'] };

  const plain = scan(text, base).map((f) => text.slice(f.start, f.end));
  assert.ok(plain.includes(gitSha) && plain.includes(sha256) && plain.includes(token),
    'plain scan should flag every high-entropy run');

  const refined = scan(text, { ...base, refineConfidence: true, minConfidence: 0.5 });
  const kept = refined.map((f) => text.slice(f.start, f.end));
  assert.ok(kept.includes(token), 'real token must survive refinement');
  assert.ok(!kept.includes(gitSha), 'git sha must be dropped');
  assert.ok(!kept.includes(sha256), 'sha256 digest must be dropped');
});

test('refineConfidence leaves checksum-validated detectors untouched', () => {
  const text = 'card 4242 4242 4242 4242';
  const plain = scan(text);
  const refined = scan(text, { refineConfidence: true });
  const card = (list) => list.find((f) => f.detector === 'credit_card');
  assert.ok(card(plain), 'baseline should detect the card');
  assert.ok(card(refined), 'refinement must not remove a checksum-validated card');
  assert.equal(card(plain).confidence, card(refined).confidence);
});

test('refineConfidence is off by default and does not change scores', () => {
  const value = 'Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv';
  const text = `"${value}"`;
  const off = scan(text, { enable: ['high_entropy'] });
  const explicitOff = scan(text, { enable: ['high_entropy'], refineConfidence: false });
  assert.equal(off[0].confidence, explicitOff[0].confidence);
});
