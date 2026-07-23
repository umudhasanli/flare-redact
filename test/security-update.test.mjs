import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  createVault,
  hmacFingerprint,
  isClean,
  luhn,
  openVault,
  redact,
  redactAsync,
  scan,
  scanAsync,
  sealVault,
  RedactionLimitError,
} from '../dist/index.js';

test('HMAC fingerprints match the platform implementation', () => {
  const expected = createHmac('sha256', 'test-secret').update('alice@corp.com').digest('hex').slice(0, 32);
  assert.equal(hmacFingerprint('test-secret', 'alice@corp.com'), expected);
});

test('surrogate mode emits deterministic type-consistent values', () => {
  const opts = { mode: 'surrogate', transformSecret: 'test-secret' };
  const first = redact('alice@corp.com 4242 4242 4242 4242', opts);
  const second = redact('alice@corp.com 4242 4242 4242 4242', opts);
  assert.equal(first, second);
  assert.match(first, /^user_[0-9a-f]{12}@example\.invalid /);
  const card = first.match(/\d(?:[ -]?\d){12,18}/)[0];
  assert.equal(luhn(card), true);
});

test('encrypted vault authenticates entries and rejects tampering', async () => {
  const vault = createVault();
  const safe = vault.redact('email alice@corp.com');
  const sealed = await sealVault(vault, 'correct horse battery staple', { iterations: 100_000 });
  const entries = await openVault(sealed, 'correct horse battery staple');
  assert.equal(new Map(entries).size, 1);
  assert.equal((await import('../dist/index.js')).restore(safe, new Map(entries)), 'email alice@corp.com');
  await assert.rejects(openVault(sealed, 'wrong password but long'), /wrong password or corrupted/);
  const tampered = { ...sealed, ciphertext: sealed.ciphertext.slice(0, -4) + 'AAAA' };
  await assert.rejects(openVault(tampered, 'correct horse battery staple'), /wrong password or corrupted/);
});

test('contextual detectors return only the sensitive capture', () => {
  const text = 'Customer name: Alice Example; address: 120 Cedar Street; DOB: 1990-04-23';
  const findings = scan(text, { enable: ['contextual'], includeValues: true });
  assert.deepEqual(findings.map((finding) => finding.detector), ['person_name', 'street_address', 'date_of_birth']);
  assert.deepEqual(findings.map((finding) => finding.value), ['Alice Example', '120 Cedar Street', '1990-04-23']);
  assert.ok(findings.every((finding) => finding.risk === 'high' && finding.confidence >= 0.85));
  const safe = redact(text, { enable: ['contextual'] });
  assert.equal(safe, 'Customer name: [REDACTED PERSON]; address: [REDACTED ADDRESS]; DOB: [REDACTED DOB]');
});

test('a local semantic provider participates in scanning and redaction', () => {
  const provider = {
    detect(text) {
      const value = 'Alice Example';
      const start = text.indexOf(value);
      return [{ detector: 'person_model', label: 'Person', why: 'Local model result.', start, end: start + value.length, confidence: 0.94, risk: 'high' }];
    },
  };
  const text = 'Reviewed by Alice Example today.';
  assert.equal(isClean(text, { semanticProvider: provider }), false);
  assert.equal(redact(text, { semanticProvider: provider }), 'Reviewed by *** today.');
});

test('async local semantic providers work without blocking the synchronous API contract', async () => {
  const semanticProvider = {
    async detect(text) {
      const value = 'Async Person';
      const start = text.indexOf(value);
      return [{ detector: 'person_model', label: 'Person', why: 'Async local model.', start, end: start + value.length, confidence: 0.95, risk: 'high' }];
    },
  };
  const text = 'Reviewed by Async Person.';
  assert.throws(() => scan(text, { semanticProvider }), /use scanAsync/);
  assert.equal((await scanAsync(text, { semanticProvider }))[0].detector, 'person_model');
  assert.equal(await redactAsync(text, { semanticProvider }), 'Reviewed by ***.');
});

test('resource limits fail closed', () => {
  assert.throws(
    () => scan('alice@corp.com', { limits: { maxInputLength: 5 } }),
    (error) => {
      assert.equal(error instanceof RedactionLimitError, true);
      assert.equal(error.code, 'ERR_REDACTION_LIMIT');
      return true;
    },
  );
  assert.throws(
    () => scan('a@x.io b@x.io', { limits: { maxFindings: 1 } }),
    RedactionLimitError,
  );
});

test('obfuscation normalization preserves exact original spans', () => {
  const token = 'ghp_' + 'a'.repeat(18) + '\u200b' + 'a'.repeat(18);
  const [tokenFinding] = scan(token, { includeValues: true });
  assert.equal(tokenFinding.detector, 'github_token');
  assert.equal(tokenFinding.start, 0);
  assert.equal(tokenFinding.end, token.length);
  assert.equal(tokenFinding.value, token);

  assert.equal(redact('alice [at] example [dot] com'), 'a*** [at] *** [dot] ***');
  assert.equal(redact('AKIA IOSF ODNN 7EXA MPLE'), 'AKIA***');
});

test('risk-aware overlap resolution prefers the higher-risk detector', () => {
  const common = { label: 'Overlap', why: 'Test overlap.', pattern: /ACME-123/g, default: true };
  const [finding] = scan('ACME-123', {
    custom: [
      { ...common, id: 'low_overlap', risk: 'low', confidence: 1 },
      { ...common, id: 'critical_overlap', risk: 'critical', confidence: 0.8 },
    ],
    only: ['low_overlap', 'critical_overlap'],
  });
  assert.equal(finding.detector, 'critical_overlap');
  assert.equal(finding.risk, 'critical');
});

test('custom placeholder collisions are rejected', () => {
  const vault = createVault({ placeholder: () => '[SAME]' });
  vault.redact('alice@corp.com');
  assert.throws(() => vault.redact('bob@corp.com'), /duplicate token/);
});
