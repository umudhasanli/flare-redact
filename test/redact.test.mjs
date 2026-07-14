import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean, summary, createRedactor, wrapConsole } from '../dist/index.js';

const gh = 'ghp_' + 'a'.repeat(36);

test('redacts an AWS access key but keeps a hint', () => {
  assert.equal(redact('key=AKIAIOSFODNN7EXAMPLE done'), 'key=AKIA*** done');
});

test('redacts GitHub, GitLab and npm tokens', () => {
  assert.equal(redact(`t ${gh}`), 't ghp_***');
  assert.equal(redact('glpat-' + 'x'.repeat(20)), 'glpat-***');
  assert.equal(redact('npm_' + 'y'.repeat(36)), 'npm_***');
});

test('redacts a JWT and a bearer header', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456';
  assert.equal(redact(jwt), '[REDACTED JWT]');
  assert.equal(redact('Authorization: Bearer ' + jwt), 'Authorization: Bearer ***');
});

test('redacts a private key block whole', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj\n-----END RSA PRIVATE KEY-----';
  assert.equal(redact(pem), '[REDACTED PRIVATE KEY]');
});

test('redacts the password inside a connection string', () => {
  assert.equal(redact('postgres://user:s3cr3t@db.host:5432/app'), 'postgres://user:***@db.host:5432/app');
});

test('masks a Luhn-valid card, ignores an invalid digit run', () => {
  assert.equal(redact('card 4242 4242 4242 4242 end'), 'card **** **** **** 4242 end');
  assert.equal(redact('id 1234 5678 9012 3456'), 'id 1234 5678 9012 3456');
});

test('masks emails as PII', () => {
  assert.equal(redact('reach me at alice@example.com now'), 'reach me at a***@*** now');
});

test('generic assignment catches password=…', () => {
  assert.equal(redact('password=hunter2'), 'password=***');
  assert.equal(redact('api_key: "abcd1234efgh"'), 'api_key: "***"');
});

test('deep-redacts objects and arrays', () => {
  const out = redact({
    user: 'bob@corp.com',
    password: 'hunter2',
    tokens: [gh],
    nested: { note: 'my key is AKIAIOSFODNN7EXAMPLE' },
  });
  assert.equal(out.password, '***');
  assert.equal(out.user, 'b***@***');
  assert.equal(out.tokens[0], 'ghp_***');
  assert.equal(out.nested.note, 'my key is AKIA***');
});

test('scan reports findings with a why, input unchanged', () => {
  const findings = scan('email bob@x.io and password=hunter2');
  const ids = findings.map((f) => f.detector);
  assert.ok(ids.includes('email'));
  assert.ok(ids.includes('generic_assignment'));
  for (const f of findings) assert.ok(f.why.length > 0);
});

test('scan on objects returns json paths', () => {
  const findings = scan({ a: { b: gh }, password: 'x' });
  const paths = findings.map((f) => f.path);
  assert.ok(paths.includes('a.b'));
  assert.ok(paths.includes('password'));
});

test('only/disable/enable toggles', () => {
  assert.equal(redact('bob@x.io', { disable: ['email'] }), 'bob@x.io');
  assert.equal(redact('AKIAIOSFODNN7EXAMPLE bob@x.io', { only: ['email'] }), 'AKIAIOSFODNN7EXAMPLE b***@***');
  assert.equal(redact('10.0.0.1', {}), '10.0.0.1');
  assert.equal(redact('10.0.0.1', { enable: ['ipv4'] }), '***.***.***.***');
});

test('label mode', () => {
  assert.equal(redact('AKIAIOSFODNN7EXAMPLE', { mode: 'label' }), '[REDACTED:aws_access_key]');
  assert.equal(redact({ password: 'x' }, { mode: 'label' }).password, '[REDACTED:sensitive_key]');
});

test('hash mode is deterministic and correlates equal values', () => {
  const a = redact('bob@x.io', { mode: 'hash' });
  const b = redact('bob@x.io', { mode: 'hash' });
  assert.equal(a, b);
  assert.match(a, /^email_[0-9a-f]{8}$/);
  assert.notEqual(a, redact('alice@x.io', { mode: 'hash' }));
  assert.notEqual(a, redact('bob@x.io', { mode: 'hash', hashSalt: 'pepper' }));
});

test('allow list keeps known-safe values', () => {
  assert.equal(redact('support@example.com', { allow: ['support@example.com'] }), 'support@example.com');
  assert.equal(redact('a@b.io c@d.io', { allow: /a@b\.io/ }), 'a@b.io c***@***');
});

test('custom detector', () => {
  const out = redact('ticket ACME-1234 here', {
    custom: [{ id: 'ticket', label: 'Ticket', why: 'internal id', pattern: /\bACME-\d{4,6}\b/g, mask: () => '[TICKET]', default: true }],
  });
  assert.equal(out, 'ticket [TICKET] here');
});

test('high_entropy catches unknown tokens when enabled', () => {
  const token = 'Zx9Qw3Rt7Yp2Lm5Kv8Nb1Hs6Df4Gj0';
  assert.equal(redact(token, {}), token);
  assert.equal(redact(token, { enable: ['high_entropy'] }), 'Zx9Q***');
});

test('isClean and summary', () => {
  assert.equal(isClean('nothing to see here'), true);
  assert.equal(isClean('password=hunter2'), false);
  const s = summary({ password: 'x', note: 'bob@x.io', key: gh });
  assert.equal(s.total, 3);
  assert.equal(s.byDetector.email, 1);
});

test('createRedactor binds options', () => {
  const r = createRedactor({ disable: ['email'] });
  assert.equal(r.redact(`bob@x.io ${gh}`), 'bob@x.io ghp_***');
  assert.equal(r.isClean('bob@x.io'), true);
});

test('adjacent secrets do not corrupt surrounding text', () => {
  assert.equal(redact('a AKIAIOSFODNN7EXAMPLE b bob@x.io c'), 'a AKIA*** b b***@*** c');
});

test('clean text is returned unchanged', () => {
  const s = 'the quick brown fox jumps over the lazy dog';
  assert.equal(redact(s), s);
  assert.deepEqual(scan(s), []);
});

test('wrapConsole redacts every argument then restores', () => {
  const seen = [];
  const fake = { log: (...a) => seen.push(a), info() {}, warn() {}, error() {}, debug() {} };
  const restore = wrapConsole({}, fake);
  fake.log('token', gh, { password: 'hunter2' });
  restore();
  assert.deepEqual(seen[0], ['token', 'ghp_***', { password: '***' }]);
  fake.log('again', gh);
  assert.deepEqual(seen[1], ['again', gh]);
});
