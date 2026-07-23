import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor, definePolicy } from '../dist/index.js';
import { pinoRedact } from '../dist/pino.js';
import { winstonRedact } from '../dist/winston.js';
import { redactHttp, redactUrl, httpRedactor } from '../dist/http.js';

const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456';

test('pinoRedact returns a formatters.log that masks the log object', () => {
  const { formatters } = pinoRedact();
  const out = formatters.log({ user: 'bob@corp.com', msg: 'paid 4242 4242 4242 4242' });
  assert.equal(out.user, 'b***@***');
  assert.match(out.msg, /\*\*\*\* 4242$/);
});

test('winstonRedact mutates in place and preserves symbol keys', () => {
  const transform = winstonRedact();
  const LEVEL = Symbol.for('level');
  const info = { level: 'info', message: 'login bob@corp.com', [LEVEL]: 'info' };
  const out = transform(info);
  assert.equal(out, info); // same object identity
  assert.equal(out[LEVEL], 'info'); // symbol metadata intact
  assert.match(out.message, /b\*\*\*@\*\*\*/);
});

test('redactHttp masks auth headers, body, and query but keeps ordinary fields', () => {
  const safe = redactHttp({
    method: 'POST',
    originalUrl: '/checkout',
    headers: { authorization: `Bearer ${jwt}`, 'content-type': 'application/json' },
    query: { ref: 'ok', email: 'bob@corp.com' },
    body: { card: '4242 4242 4242 4242', note: 'ship fast' },
  });
  assert.equal(safe.method, 'POST');
  assert.equal(safe.url, '/checkout');
  assert.equal(safe.headers['content-type'], 'application/json');
  assert.equal(safe.headers.authorization, '***'); // sensitive key name → fully masked
  assert.equal(safe.query.email, 'b***@***');
  assert.match(safe.body.card, /\*\*\*\* 4242$/);
  assert.equal(safe.body.note, 'ship fast');
});

test('httpRedactor attaches a non-enumerable redacted() snapshot', () => {
  const mw = httpRedactor();
  const req = { method: 'GET', headers: { cookie: 'session=secret' }, body: { email: 'a@b.io' } };
  let called = false;
  mw(req, {}, () => { called = true; });
  assert.equal(called, true);
  assert.ok(!Object.keys(req).includes('redacted')); // non-enumerable, won't get logged itself
  const snap = req.redacted();
  assert.equal(snap.body.email, 'a***@***');
});

test('redactHttp removes secrets from the URL string as well as parsed query', () => {
  const safe = redactHttp({
    method: 'GET',
    originalUrl: '/callback?token=ghp_' + 'a'.repeat(36) + '&email=bob%40corp.com#owner=alice@corp.com',
    query: { token: 'ghp_' + 'a'.repeat(36), email: 'bob@corp.com' },
  });
  assert.doesNotMatch(safe.url, /ghp_|bob|alice/);
  assert.match(safe.url, /token=\*\*\*/);
});

test('redactUrl preserves absolute and relative URL shapes', () => {
  assert.match(redactUrl('https://user:secret@example.com/a@b.io?password=hunter2'), /^https:/);
  assert.doesNotMatch(redactUrl('https://user:secret@example.com/a@b.io?password=hunter2'), /user|secret|a%40b\.io|hunter2/);
  assert.equal(redactUrl('?email=bob%40corp.com'), '?email=b***%40***');
  assert.equal(redactUrl('?bob%40corp.com=value'), '?b***%40***=value');
});

test('one policy, used across surfaces', () => {
  const policy = definePolicy({ disable: ['email'] });
  assert.equal(policy.redact('bob@x.io AKIAIOSFODNN7EXAMPLE'), 'bob@x.io AKIA***');
  // same options flow into an adapter
  const { formatters } = pinoRedact(policy.options);
  assert.equal(formatters.log({ a: 'bob@x.io', b: 'AKIAIOSFODNN7EXAMPLE' }).b, 'AKIA***');
  assert.equal(formatters.log({ a: 'bob@x.io' }).a, 'bob@x.io'); // email disabled everywhere
});

test('createRedactor exposes a vault bound to the policy', () => {
  const r = createRedactor();
  const v = r.vault();
  const red = v.redact('to bob@x.io');
  assert.match(red, /\[FR_EMAIL_[0-9a-f]{24}\]/);
  assert.equal(v.restore(red), 'to bob@x.io');
});
