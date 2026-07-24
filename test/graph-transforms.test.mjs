import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../dist/index.js';
import { pseudonymize, surrogate } from '../dist/transforms.js';
import { mapGraph } from '../dist/graph.js';
import { luhnCheck } from '../dist/checksums.js';

const SECRET = 'unit-test-secret';

test('pseudonymize preserves shape and is keyed', () => {
  const out = pseudonymize('Ab3-Cd9_x', SECRET);
  assert.equal(out.length, 9);
  assert.match(out, /^[A-Z][a-z]\d-[A-Z][a-z]\d_[a-z]$/);
  assert.equal(out[3], '-');
  assert.equal(out[7], '_');
  assert.equal(pseudonymize('Ab3-Cd9_x', SECRET), out);
  assert.notEqual(pseudonymize('Ab3-Cd9_x', 'other-secret'), out);
  assert.notEqual(pseudonymize('Ab3-Cd9_y', SECRET), out);
});

test('card surrogate keeps separators and stays Luhn-valid', () => {
  const card = '4242 4242 4242 4242';
  const out = surrogate(card, { id: 'credit_card' }, SECRET);
  assert.match(out, /^\d{4} \d{4} \d{4} \d{4}$/);
  assert.notEqual(out, card);
  assert.ok(luhnCheck(out), `surrogate ${out} must pass Luhn`);
  assert.equal(surrogate(card, { id: 'credit_card' }, SECRET), out);
});

test('email and person surrogates produce safe deterministic stand-ins', () => {
  const email = surrogate('alice@corp.com', { id: 'email' }, SECRET);
  assert.match(email, /^user_[0-9a-f]{12}@example\.invalid$/);
  const person = surrogate('Alice Smith', { id: 'person_name' }, SECRET);
  assert.match(person, /^[A-Z][a-z]+ [A-Z][a-z]+$/);
  assert.equal(surrogate('Alice Smith', { id: 'person_name' }, SECRET), person);
});

test('mapGraph rewrites URL and URLSearchParams instances', () => {
  const url = new URL('https://user:hunter2@db.example.com/path?token=abc');
  const params = new URLSearchParams('a=1&b=two');
  const mapped = mapGraph({ url, params }, (s) => s.replaceAll('hunter2', '***'));
  assert.ok(mapped.url instanceof URL);
  assert.equal(mapped.url.password, '***');
  assert.ok(mapped.params instanceof URLSearchParams);
  assert.equal(mapped.params.get('b'), 'two');
  assert.equal(url.password, 'hunter2');
});

test('mapGraph preserves Error prototype, redacts message and stack, keeps custom props', () => {
  class AppError extends Error {}
  const err = new AppError('token ghp_secret in message');
  err.requestId = 'req-1';
  const mapped = mapGraph(err, (s) => s.replaceAll('ghp_secret', '***'));
  assert.ok(mapped instanceof AppError);
  assert.equal(mapped.message, 'token *** in message');
  if (typeof err.stack === 'string') assert.equal(mapped.stack.includes('ghp_secret'), false);
  assert.equal(mapped.requestId, 'req-1');
  assert.equal(err.message, 'token ghp_secret in message');
});

test('mapGraph keeps shared references shared and sparse arrays sparse', () => {
  const shared = { note: 'shared' };
  const sparse = new Array(3);
  sparse[1] = 'x';
  const input = { a: shared, b: shared, sparse };
  const mapped = mapGraph(input, (s) => s.toUpperCase());
  assert.equal(mapped.a, mapped.b);
  assert.equal(Object.prototype.hasOwnProperty.call(mapped.sparse, 0), false);
  assert.equal(mapped.sparse[1], 'X');
  assert.equal(mapped.sparse.length, 3);
});

test('mapGraph passes atomic objects through untouched', () => {
  const date = new Date(1700000000000);
  const re = /secret/g;
  const buf = new Uint8Array([1, 2, 3]);
  const mapped = mapGraph({ date, re, buf }, (s) => '***');
  assert.equal(mapped.date, date);
  assert.equal(mapped.re, re);
  assert.equal(mapped.buf, buf);
});

test('redact traverses symbol keys and Map/Set entries end to end', () => {
  const sym = Symbol('meta');
  const input = {
    [sym]: 'email bob@x.io',
    m: new Map([['contact', 'bob@x.io']]),
    s: new Set(['bob@x.io', 'safe']),
  };
  const out = redact(input, { only: ['email'] });
  assert.equal(out[sym].includes('bob@x.io'), false);
  assert.equal(out.m.get('contact').includes('bob@x.io'), false);
  assert.equal([...out.s].some((v) => v.includes('bob@x.io')), false);
  assert.ok(out.s.has('safe'));
});
