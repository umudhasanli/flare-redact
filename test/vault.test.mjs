import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, restore, redact, fpe } from '../dist/index.js';

test('vault redact then restore is a round trip', () => {
  const v = createVault();
  const redacted = v.redact('email bob@corp.com and key AKIAIOSFODNN7EXAMPLE');
  assert.match(redacted, /\[EMAIL_1\]/);
  assert.match(redacted, /\[AWS_ACCESS_KEY_1\]/);
  assert.doesNotMatch(redacted, /bob@corp\.com/);
  assert.equal(v.restore(redacted), 'email bob@corp.com and key AKIAIOSFODNN7EXAMPLE');
});

test('vault is referentially consistent — same value, same placeholder', () => {
  const v = createVault();
  const out = v.redact('from bob@x.io to bob@x.io cc alice@x.io');
  const found = out.match(/\[EMAIL_\d+\]/g);
  assert.equal(found[0], found[1]); // both bob@x.io → same token
  assert.notEqual(found[0], found[2]); // alice differs
});

test('vault works on objects and restores structure', () => {
  const v = createVault();
  const red = v.redact({ user: 'bob@x.io', password: 'hunter2', note: 'card 4242 4242 4242 4242' });
  assert.doesNotMatch(JSON.stringify(red), /bob@x\.io|hunter2/);
  const back = v.restore(red);
  assert.equal(back.user, 'bob@x.io');
  assert.equal(back.password, 'hunter2');
  assert.equal(back.note, 'card 4242 4242 4242 4242');
});

test('standalone restore() accepts a vault or a plain map', () => {
  const v = createVault();
  const red = v.redact('token ghp_' + 'a'.repeat(36));
  assert.equal(restore(red, v), 'token ghp_' + 'a'.repeat(36));
  const map = Object.fromEntries(v.entries());
  assert.equal(restore(red, map), 'token ghp_' + 'a'.repeat(36));
});

test('custom placeholder format', () => {
  const v = createVault({ placeholder: (id, n) => `<<${id}:${n}>>` });
  const red = v.redact('bob@x.io');
  assert.equal(red, '<<email:1>>');
  assert.equal(v.restore(red), 'bob@x.io');
});

test('fpe mode preserves shape and is deterministic', () => {
  const a = redact('bob@corp.com', { mode: 'fpe' });
  assert.match(a, /^[a-z]+@[a-z]+\.[a-z]+$/); // still email-shaped
  assert.notEqual(a, 'bob@corp.com');
  assert.equal(a, redact('bob@corp.com', { mode: 'fpe' })); // deterministic
});

test('fpe keeps the digit groups of a card', () => {
  const out = fpe('4242 4242 4242 4242');
  assert.match(out, /^\d{4} \d{4} \d{4} \d{4}$/);
  assert.notEqual(out, '4242 4242 4242 4242');
});
