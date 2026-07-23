import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSession } from '../dist/index.js';

test('a session masks in and restores out', () => {
  const s = createSession();
  const safe = s.redact('email me at alice@corp.com');
  const placeholder = safe.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
  assert.equal(s.restore(`replying to ${placeholder}`), 'replying to alice@corp.com');
});

test('placeholders are consistent across turns', () => {
  const s = createSession();
  const t1 = s.redact('I am alice@corp.com');
  const t2 = s.redact('remind alice@corp.com and bob@corp.com');
  const a1 = t1.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
  const both = t2.match(/\[FR_EMAIL_[0-9a-f]{24}\]/g);
  assert.equal(both[0], a1); // same alice → same placeholder as turn 1
  assert.notEqual(both[1], a1); // bob is different
});

test('redactMessages masks a chat array', () => {
  const s = createSession();
  const out = s.redactMessages([
    { role: 'system', content: 'be helpful' },
    { role: 'user', content: 'ship to alice@corp.com' },
  ]);
  assert.equal(out[0].content, 'be helpful');
  assert.match(out[1].content, /\[FR_EMAIL_[0-9a-f]{24}\]/);
});

test('streaming restore survives a placeholder split across chunks', () => {
  const s = createSession();
  const safe = s.redact('to alice@corp.com');
  const placeholder = safe.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
  const r = s.stream();
  let out = '';
  const cut = Math.floor(placeholder.length / 2);
  for (const chunk of ['sent to ' + placeholder.slice(0, cut), placeholder.slice(cut), ' now']) out += r.push(chunk);
  out += r.flush();
  assert.equal(out, 'sent to alice@corp.com now');
});

test('streaming restore supports custom placeholder formats without brackets', () => {
  const s = createSession({ placeholder: (id, index) => `<${id}:${index}>` });
  const safe = s.redact('alice@corp.com');
  const r = s.stream();
  const split = safe.indexOf(':') + 1;
  assert.equal(r.push(safe.slice(0, split)) + r.push(safe.slice(split)) + r.flush(), 'alice@corp.com');
});

test('reset starts a clean conversation', () => {
  const s = createSession();
  s.redact('alice@corp.com');
  assert.equal(s.size, 1);
  s.reset();
  assert.equal(s.size, 0);
});
