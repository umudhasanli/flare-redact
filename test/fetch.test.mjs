import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wrapFetch } from '../dist/fetch.js';

function capture() {
  const calls = [];
  const fetchImpl = async (input, init) => {
    calls.push({ input, init });
    return { ok: true };
  };
  return { fetchImpl, calls };
}

test('redacts the body for a configured host only', async () => {
  const { fetchImpl, calls } = capture();
  const fetch = wrapFetch(fetchImpl, { hosts: ['api.segment.io'] });
  await fetch('https://api.segment.io/track', { method: 'POST', body: JSON.stringify({ email: 'bob@x.io' }) });
  assert.equal(calls[0].init.body, JSON.stringify({ email: 'b***@***' }));
});

test('leaves other hosts untouched', async () => {
  const { fetchImpl, calls } = capture();
  const fetch = wrapFetch(fetchImpl, { hosts: ['api.segment.io'] });
  const body = JSON.stringify({ email: 'bob@x.io' });
  await fetch('https://api.myapp.com/checkout', { method: 'POST', body });
  assert.equal(calls[0].init.body, body); // real API call: PII intact
});

test('matches parent domains', async () => {
  const { fetchImpl, calls } = capture();
  const fetch = wrapFetch(fetchImpl, { hosts: ['segment.io'] });
  await fetch('https://cdn.segment.io/v1', { method: 'POST', body: JSON.stringify({ card: '4242 4242 4242 4242' }) });
  assert.match(calls[0].init.body, /\*\*\*\* 4242/);
});

test('redacts a non-JSON text body too', async () => {
  const { fetchImpl, calls } = capture();
  const fetch = wrapFetch(fetchImpl, { hosts: ['logs.example.com'] });
  await fetch('https://logs.example.com', { method: 'POST', body: 'user bob@x.io logged in' });
  assert.equal(calls[0].init.body, 'user b***@*** logged in');
});

test('with no hosts configured, nothing is redacted', async () => {
  const { fetchImpl, calls } = capture();
  const fetch = wrapFetch(fetchImpl);
  const body = JSON.stringify({ email: 'bob@x.io' });
  await fetch('https://anywhere.com', { method: 'POST', body });
  assert.equal(calls[0].init.body, body);
});
