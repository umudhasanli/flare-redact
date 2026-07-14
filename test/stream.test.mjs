import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactStream } from '../dist/stream.js';

function run(input) {
  return new Promise((resolve) => {
    const s = redactStream();
    const chunks = [];
    s.on('data', (c) => chunks.push(c.toString()));
    s.on('end', () => resolve(chunks.join('')));
    for (const line of input) s.write(line);
    s.end();
  });
}

test('redactStream masks secrets line by line', async () => {
  const out = await run(['user bob@x.io\n', 'token ghp_' + 'a'.repeat(36) + '\n']);
  assert.match(out, /user b\*\*\*@\*\*\*/);
  assert.match(out, /token ghp_\*\*\*/);
});

test('redactStream handles a secret split across chunks', async () => {
  const gh = 'ghp_' + 'a'.repeat(36);
  const out = await run(['token ' + gh.slice(0, 10), gh.slice(10) + '\n']);
  assert.match(out, /token ghp_\*\*\*/);
});
