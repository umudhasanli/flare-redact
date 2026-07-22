import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';
import { createApp } from './server.mjs';

const output = new PassThrough();
let logText = '';
output.on('data', (chunk) => { logText += chunk; });

const server = createApp(pino(pinoRedact(), output)).listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const { port } = server.address();

try {
  const response = await fetch(`http://127.0.0.1:${port}/checkout?email=alice@example.com`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer not-a-real-token',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'alice@example.com', card: '4242 4242 4242 4242' }),
  });
  assert.deepEqual(await response.json(), { ok: true });
  await new Promise((resolve) => setImmediate(resolve));
  assert.doesNotMatch(logText, /alice@example\.com/);
  assert.doesNotMatch(logText, /not-a-real-token/);
  assert.match(logText, /a\*\*\*@\*\*\*/);
  console.log('Express + Pino request log contains no original email or bearer token.');
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
