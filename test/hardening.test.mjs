import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, restore } from '../dist/index.js';
import { wrapOpenAI, wrapAnthropic } from '../dist/llm.js';

test('restore is collision-safe: [EMAIL_1] is not clobbered by [EMAIL_10]', () => {
  const v = createVault();
  const emails = Array.from({ length: 12 }, (_, i) => `user${i}@corp.com`);
  const redacted = v.redact(emails.join(' '));
  assert.match(redacted, /\[EMAIL_10\]/);
  assert.match(redacted, /\[EMAIL_1\]/);
  assert.equal(v.restore(redacted), emails.join(' '));
});

test('standalone restore with a plain map is collision-safe', () => {
  const map = { '[T_1]': 'one', '[T_10]': 'ten', '[T_100]': 'hundred' };
  assert.equal(restore('[T_100] [T_10] [T_1]', map), 'hundred ten one');
});

test('wrapOpenAI is idempotent — wrapping twice does not double-wrap', () => {
  const client = { chat: { completions: { create: async () => ({ choices: [] }) } } };
  wrapOpenAI(client);
  const once = client.chat.completions.create;
  wrapOpenAI(client);
  assert.equal(client.chat.completions.create, once);
});

test('wrapOpenAI leaves null content and tool calls untouched', async () => {
  let sent;
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          sent = params.messages;
          return { choices: [{ message: { role: 'assistant', content: null } }] };
        },
      },
    },
  };
  wrapOpenAI(client);
  await client.chat.completions.create({
    messages: [
      { role: 'assistant', content: null, tool_calls: [{ id: 'x' }] },
      { role: 'user', content: 'email bob@x.io' },
    ],
  });
  assert.equal(sent[0].content, null);
  assert.deepEqual(sent[0].tool_calls, [{ id: 'x' }]);
  assert.match(sent[1].content, /\[EMAIL_1\]/);
});

test('wrapOpenAI streaming restores a placeholder split at every boundary', async () => {
  const reply = 'ok [EMAIL_1] done';
  const expected = 'ok alice@corp.com done';
  for (let cut = 1; cut < reply.length; cut++) {
    const pieces = [reply.slice(0, cut), reply.slice(cut)];
    const client = {
      chat: {
        completions: {
          create: async () =>
            (async function* () {
              for (const p of pieces) yield { choices: [{ index: 0, delta: { content: p } }] };
            })(),
        },
      },
    };
    wrapOpenAI(client);
    const stream = await client.chat.completions.create({
      messages: [{ role: 'user', content: 'to alice@corp.com' }],
      stream: true,
    });
    let text = '';
    for await (const chunk of stream) text += chunk.choices?.[0]?.delta?.content ?? '';
    assert.equal(text, expected, `split at ${cut}`);
  }
});

test('wrapAnthropic redacts a system prompt given as text blocks', async () => {
  let sentSystem;
  const client = {
    messages: {
      create: async (params) => {
        sentSystem = params.system;
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    },
  };
  wrapAnthropic(client);
  await client.messages.create({
    system: [{ type: 'text', text: 'the admin email is root@corp.com' }],
    messages: [{ role: 'user', content: 'hi' }],
  });
  assert.doesNotMatch(sentSystem[0].text, /root@corp\.com/);
  assert.match(sentSystem[0].text, /\[EMAIL_1\]/);
});

test('vault restore round-trips a deeply nested object', () => {
  const v = createVault();
  const red = v.redact({ a: [{ b: { c: 'reach bob@x.io now' } }], d: ['ghp_' + 'a'.repeat(36)] });
  assert.doesNotMatch(JSON.stringify(red), /bob@x\.io|ghp_a/);
  assert.deepEqual(v.restore(red), { a: [{ b: { c: 'reach bob@x.io now' } }], d: ['ghp_' + 'a'.repeat(36)] });
});
