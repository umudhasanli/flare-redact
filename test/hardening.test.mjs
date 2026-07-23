import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, restore } from '../dist/index.js';
import { wrapOpenAI, wrapAnthropic } from '../dist/llm.js';

test('opaque placeholders are unique and restore without collisions', () => {
  const v = createVault();
  const emails = Array.from({ length: 12 }, (_, i) => `user${i}@corp.com`);
  const redacted = v.redact(emails.join(' '));
  const placeholders = redacted.match(/\[FR_EMAIL_[0-9a-f]{24}\]/g);
  assert.equal(placeholders.length, 12);
  assert.equal(new Set(placeholders).size, 12);
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
  assert.match(sent[1].content, /\[FR_EMAIL_[0-9a-f]{24}\]/);
});

test('wrapOpenAI redacts secrets inside tool-call arguments in message history', async () => {
  let sent;
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          sent = params.messages;
          return { choices: [{ message: { role: 'assistant', content: 'ok' } }] };
        },
      },
    },
  };
  wrapOpenAI(client, { placeholderStyle: 'readable' });
  await client.chat.completions.create({
    messages: [{
      role: 'assistant',
      content: null,
      tool_calls: [{
        id: 'call_1',
        type: 'function',
        function: {
          name: 'send_email',
          arguments: '{"email":"alice@corp.com","password":"hunter2"}',
        },
      }],
    }],
  });
  const args = sent[0].tool_calls[0].function.arguments;
  assert.doesNotMatch(args, /alice@corp|hunter2/);
  assert.match(args, /\[EMAIL_1\]|\[GENERIC_ASSIGNMENT_1\]/);
});

test('wrapOpenAI restores placeholders split across streamed tool arguments', async () => {
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          const placeholder = params.messages[0].content.match(/<email:1>/)[0];
          const json = `{"to":"${placeholder}"}`;
          return (async function* () {
            yield {
              choices: [{
                index: 0,
                delta: { tool_calls: [{ index: 0, function: { arguments: json.slice(0, 10) } }] },
              }],
            };
            yield {
              choices: [{
                index: 0,
                delta: { tool_calls: [{ index: 0, function: { arguments: json.slice(10) } }] },
              }],
            };
          })();
        },
      },
    },
  };
  wrapOpenAI(client, { placeholder: (id, index) => `<${id}:${index}>` });
  const stream = await client.chat.completions.create({
    messages: [{ role: 'user', content: 'to alice@corp.com' }],
    stream: true,
  });
  let args = '';
  for await (const chunk of stream) {
    args += chunk.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments ?? '';
  }
  assert.equal(args, '{"to":"alice@corp.com"}');
});

test('wrapOpenAI streaming restores a placeholder split at every boundary', async () => {
  const expected = 'ok alice@corp.com done';
  for (let cut = 1; cut < 38; cut++) {
    const client = {
      chat: {
        completions: {
          create: async (params) => {
            const ph = params.messages[0].content.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
            const reply = `ok ${ph} done`;
            const pieces = [reply.slice(0, cut), reply.slice(cut)];
            return (async function* () {
              for (const p of pieces) yield { choices: [{ index: 0, delta: { content: p } }] };
            })();
          },
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
  assert.match(sentSystem[0].text, /\[FR_EMAIL_[0-9a-f]{24}\]/);
});

test('vault restore round-trips a deeply nested object', () => {
  const v = createVault();
  const red = v.redact({ a: [{ b: { c: 'reach bob@x.io now' } }], d: ['ghp_' + 'a'.repeat(36)] });
  assert.doesNotMatch(JSON.stringify(red), /bob@x\.io|ghp_a/);
  assert.deepEqual(v.restore(red), { a: [{ b: { c: 'reach bob@x.io now' } }], d: ['ghp_' + 'a'.repeat(36)] });
});
