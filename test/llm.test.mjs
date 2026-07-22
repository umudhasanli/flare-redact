import { test } from 'node:test';
import assert from 'node:assert/strict';
import { wrapOpenAI, wrapAnthropic, redactPrompt } from '../dist/llm.js';

const EMAIL = 'alice@corp.com';

test('redactPrompt hides PII and the vault restores it', () => {
  const { text, vault } = redactPrompt(`contact ${EMAIL}`);
  assert.doesNotMatch(text, /alice@corp\.com/);
  assert.equal(vault.restore(text), `contact ${EMAIL}`);
});

test('wrapOpenAI redacts the outgoing prompt and restores the reply', async () => {
  let seenByModel;
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          seenByModel = params.messages[0].content;
          // the "model" references the placeholder it was given in its answer
          const ph = seenByModel.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
          return { choices: [{ message: { role: 'assistant', content: `sure, I'll email ${ph}` } }] };
        },
      },
    },
  };
  wrapOpenAI(client);
  const res = await client.chat.completions.create({
    model: 'gpt-x',
    messages: [{ role: 'user', content: `write to ${EMAIL}` }],
  });
  assert.doesNotMatch(seenByModel, /alice@corp\.com/); // model never saw the real email
  assert.match(seenByModel, /\[FR_EMAIL_[0-9a-f]{24}\]/);
  assert.equal(res.choices[0].message.content, `sure, I'll email ${EMAIL}`); // restored for the app
});

test('wrapOpenAI restores across streamed chunks (placeholder split in two)', async () => {
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          const ph = params.messages[0].content.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
          const pieces = ['mailing ', ph.slice(0, 4), ph.slice(4), ' now'];
          return (async function* () {
            for (const p of pieces) yield { choices: [{ index: 0, delta: { content: p } }] };
          })();
        },
      },
    },
  };
  wrapOpenAI(client);
  const stream = await client.chat.completions.create({
    messages: [{ role: 'user', content: `send to ${EMAIL}` }],
    stream: true,
  });
  let text = '';
  for await (const chunk of stream) text += chunk.choices?.[0]?.delta?.content ?? '';
  assert.equal(text, `mailing ${EMAIL} now`);
});

test('wrapAnthropic redacts messages and system, restores content blocks', async () => {
  let seenSystem, seenMsg;
  const client = {
    messages: {
      create: async (params) => {
        seenSystem = params.system;
        seenMsg = params.messages[0].content;
        const ph = seenMsg.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)[0];
        return { content: [{ type: 'text', text: `noted ${ph}` }] };
      },
    },
  };
  wrapAnthropic(client);
  const res = await client.messages.create({
    model: 'claude-x',
    system: `admin is ${EMAIL}`,
    messages: [{ role: 'user', content: `ping ${EMAIL}` }],
  });
  assert.doesNotMatch(seenSystem, /alice@corp\.com/);
  assert.doesNotMatch(seenMsg, /alice@corp\.com/);
  assert.equal(res.content[0].text, `noted ${EMAIL}`);
});

test('wrapOpenAI throws on a client of the wrong shape', () => {
  assert.throws(() => wrapOpenAI({}), /chat\.completions\.create/);
});
