import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createToolBoundary,
  redactMcpMessage,
  redactToolCall,
  redactToolResult,
} from '../dist/tool.js';

test('one-way tool and MCP helpers redact structured and JSON-string payloads', () => {
  const call = {
    name: 'send_email',
    arguments: JSON.stringify({ email: 'alice@corp.com', password: 'hunter2' }),
  };
  const result = { content: [{ type: 'text', text: 'owner bob@corp.com' }] };
  assert.doesNotMatch(redactToolCall(call).arguments, /alice|hunter2/);
  assert.doesNotMatch(JSON.stringify(redactToolResult(result)), /bob@corp/);
  assert.equal(redactMcpMessage({ params: { token: 'secret' } }).params.token, '***');
});

test('tool boundary restores model calls and redacts results with one vault', () => {
  const boundary = createToolBoundary({ placeholderStyle: 'readable' });
  const prompt = boundary.redactForModel({ text: 'email alice@corp.com' });
  const placeholder = prompt.text.match(/\[EMAIL_1\]/)[0];
  const call = boundary.restoreForTool({ name: 'send', arguments: `{"to":"${placeholder}"}` });
  assert.equal(JSON.parse(call.arguments).to, 'alice@corp.com');
  const result = boundary.redactForModel({ owner: 'bob@corp.com' });
  assert.doesNotMatch(result.owner, /bob@corp/);
  assert.equal(boundary.size, 2);
});
