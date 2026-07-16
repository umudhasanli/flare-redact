import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, createVault, createSession } from '../dist/index.js';

test('a list of terms is masked one-way', () => {
  assert.equal(redact('deploy Falcon and Bluebird', { terms: ['Falcon', 'Bluebird'] }), 'deploy *** and ***');
});

test('terms can carry their own replacement text', () => {
  const out = redact('Launch Project Zeus now', { terms: { 'Project Zeus': '[CLASSIFIED]' } });
  assert.equal(out, 'Launch [CLASSIFIED] now');
});

test('longest term wins and word boundaries are respected', () => {
  // "Project Zeus" should match as a whole, not just "Zeus"
  const out = redact('Project Zeus vs Zeus', { terms: ['Zeus', 'Project Zeus'] });
  assert.equal(out, '*** vs ***');
  // does not match inside another word
  assert.equal(redact('Zeuses ran', { terms: ['Zeus'] }), 'Zeuses ran');
});

test('terms are case-insensitive by default, case-sensitive on request', () => {
  assert.equal(redact('FALCON falcon', { terms: ['falcon'] }), '*** ***');
  assert.equal(redact('FALCON falcon', { terms: ['falcon'], termsCaseSensitive: true }), 'FALCON ***');
});

test('terms work in any language (unicode boundaries)', () => {
  assert.equal(redact('层 密项目 结束', { terms: ['密项目'] }), '层 *** 结束');
});

test('terms are reversible in a vault', () => {
  const v = createVault({ terms: ['Project Zeus'] });
  const masked = v.redact('ship Project Zeus');
  assert.match(masked, /\[CUSTOM_TERM_1\]/);
  assert.equal(v.restore(masked), 'ship Project Zeus');
});

test('terms round-trip through a chat session with detectors', () => {
  const s = createSession({ terms: ['Falcon'] });
  const masked = s.redact('email alice@corp.com about Falcon');
  assert.doesNotMatch(masked, /alice@corp\.com|Falcon/);
  assert.equal(s.restore(masked), 'email alice@corp.com about Falcon');
});
