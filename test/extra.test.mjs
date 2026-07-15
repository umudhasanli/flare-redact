import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../dist/index.js';

test('third-party service secrets are caught by default', () => {
  // synthetic (repeated chars) so they match the pattern without being real tokens
  const discord = 'N' + 'a'.repeat(23) + '.bbbbbb.' + 'c'.repeat(30);
  assert.match(redact(discord), /DISCORD TOKEN/);
  const telegram = '110201543:' + 'A'.repeat(35);
  assert.match(redact('token ' + telegram), /TELEGRAM TOKEN/);
  assert.equal(redact('shpat_' + 'a'.repeat(32)), 'shpat_***');
  assert.equal(redact('dop_v1_' + 'b'.repeat(64)), 'dop_v1_***');
});

test('crypto is opt-in and structural', () => {
  const eth = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
  assert.equal(redact(eth), eth); // off by default
  assert.equal(redact(eth, { enable: ['crypto'] }), '0x742d***');
});

test('a BIP39 seed phrase is masked, ordinary prose is not', () => {
  const seed = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  assert.equal(redact(seed, { enable: ['crypto'] }), '[REDACTED SEED PHRASE]');
  const prose = 'the quick brown fox jumps over the lazy dog and then runs away home';
  assert.equal(redact(prose, { enable: ['crypto'] }), prose);
});

test('checksum-validated IDs mask real numbers and ignore fakes', () => {
  assert.equal(redact('nhs 943 476 5919', { enable: ['gb'] }), 'nhs [REDACTED ID]');
  assert.equal(redact('nhs 943 476 5918', { enable: ['gb'] }), 'nhs 943 476 5918'); // bad checksum
  assert.equal(redact('vin 1HGCM82633A004352', { enable: ['vehicle'] }), 'vin [REDACTED VIN]');
  assert.equal(redact('routing 021000021', { enable: ['finance'] }), 'routing [REDACTED ROUTING]');
  assert.equal(redact('routing 021000022', { enable: ['finance'] }), 'routing 021000022'); // bad checksum
});

test('network data is opt-in', () => {
  const coords = '37.7749,-122.4194';
  assert.equal(redact(coords), coords);
  assert.equal(redact(coords, { enable: ['network'] }), '[REDACTED COORDS]');
  assert.match(redact('http://192.168.1.5:8080/admin', { enable: ['network'] }), /INTERNAL URL/);
});
