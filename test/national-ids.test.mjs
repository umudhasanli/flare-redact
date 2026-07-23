import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean } from '../dist/index.js';
import {
  frNirValid,
  aadhaarValid,
  tfnValid,
  cnResidentIdValid,
  jpMyNumberValid,
} from '../dist/checksums.js';

// Every sample is either the well-known documentation example for the format
// or was generated with an independent implementation of the checksum.

test('fr_nir validates the INSEE key, including Corsican departments', () => {
  assert.ok(frNirValid('2690549588157 80'.replace(' ', '')));
  assert.ok(frNirValid('1 55 08 2A 168 025 50'));
  assert.ok(!frNirValid('269054958815781'));
  const text = 'assuré 2 69 05 49 588 157 80 dossier';
  assert.equal(scan(text, { enable: ['fr'] })[0]?.detector, 'fr_nir');
  assert.equal(redact(text, { enable: ['fr'] }).includes('588'), false);
  assert.ok(isClean(text));
});

test('in_aadhaar validates the Verhoeff checksum', () => {
  assert.ok(aadhaarValid('234123412346'));
  assert.ok(aadhaarValid('987654321096'));
  assert.ok(!aadhaarValid('234123412347'));
  assert.ok(!aadhaarValid('123412341234'));
  assert.equal(scan('uid 2341 2341 2346 ok', { enable: ['in'] })[0]?.detector, 'in_aadhaar');
  assert.ok(isClean('uid 2341 2341 2346 ok'));
});

test('au_tfn validates the weighted mod-11 checksum', () => {
  assert.ok(tfnValid('123456782'));
  assert.ok(!tfnValid('123456783'));
  assert.ok(!tfnValid('999999999'));
  assert.equal(scan('tfn 123 456 782', { enable: ['au'] })[0]?.detector, 'au_tfn');
});

test('cn_resident_id validates the ISO 7064 check character and birth date', () => {
  assert.ok(cnResidentIdValid('11010519491231002X'));
  assert.ok(cnResidentIdValid('11010519491231002x'));
  assert.ok(!cnResidentIdValid('110105194912310021'));
  assert.ok(!cnResidentIdValid('11010519491331002X'));
  assert.equal(scan('id 11010519491231002X', { enable: ['cn'] })[0]?.detector, 'cn_resident_id');
});

test('jp_my_number validates the weighted mod-11 check digit', () => {
  assert.ok(jpMyNumberValid('123456789018'));
  assert.ok(jpMyNumberValid('867530901231'));
  assert.ok(!jpMyNumberValid('123456789019'));
  assert.equal(scan('番号 1234 5678 9018', { enable: ['jp'] })[0]?.detector, 'jp_my_number');
});

test('new national IDs stay opt-in and are groupable by the pii tag', () => {
  const text = 'nir 2690549588157 80 aadhaar 234123412346 tfn 123456782';
  assert.ok(isClean(text));
  const detectors = scan(text.replace(' 80', '80'), { enable: ['pii'] }).map((f) => f.detector);
  assert.ok(detectors.includes('in_aadhaar'));
});
