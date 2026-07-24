import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean } from '../dist/index.js';

const opts = { only: ['phone'] };

test('phone catches E.164, formatted international, parenthesized, and trunk-0 numbers', () => {
  const numbers = [
    '+994501234567',
    '+90 532 123 45 67',
    '+1 (415) 555-2671',
    '(555) 123-4567',
    '0532 123 45 67',
    '0044 20 7946 0958',
  ];
  for (const n of numbers) {
    const [finding] = scan(`call ${n} today`, opts);
    assert.equal(finding?.detector, 'phone', n);
    assert.equal(redact(`call ${n} today`, opts).includes(n), false, n);
  }
});

test('phone never fires on dates, versions, or bare digit runs', () => {
  const clean = [
    'released 2026.07.24 build',
    'deadline 07.24.2026 noted',
    'invoice 2026-07-24-0001',
    'id 123456789 assigned',
    'v2.10.4567 deployed',
  ];
  for (const text of clean) {
    assert.ok(isClean(text, opts), text);
  }
});

test('phone stays opt-in and masks with a short hint', () => {
  assert.ok(isClean('call +994501234567'));
  assert.equal(redact('call +994501234567', opts), 'call +99***');
  assert.equal(redact('call (555) 123-4567', opts), 'call (5***');
});
