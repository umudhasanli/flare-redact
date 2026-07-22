import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv, stringifyCsv, redactCsv } from '../dist/csv.js';

test('parseCsv handles quotes, embedded commas, newlines and CRLF', () => {
  const rows = parseCsv('a,b,c\r\n"x,y","he said ""hi""","line1\nline2"');
  assert.deepEqual(rows, [
    ['a', 'b', 'c'],
    ['x,y', 'he said "hi"', 'line1\nline2'],
  ]);
});

test('stringifyCsv round-trips and quotes only when needed', () => {
  const rows = [['a', 'b'], ['x,y', 'plain']];
  assert.equal(stringifyCsv(rows), 'a,b\n"x,y",plain');
  assert.deepEqual(parseCsv(stringifyCsv(rows)), rows);
});

test('redactCsv masks values but leaves headers and structure', () => {
  const csv = 'name,email,card\nAlice,alice@corp.com,4242 4242 4242 4242';
  const out = redactCsv(csv);
  const rows = parseCsv(out);
  assert.deepEqual(rows[0], ['name', 'email', 'card']); // header untouched
  assert.equal(rows[1][1], 'a***@***');
  assert.match(rows[1][2], /\*\*\*\* 4242$/);
});

test('redactCsv in pseudonym mode is deterministic and join-consistent', () => {
  const csv = 'email\nbob@x.io\nbob@x.io\nalice@x.io';
  const rows = parseCsv(redactCsv(csv, { mode: 'pseudonym', transformSecret: 'dataset-transform-secret' }));
  assert.equal(rows[1][0], rows[2][0]); // same email → same masked value (joins survive)
  assert.notEqual(rows[1][0], rows[3][0]); // different email → different
  assert.match(rows[1][0], /^[a-z]+@[a-z]\.[a-z]+$/); // still email-shaped
});
