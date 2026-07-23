import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { sha256Bytes, hmacSha256Bytes, bytesToHex, hmacFingerprint, deriveBytes } from '../dist/crypto.js';

// FIPS 180-4 / NIST CAVP known-answer vectors for SHA-256.
const SHA256_VECTORS = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  [
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  ],
  [
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
  ],
  ['a'.repeat(1_000_000), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'],
];

test('sha256Bytes matches FIPS 180-4 known-answer vectors', () => {
  for (const [message, digest] of SHA256_VECTORS) {
    assert.equal(bytesToHex(sha256Bytes(message)), digest);
  }
});

test('sha256Bytes matches node:crypto across block boundaries', () => {
  // Deterministic pseudo-random bytes; lengths straddle the 55/56/64-byte
  // padding and block edges where hand-rolled SHA-256 implementations break.
  for (const length of [0, 1, 31, 32, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4096]) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 131 + 89) % 251;
    const expected = createHash('sha256').update(bytes).digest('hex');
    assert.equal(bytesToHex(sha256Bytes(bytes)), expected, `length ${length}`);
  }
});

test('sha256Bytes encodes string input as UTF-8', () => {
  for (const message of ['héllo wörld', 'парол sirr açar', '密码鍵🔑', '\u0000\ufffd']) {
    const expected = createHash('sha256').update(message, 'utf8').digest('hex');
    assert.equal(bytesToHex(sha256Bytes(message)), expected);
  }
});

// RFC 4231 HMAC-SHA-256 test cases 1-7.
const hexBytes = (hex) => new Uint8Array(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
const RFC4231_VECTORS = [
  {
    name: 'case 1',
    key: hexBytes('0b'.repeat(20)),
    data: 'Hi There',
    mac: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    name: 'case 2 (short key)',
    key: 'Jefe',
    data: 'what do ya want for nothing?',
    mac: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    name: 'case 3',
    key: hexBytes('aa'.repeat(20)),
    data: hexBytes('dd'.repeat(50)),
    mac: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
  },
  {
    name: 'case 4',
    key: hexBytes('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: hexBytes('cd'.repeat(50)),
    mac: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
  },
  {
    name: 'case 5 (truncated to 128 bits)',
    key: hexBytes('0c'.repeat(20)),
    data: 'Test With Truncation',
    mac: 'a3b6167473100ee06e0c796c2955552b',
    truncate: 16,
  },
  {
    name: 'case 6 (key larger than block)',
    key: hexBytes('aa'.repeat(131)),
    data: 'Test Using Larger Than Block-Size Key - Hash Key First',
    mac: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
  },
  {
    name: 'case 7 (key and data larger than block)',
    key: hexBytes('aa'.repeat(131)),
    data:
      'This is a test using a larger than block-size key and a larger than block-size data. ' +
      'The key needs to be hashed before being used by the HMAC algorithm.',
    mac: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
  },
];

test('hmacSha256Bytes matches RFC 4231 known-answer vectors', () => {
  for (const { name, key, data, mac, truncate } of RFC4231_VECTORS) {
    const full = hmacSha256Bytes(key, data);
    const actual = bytesToHex(truncate ? full.subarray(0, truncate) : full);
    assert.equal(actual, mac, name);
  }
});

test('hmacSha256Bytes matches node:crypto for boundary-length keys', () => {
  // Keys at 63/64/65 bytes cross the "hash the key first" block threshold.
  for (const keyLength of [0, 1, 63, 64, 65, 128, 200]) {
    const key = new Uint8Array(keyLength);
    for (let i = 0; i < keyLength; i++) key[i] = (i * 37 + 11) % 256;
    const expected = createHmac('sha256', key).update('flare-redact').digest('hex');
    assert.equal(bytesToHex(hmacSha256Bytes(key, 'flare-redact')), expected, `key length ${keyLength}`);
  }
});

test('hmacFingerprint truncates the HMAC and requires a secret', () => {
  const expected = createHmac('sha256', 'secret').update('value').digest('hex');
  assert.equal(hmacFingerprint('secret', 'value'), expected.slice(0, 32));
  assert.equal(hmacFingerprint('secret', 'value', 8), expected.slice(0, 16));
  assert.throws(() => hmacFingerprint('', 'value'), /transformSecret/);
});

test('deriveBytes is a deterministic counter-mode HMAC chain', () => {
  const derived = deriveBytes('key', 'context', 80);
  assert.equal(derived.length, 80);
  assert.deepEqual(deriveBytes('key', 'context', 80), derived);
  // Independent reconstruction with node:crypto: HMAC(key, context || 0x00 || counter).
  const manual = new Uint8Array(80);
  for (let counter = 0, offset = 0; offset < manual.length; counter++) {
    const block = createHmac('sha256', 'key').update(`context\u0000${counter}`, 'utf8').digest();
    const take = Math.min(block.length, manual.length - offset);
    manual.set(block.subarray(0, take), offset);
    offset += take;
  }
  assert.deepEqual(derived, manual);
});

test('deriveBytes separates contexts and enforces exact lengths', () => {
  assert.notDeepEqual(deriveBytes('key', 'context-a', 32), deriveBytes('key', 'context-b', 32));
  assert.notDeepEqual(deriveBytes('key-a', 'context', 32), deriveBytes('key-b', 'context', 32));
  for (const length of [1, 31, 32, 33, 100]) {
    assert.equal(deriveBytes('key', 'context', length).length, length);
  }
  // A longer request must extend, not alter, the shorter derivation.
  assert.deepEqual(deriveBytes('key', 'context', 64).subarray(0, 32), deriveBytes('key', 'context', 32));
});
