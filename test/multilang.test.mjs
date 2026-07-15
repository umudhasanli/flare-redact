import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan } from '../dist/index.js';

test('assignment detection works across languages', () => {
  assert.equal(redact('şifrə=hunter2'), 'şifrə=***'); // Azerbaijani/Turkish
  assert.equal(redact('密码: mysecret9'), '密码: ***'); // Chinese
  assert.equal(redact('пароль=abcdef'), 'пароль=***'); // Russian
  assert.equal(redact('contraseña: secreto123'), 'contraseña: ***'); // Spanish
  assert.equal(redact('senha = qwerty12'), 'senha = ***'); // Portuguese
});

test('sensitive object keys are recognized in other languages', () => {
  const out = redact({ 'şifrə': 'hunter2', '密码': 'abc123', wachtwoord: 'geheim42' });
  assert.equal(out['şifrə'], '***');
  assert.equal(out['密码'], '***');
  assert.equal(out.wachtwoord, '***');
});

test('IBAN is detected by default and validated by checksum', () => {
  assert.equal(redact('pay to GB82WEST12345698765432 today'), 'pay to [REDACTED IBAN] today');
  // one digit off → fails mod-97 → left alone
  assert.equal(redact('pay to GB82WEST12345698765433 today'), 'pay to GB82WEST12345698765433 today');
});

test('national IDs are opt-in by country tag', () => {
  const tckn = '10000000146'; // valid Turkish ID
  assert.equal(redact(tckn), tckn); // off by default
  assert.equal(redact(`id ${tckn}`, { enable: ['tr'] }), 'id [REDACTED ID]');
});

test('a number that fails the checksum is NEVER masked (no false positives)', () => {
  const notValid = '12345678901'; // 11 digits, fails the TCKN checksum
  assert.equal(redact(`ref ${notValid}`, { enable: ['tr'] }), `ref ${notValid}`);
  assert.equal(redact('order 99999999999', { enable: ['tr', 'pl', 'de'] }), 'order 99999999999');
});

test('enable by tag: "pii" turns on every national ID, a country code only its own', () => {
  const cpf = '11144477735'; // valid Brazilian CPF
  assert.match(redact(`cpf ${cpf}`, { enable: ['pii'] }), /\[REDACTED ID\]/);
  assert.equal(redact(`cpf ${cpf}`, { enable: ['tr'] }), `cpf ${cpf}`); // tr doesn't enable br
});

test('disable by tag removes a whole group', () => {
  assert.equal(redact('bob@x.io', { disable: ['pii'] }), 'bob@x.io'); // email is pii
  assert.equal(redact('bob@x.io AKIAIOSFODNN7EXAMPLE', { disable: ['pii'] }), 'bob@x.io AKIA***');
});

test('scan reports the locale detector id and why', () => {
  const [f] = scan('GB82WEST12345698765432');
  assert.equal(f.detector, 'iban');
  assert.ok(f.why.length > 0);
});
