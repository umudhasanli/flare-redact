import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  luhnCheck, ibanValid, tcknValid, cpfValid, dniValid,
  bsnValid, peselValid, deTaxIdValid, codiceFiscaleValid, ssnValid,
} from '../dist/checksums.js';

const cases = [
  ['IBAN', ibanValid, ['GB82WEST12345698765432', 'DE89370400440532013000', 'FR1420041010050500013M02606'], ['GB82WEST12345698765433', 'ZZ00NOPE']],
  ['TCKN', tcknValid, ['10000000146'], ['10000000145', '00000000000']],
  ['CPF', cpfValid, ['11144477735', '111.444.777-35'], ['11144477734', '11111111111']],
  ['DNI/NIE', dniValid, ['12345678Z', 'X1234567L'], ['12345678A', '99999999Z']],
  ['BSN', bsnValid, ['111222333'], ['111222334', '000000000']],
  ['PESEL', peselValid, ['44051401359'], ['44051401358']],
  ['DE-Tax', deTaxIdValid, ['86095742719', '65929970489'], ['86095742718']],
  ['CodiceFiscale', codiceFiscaleValid, ['MRTMTT25D09F205Z'], ['MRTMTT25D09F205A']],
  ['SSN', ssnValid, ['123-45-6789', '123456789'], ['000-45-6789', '666-45-6789', '900-45-6789', '123-00-6789']],
  ['Luhn', luhnCheck, ['4242424242424242', '046454286'], ['4242424242424241']],
];

for (const [name, fn, valid, invalid] of cases) {
  test(`${name}: accepts valid, rejects invalid`, () => {
    for (const v of valid) assert.equal(fn(v), true, `expected valid: ${v}`);
    for (const v of invalid) assert.equal(fn(v), false, `expected invalid: ${v}`);
  });
}
