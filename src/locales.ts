import type { Detector } from './detectors.js';
import {
  ibanValid,
  tcknValid,
  cpfValid,
  dniValid,
  bsnValid,
  peselValid,
  deTaxIdValid,
  codiceFiscaleValid,
  luhnCheck,
  ssnValid,
} from './checksums.js';

const mask = (): string => '[REDACTED ID]';

/**
 * National identifiers and IBANs. Every one is checksum-validated, so a random
 * run of digits can't be mistaken for a real ID. All are opt-in by country tag
 * except IBAN, whose mod-97 check is strong enough to run by default.
 *
 *   redact(text, { enable: ['tr'] })   // Turkish IDs
 *   redact(text, { enable: ['pii'] })  // every national ID
 */
export const LOCALE_DETECTORS: Detector[] = [
  {
    id: 'iban',
    label: 'IBAN',
    why: 'An international bank account number.',
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    validate: ibanValid,
    mask: () => '[REDACTED IBAN]',
    default: true,
    tags: ['pii', 'finance'],
  },
  {
    id: 'tr_tckn',
    label: 'Turkish national ID (TCKN)',
    why: 'Turkey T.C. Kimlik No — a national identifier.',
    pattern: /\b[1-9]\d{10}\b/g,
    validate: tcknValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'tr'],
  },
  {
    id: 'br_cpf',
    label: 'Brazilian CPF',
    why: 'Brazil taxpayer registry number — high-value PII.',
    pattern: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,
    validate: cpfValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'br'],
  },
  {
    id: 'es_dni',
    label: 'Spanish DNI / NIE',
    why: 'Spain national identity / foreigner number.',
    pattern: /\b[XYZ]?\d{7,8}[A-Za-z]\b/g,
    validate: dniValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'es'],
  },
  {
    id: 'nl_bsn',
    label: 'Dutch BSN',
    why: 'Netherlands citizen service number.',
    pattern: /\b\d{9}\b/g,
    validate: bsnValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'nl'],
  },
  {
    id: 'pl_pesel',
    label: 'Polish PESEL',
    why: 'Poland national identification number.',
    pattern: /\b\d{11}\b/g,
    validate: peselValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'pl'],
  },
  {
    id: 'de_tax_id',
    label: 'German tax ID (Steuer-IdNr)',
    why: 'Germany tax identification number.',
    pattern: /\b\d{11}\b/g,
    validate: deTaxIdValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'de'],
  },
  {
    id: 'it_codice_fiscale',
    label: 'Italian Codice Fiscale',
    why: 'Italy fiscal code — a national identifier.',
    pattern: /\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/gi,
    validate: codiceFiscaleValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'it'],
  },
  {
    id: 'ca_sin',
    label: 'Canadian SIN',
    why: 'Canada social insurance number.',
    pattern: /\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g,
    validate: luhnCheck,
    mask,
    default: false,
    tags: ['pii', 'id', 'ca'],
  },
  {
    id: 'us_ssn',
    label: 'US Social Security number',
    why: 'A US national identifier — high-value PII.',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    validate: ssnValid,
    mask,
    default: false,
    tags: ['pii', 'id', 'us'],
  },
];
