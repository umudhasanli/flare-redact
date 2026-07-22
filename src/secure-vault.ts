import type { Vault } from './vault.js';

export interface SealedVaultV1 {
  format: 'flare-redact-vault';
  version: 1;
  kdf: {
    name: 'PBKDF2';
    hash: 'SHA-256';
    iterations: number;
    salt: string;
  };
  cipher: {
    name: 'AES-GCM';
    iv: string;
  };
  ciphertext: string;
}

export interface SealVaultOptions {
  /** PBKDF2 work factor. Values below 100,000 are rejected. */
  iterations?: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AAD = encoder.encode('flare-redact-vault:v1');
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 2_000_000;

function webCrypto(): Crypto {
  const provider = globalThis.crypto;
  if (!provider?.subtle || !provider.getRandomValues) {
    throw new Error('Web Crypto is required for encrypted vault persistence.');
  }
  return provider;
}

function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    out += BASE64[a >>> 2]!;
    out += BASE64[((a & 3) << 4) | ((b ?? 0) >>> 4)]!;
    out += b === undefined ? '=' : BASE64[((b & 15) << 2) | ((c ?? 0) >>> 6)]!;
    out += c === undefined ? '=' : BASE64[c & 63]!;
  }
  return out;
}

function fromBase64(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error('Encrypted vault contains invalid base64 data.');
  }
  const clean = value.replace(/=+$/, '');
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const index = BASE64.indexOf(ch);
    if (index < 0) throw new Error('Encrypted vault contains invalid base64 data.');
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

async function deriveKey(password: string, salt: Uint8Array, iterations: number, usage: KeyUsage[]): Promise<CryptoKey> {
  const crypto = webCrypto();
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    usage,
  );
}

function validatePassword(password: string): void {
  if (password.length < 12) throw new Error('Vault password must contain at least 12 characters.');
}

function normalizeEntries(source: Vault | Array<[string, string]>): Array<[string, string]> {
  return Array.isArray(source) ? source : source.entries();
}

/** Encrypt a placeholder map using PBKDF2-SHA-256 and AES-256-GCM. */
export async function sealVault(
  source: Vault | Array<[string, string]>,
  password: string,
  options: SealVaultOptions = {},
): Promise<SealedVaultV1> {
  validatePassword(password);
  const iterations = options.iterations ?? 310_000;
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error(`PBKDF2 iterations must be an integer from ${MIN_ITERATIONS} to ${MAX_ITERATIONS}.`);
  }
  const crypto = webCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, iterations, ['encrypt']);
  const plaintext = encoder.encode(JSON.stringify({ entries: normalizeEntries(source) }));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: AAD as BufferSource, tagLength: 128 },
    key,
    plaintext,
  );
  return {
    format: 'flare-redact-vault',
    version: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toBase64(salt) },
    cipher: { name: 'AES-GCM', iv: toBase64(iv) },
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

export function isSealedVault(value: unknown): value is SealedVaultV1 {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  if (record.format !== 'flare-redact-vault' || record.version !== 1) return false;
  if (!record.kdf || typeof record.kdf !== 'object' || !record.cipher || typeof record.cipher !== 'object') return false;
  const kdf = record.kdf as Record<string, unknown>;
  const cipher = record.cipher as Record<string, unknown>;
  return kdf.name === 'PBKDF2'
    && kdf.hash === 'SHA-256'
    && typeof kdf.iterations === 'number'
    && typeof kdf.salt === 'string'
    && cipher.name === 'AES-GCM'
    && typeof cipher.iv === 'string'
    && typeof record.ciphertext === 'string';
}

/** Decrypt and authenticate a sealed vault. Wrong passwords reveal no entries. */
export async function openVault(envelope: unknown, password: string): Promise<Array<[string, string]>> {
  validatePassword(password);
  if (!isSealedVault(envelope)) throw new Error('Not a supported encrypted flare-redact vault.');
  if (envelope.kdf.name !== 'PBKDF2' || envelope.kdf.hash !== 'SHA-256' || envelope.cipher.name !== 'AES-GCM') {
    throw new Error('Encrypted vault uses unsupported cryptographic parameters.');
  }
  if (!Number.isInteger(envelope.kdf.iterations) || envelope.kdf.iterations < MIN_ITERATIONS || envelope.kdf.iterations > MAX_ITERATIONS) {
    throw new Error('Encrypted vault uses an unsafe PBKDF2 work factor.');
  }
  try {
    const salt = fromBase64(envelope.kdf.salt);
    const iv = fromBase64(envelope.cipher.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error('invalid parameters');
    const key = await deriveKey(password, salt, envelope.kdf.iterations, ['decrypt']);
    const plaintext = await webCrypto().subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: AAD as BufferSource, tagLength: 128 },
      key,
      fromBase64(envelope.ciphertext) as BufferSource,
    );
    const parsed = JSON.parse(decoder.decode(plaintext)) as { entries?: unknown };
    if (!Array.isArray(parsed.entries)) throw new Error('invalid payload');
    const entries: Array<[string, string]> = [];
    const placeholders = new Set<string>();
    for (const entry of parsed.entries) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || typeof entry[1] !== 'string') {
        throw new Error('invalid payload');
      }
      if (placeholders.has(entry[0])) throw new Error('invalid payload');
      placeholders.add(entry[0]);
      entries.push([entry[0], entry[1]]);
    }
    return entries;
  } catch {
    throw new Error('Could not decrypt vault: wrong password or corrupted file.');
  }
}
