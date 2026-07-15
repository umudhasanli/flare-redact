import { redact, type RedactOptions } from './index.js';

/** Parse CSV text into rows of string cells (RFC 4180: quotes, escapes, CRLF). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i++;
    } else if (c === ',') {
      row.push(field);
      field = '';
      i++;
    } else if (c === '\r') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i += text[i + 1] === '\n' ? 2 : 1;
    } else if (c === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i++;
    } else {
      field += c;
      i++;
    }
  }
  if (field !== '' || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function escapeField(f: string): string {
  return /[",\r\n]/.test(f) ? '"' + f.replace(/"/g, '""') + '"' : f;
}

/** Serialize rows back to CSV, quoting only fields that need it. */
export function stringifyCsv(rows: string[][]): string {
  return rows.map((r) => r.map(escapeField).join(',')).join('\n');
}

/**
 * Redact every cell of a CSV. With `{ mode: 'fpe' }` the output is
 * format-preserving and deterministic, so the same value maps the same way in
 * every row — a safe, join-consistent copy of your data for staging and tests.
 */
export function redactCsv(text: string, opts: RedactOptions = {}): string {
  const rows = parseCsv(text);
  return stringifyCsv(rows.map((r) => r.map((cell) => redact(cell, opts))));
}
