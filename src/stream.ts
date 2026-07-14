import { Transform } from 'node:stream';
import { redact, type RedactOptions } from './index.js';

export function redactStream(opts: RedactOptions = {}): Transform {
  let carry = '';
  const flushLines = (text: string, final: boolean): string => {
    const parts = (carry + text).split('\n');
    carry = final ? '' : parts.pop() ?? '';
    return parts.map((line) => redact(line, opts)).join('\n');
  };
  return new Transform({
    transform(chunk, _enc, cb) {
      const out = flushLines(chunk.toString(), false);
      cb(null, out.length ? out + '\n' : '');
    },
    flush(cb) {
      cb(null, carry ? redact(carry, opts) : '');
    },
  });
}
