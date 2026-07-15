import { redact, type RedactOptions } from './index.js';

/**
 * Drop-in redaction for pino. Unlike pino's own `redact`, which needs a list of
 * field paths, this reads the values — so it also catches the secret in a
 * free-text message or a nested third-party object.
 *
 *   import pino from 'pino';
 *   import { pinoRedact } from 'flare-redact/pino';
 *
 *   const log = pino(pinoRedact());
 *   log.info({ user: 'bob@corp.com' }); // → { "user": "b***@***" }
 */
export function pinoRedact(opts: RedactOptions = {}) {
  return {
    formatters: {
      log(object: Record<string, unknown>): Record<string, unknown> {
        return redact(object, opts);
      },
    },
  };
}
