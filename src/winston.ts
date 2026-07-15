import { redact, type RedactOptions } from './index.js';

/**
 * A winston format transform. It redacts every enumerable field of the log
 * `info` in place, so winston's own symbol-keyed metadata (level, message)
 * stays intact.
 *
 *   import winston from 'winston';
 *   import { winstonRedact } from 'flare-redact/winston';
 *
 *   const log = winston.createLogger({
 *     format: winston.format.combine(winston.format(winstonRedact())(), winston.format.json()),
 *     transports: [new winston.transports.Console()],
 *   });
 */
export function winstonRedact(opts: RedactOptions = {}) {
  return (info: Record<string, unknown>): Record<string, unknown> => {
    for (const key of Object.keys(info)) {
      info[key] = redact(info[key], opts);
    }
    return info;
  };
}
