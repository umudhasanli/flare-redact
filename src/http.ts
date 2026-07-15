import { redact, type RedactOptions } from './index.js';

export interface HttpRequestLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers?: Record<string, unknown>;
  query?: unknown;
  params?: unknown;
  body?: unknown;
}

export interface RedactedRequest {
  method?: string;
  url?: string;
  headers: unknown;
  query: unknown;
  params: unknown;
  body: unknown;
}

/**
 * A safe-to-log snapshot of a request. Authorization/Cookie headers, and any
 * secret or PII in the query, params, or body, are masked — while ordinary
 * fields (content-type, path, method) are left readable.
 */
export function redactHttp(req: HttpRequestLike, opts: RedactOptions = {}): RedactedRequest {
  return {
    method: req.method,
    url: req.originalUrl ?? req.url,
    headers: redact(req.headers ?? {}, opts),
    query: redact(req.query, opts),
    params: redact(req.params, opts),
    body: redact(req.body, opts),
  };
}

/**
 * Connect/Express middleware. It doesn't touch the live request; it attaches
 * `req.redacted()`, which returns a masked snapshot for your logger. Mount it
 * after your body parser so `body` is populated.
 *
 *   app.use(httpRedactor());
 *   app.use((req, _res, next) => { logger.info(req.redacted()); next(); });
 */
export function httpRedactor(opts: RedactOptions = {}) {
  return (req: HttpRequestLike, _res: unknown, next: () => void): void => {
    Object.defineProperty(req, 'redacted', {
      value: () => redactHttp(req, opts),
      enumerable: false,
      configurable: true,
      writable: true,
    });
    next();
  };
}
