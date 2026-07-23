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

function decode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Redact credentials, path segments, query values, and fragments while keeping
 * an absolute or relative URL usable in a log message.
 */
export function redactUrl(input: string, opts: RedactOptions = {}): string {
  const absolute = /^[a-z][a-z\d+.-]*:/i.test(input);
  const protocolRelative = input.startsWith('//');
  const queryOnly = input.startsWith('?');
  const hashOnly = input.startsWith('#');
  const leadingSlash = input.startsWith('/');
  try {
    const parsed = new URL(input, 'http://flare-redact.invalid');
    if (parsed.username) parsed.username = '***';
    if (parsed.password) parsed.password = '***';
    parsed.pathname = parsed.pathname
      .split('/')
      .map((segment) => encodeURIComponent(redact(decode(segment), opts)))
      .join('/');

    const query = new URLSearchParams();
    for (const [key, value] of parsed.searchParams) {
      const keyed = redact({ [key]: value }, opts) as Record<string, string>;
      query.append(redact(key, opts), keyed[key] ?? redact(value, opts));
    }
    parsed.search = query.toString();
    if (parsed.hash) parsed.hash = encodeURIComponent(redact(decode(parsed.hash.slice(1)), opts));

    if (absolute) return parsed.toString();
    if (protocolRelative) return `//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
    if (queryOnly) return `${parsed.search}${parsed.hash}`;
    if (hashOnly) return parsed.hash;
    const path = leadingSlash ? parsed.pathname : parsed.pathname.replace(/^\//, '');
    return `${path}${parsed.search}${parsed.hash}`;
  } catch {
    return redact(input, opts);
  }
}

/**
 * A safe-to-log snapshot of a request. Authorization/Cookie headers, and any
 * secret or PII in the query, params, or body, are masked — while ordinary
 * fields (content-type, path, method) are left readable.
 */
export function redactHttp(req: HttpRequestLike, opts: RedactOptions = {}): RedactedRequest {
  return {
    method: req.method,
    url: typeof (req.originalUrl ?? req.url) === 'string'
      ? redactUrl((req.originalUrl ?? req.url)!, opts)
      : undefined,
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
