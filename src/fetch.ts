import { redact, type RedactOptions } from './index.js';

export interface FetchGuardOptions extends RedactOptions {
  /**
   * Only redact the body of requests sent to these hosts (exact host, a parent
   * domain like `"segment.io"`, or a RegExp). With none set, nothing is
   * redacted — you opt in the sinks you don't want PII flowing to.
   */
  hosts?: Array<string | RegExp>;
}

type FetchFn = (input: unknown, init?: { body?: unknown; [k: string]: unknown }) => Promise<unknown>;

function hostOf(input: unknown): string {
  try {
    const url = typeof input === 'string' ? input : ((input as { url?: string })?.url ?? String(input));
    return new URL(url, 'http://localhost').host;
  } catch {
    return '';
  }
}

function makeHostMatch(hosts?: Array<string | RegExp>): (host: string) => boolean {
  if (!hosts?.length) return () => false;
  return (host) =>
    !!host &&
    hosts.some((h) => (h instanceof RegExp ? h.test(host) : host === h || host.endsWith('.' + h)));
}

function redactBody(body: string, opts: RedactOptions): string {
  try {
    return JSON.stringify(redact(JSON.parse(body), opts));
  } catch {
    return redact(body, opts);
  }
}

/**
 * Wrap `fetch` so secrets and PII are stripped from a request body before it
 * leaves for a host you name — analytics, telemetry, a webhook, a log sink.
 * Requests to every other host pass through untouched.
 *
 *   const fetch = wrapFetch(globalThis.fetch, { hosts: ['api.segment.io'] });
 */
export function wrapFetch(fetchImpl: FetchFn, opts: FetchGuardOptions = {}): FetchFn {
  const match = makeHostMatch(opts.hosts);
  return (input, init) => {
    if (init && typeof init.body === 'string' && match(hostOf(input))) {
      return fetchImpl(input, { ...init, body: redactBody(init.body, opts) });
    }
    return fetchImpl(input, init);
  };
}
