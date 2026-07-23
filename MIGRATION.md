# Migrating to flare-redact 1.0

Version 1.0 makes the public API safe by default and establishes the compatibility
contract for the `1.x` line.

## Upgrade

```bash
npm install flare-redact@^1.0.0
```

Projects pinned to `0.9.0`, `^0.9.0`, or a lockfile stay on their current version
until this command is run.

## Breaking change: scan values are opt-in

`scan()` and `scanAsync()` no longer return the raw matched secret by default.
Locations, detector metadata, risk, and confidence are unchanged.

```js
scan(input);                          // value is omitted
scan(input, { includeValues: true }); // value is present
```

Only enable `includeValues` in trusted, in-process diagnostics. Do not send those
findings to logs, CI reports, analytics, or error trackers.

## Object graph behavior

Redaction now terminates safely on circular input and preserves shared
references. It also traverses `Map`, `Set`, enumerable symbol values, `Error`
messages, `URL`, and `URLSearchParams`. If code previously depended on these
values being passed through without inspection, review the new masked output.

## HTTP snapshots

`redactHttp()` now sanitizes the URL string in addition to `query`, `params`,
headers, and body. Use `redactUrl()` directly when logging a URL outside an HTTP
request snapshot.

## LLM and tool calls

OpenAI and Anthropic wrappers now redact the complete message structure,
including tool-call argument strings, and restore streamed tool arguments across
chunk boundaries. For model-agnostic agent loops and MCP, use
`createToolBoundary()` from `flare-redact/tool`.

## Streams

`redactStream()` now buffers bounded multiline private-key records. Complete and
unterminated PEM private keys are masked; an oversized buffered record raises
`RedactionLimitError` with code `ERR_REDACTION_LIMIT`.

## Reusable policies

`createRedactor()` and `definePolicy()` now precompile detector selection and
matchers. `compilePolicy()` is the explicit name for the same API and also
exposes async scan/redaction methods.
