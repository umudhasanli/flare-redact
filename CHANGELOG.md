# Changelog

## 1.0.0 — 2026-07-23

### Production boundaries

- Sanitize credentials, path segments, query values, and fragments inside HTTP
  URL strings; export `redactUrl()` for standalone use.
- Redact complete OpenAI and Anthropic message structures, including tool-call
  arguments, and restore streamed OpenAI tool arguments and Anthropic partial
  JSON across arbitrary chunk boundaries.
- Add `flare-redact/tool` with one-way tool/MCP helpers and a reversible,
  conversation-scoped `createToolBoundary()` for agent loops.
- Make stream redaction record-aware for multiline PEM private keys, fail closed
  on unterminated keys, and bound buffered record size.

### Safe and stable core

- Omit raw secret values from `scan()` and `scanAsync()` findings by default.
  Trusted diagnostics can opt in with `includeValues: true`.
- Preserve cycles and shared references during redaction; traverse `Map`, `Set`,
  enumerable symbols, `Error`, `URL`, and `URLSearchParams`.
- Make global/sticky allow-list and sensitive-key regular expressions
  deterministic across repeated values.
- Add stable `FlareRedactError` codes; resource and stream limits use
  `ERR_REDACTION_LIMIT`.
- Add `compilePolicy()` and make `createRedactor()` / `definePolicy()` reuse
  resolved detectors and matchers, including async operations.
- Replace bracket-specific streamed vault restoration with matching based on the
  actual placeholder set, including custom placeholder formats.

### Verification

- Expand the test suite from 112 to 129 production-focused tests covering HTTP
  URL leakage, tool/MCP boundaries, streamed tool arguments, circular graphs,
  complex built-ins, multiline keys, custom placeholders, and safe findings.
- Add package export and tarball validation to CI.
- Add a dedicated `0.9.x` to `1.0.0` migration guide.

See [MIGRATION.md](MIGRATION.md) before upgrading.

## 0.9.0 — 2026-07-23

### Security

- Replace 32-bit FNV correlation tokens with keyed HMAC-SHA-256.
- Rename non-reversible shape preservation to `pseudonym`; retain `fpe` only as
  a deprecated compatibility alias and stop describing it as encryption.
- Add deterministic type-consistent `surrogate` mode.
- Require `transformSecret` for hash, pseudonym, and surrogate modes.
- Use opaque 96-bit random vault placeholders by default.
- Add PBKDF2-SHA-256 + AES-256-GCM authenticated vault persistence.
- Make CLI vault files encrypted by default and reject plaintext maps unless
  `--allow-plaintext-vault` is explicit.
- Add per-string input/finding limits and hostile-input benchmarks.

### Detection and resilience

- Add risk and confidence to findings and SARIF output.
- Add weighted risk-aware overlap resolution.
- Add opt-in contextual person-name, street-address, and birth-date detectors.
- Add sync and async semantic-provider hooks for local NER models.
- Detect bracket-obfuscated email addresses, spaced AWS keys, and tokens split
  with zero-width characters while preserving original character spans.
- Add reproducible latency and hostile-input scaling benchmarks.
- Change scan JSON to schema version 2.
- Make line/column calculation linear in input plus findings instead of rescanning
  the prefix for every finding.
- Add runnable OpenAI-compatible, Express + Pino, and copy-ready GitHub Actions
  CLI scan examples.

### Migration

- Upgrade Node.js to version 20 or newer. Opaque vault placeholders and encrypted
  vault persistence rely on the stable Web Crypto API.
- Set `transformSecret` in code, or `FLARE_REDACT_SECRET` for the CLI, when using
  deterministic protected modes.
- Set `FLARE_REDACT_VAULT_PASSWORD` before CLI `--vault` or `--restore`.
- Use `createVault({ placeholderStyle: 'readable' })` only if legacy predictable
  placeholders are required in a trusted local flow.
- Update scan-report consumers for schema version 2 and the `risk` and
  `confidence` fields.

## 0.8.0

- Add file-aware scan reports with line/column locations, safe JSON, and SARIF
  output for CI and code-scanning integrations.
