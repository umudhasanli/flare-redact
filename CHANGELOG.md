# Changelog

## 0.9.0 — unreleased

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

### Migration

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
