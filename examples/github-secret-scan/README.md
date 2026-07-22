# Pull-request secret and PII scan

Copy [`flare-redact.yml`](flare-redact.yml) to
`.github/workflows/flare-redact.yml` in a repository. It scans tracked project
contents locally on the GitHub runner and fails the check when a finding is
reported.

The workflow scans common tracked source and configuration formats and excludes
the npm lockfile. Add `--enable high_entropy` for unknown token formats, or use
`--only` for a narrowly scoped policy. High-entropy scanning is intentionally
not enabled by default because generated identifiers can create noisy findings.
