# Security

If you've found a detector bypass, a built-in pattern that can be made to
backtrack, a vault confidentiality/authentication issue, a placeholder collision,
or another security impact, report it privately instead of opening a public
issue. Use synthetic or revoked values in the reproduction.

Use GitHub's private advisory form:
**[Report a vulnerability](https://github.com/flare-collection/flare-redact/security/advisories/new)**

I'll acknowledge within a few days and keep you in the loop on a fix. Once it's
patched and released, I'm glad to credit you — unless you'd rather stay
anonymous, which is completely fine.

Supported versions: the latest released version on npm. Please make sure you can
reproduce on that before reporting.

## Security scope

Detection is best-effort and cannot prove that input is free of PII. Built-in
patterns are reviewed and adversarially benchmarked, but custom regular
expressions are trusted code because JavaScript RegExp has no general linear-time
guarantee. Encrypted vaults protect persisted maps, not a compromised host,
untrusted code running in the same process, or keys already present in process
memory. Restoring a placeholder intentionally reveals its original value, and
deterministic transforms intentionally reveal equality between matching inputs.

`scan()` omits matched values by default. Enabling `includeValues` is an explicit
confidentiality tradeoff: those findings must not be logged or exported. HTTP
redaction covers only the returned snapshot, never the live request. Tool and LLM
vaults protect data before it crosses the configured model boundary; restoring a
model-produced tool call intentionally exposes the original locally to that tool.
