<p align="center">
  <img src="assets/flare-redact.svg" alt="flare-redact" width="200">
</p>

<h1 align="center">flare-redact</h1>

<p align="center">
  <b>Hide secrets & PII in logs, prompts, and text — before they leak.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/flare-redact"><img src="https://img.shields.io/npm/v/flare-redact.svg" alt="npm"></a>
  <a href="https://github.com/umudhasanli/flare-redact/actions/workflows/ci.yml"><img src="https://github.com/umudhasanli/flare-redact/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/npm/types/flare-redact.svg" alt="TypeScript">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/languages-24-4f46e5" alt="24 languages">
  <img src="https://img.shields.io/badge/detectors-50-4f46e5" alt="50 detectors">
  <img src="https://img.shields.io/badge/runtime-node%20%7C%20browser%20%7C%20edge-blue" alt="Runtimes">
</p>

<p align="center">
  🌐 <b>International by default — 24 languages</b><br>
  🇬🇧 🇨🇳 🇮🇳 🇪🇸 🇸🇦 🇫🇷 🇵🇹 🇷🇺 🇯🇵 🇩🇪 🇰🇷 🇹🇷 🇮🇹 🇮🇷 🇵🇱 🇺🇦 🇳🇱 🇻🇳 🇮🇩 🇹🇭 🇬🇷 🇮🇱 🇦🇿 🇷🇴
</p>

---

Every leaked secret has the same origin story: someone logged an object, and a
password, token, or API key was sitting inside it. The code looked innocent —
`logger.info({ user })` — but `user` carried a session token, and now it's in
your log aggregator, your error tracker, and three vendors' systems forever.

**flare-redact** is one function you wrap around that data. It reads the *content*,
not just the field names, so it catches the AWS key someone pasted into a free-text
`note`, the JWT in an `Authorization` header, the card number in a stack trace — and
masks them, keeping just enough of a hint to stay debuggable.

```js
import { redact } from 'flare-redact';

redact('User alice@corp.com paid with 4242 4242 4242 4242, token ghp_' + 'a'.repeat(36));
// → 'User a***@*** paid with **** **** **** 4242, token ghp_***'
```

Nothing to configure. No list of field paths to maintain. No native build step.

> **The same problem now has a new address: your LLM calls.** Wrap your OpenAI or
> Anthropic client and secrets are stripped from every prompt and restored in the
> reply — the model never sees the real data, your app still gets the right answer.
> [Jump to it ↓](#redact-prompts-before-they-reach-an-llm)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/coverage-dark.svg">
    <img src="assets/coverage-light.svg" alt="One policy applied across app, logs, HTTP, LLM, datasets, and egress" width="820">
  </picture>
</p>

|   |   |   |
|---|---|---|
| 🔍 **Content-aware** — reads values, not just field names | ♻️ **Reversible** — vault: redact → use → restore | 🎭 **Format-preserving** — emails stay email-shaped |
| 🤖 **LLM-safe** — strips secrets before OpenAI/Anthropic | 🌍 **24 languages** — plus checksum-validated national IDs | 🛡️ **ReDoS-safe · 0 deps** — safe on untrusted input |

## Contents

- [Install](#install)
- [Redact anything](#redact-anything)
- [Redact prompts before they reach an LLM](#redact-prompts-before-they-reach-an-llm)
- [Ways to hide a value](#ways-to-hide-a-value)
- [Reversible redaction](#reversible-redaction)
- [See what leaks, and why](#see-what-leaks-and-why)
- [Guard your logger in one line](#guard-your-logger-in-one-line)
- [One policy, everywhere](#one-policy-everywhere)
- [Anonymize a dataset for staging](#anonymize-a-dataset-for-staging)
- [Guard what leaves your app](#guard-what-leaves-your-app)
- [Streams](#streams)
- [Fail a build when a secret sneaks in](#fail-a-build-when-a-secret-sneaks-in)
- [CLI](#cli)
- [What it catches](#what-it-catches)
- [Every language, every country](#every-language-every-country)
- [Custom detectors & allowlists](#custom-detectors--allowlists)
- [API](#api)
- [Why not a field allowlist?](#why-not-a-field-allowlist)

## Install

```bash
npm install flare-redact
```

Node 18+, and it runs in the browser and edge runtimes too — zero dependencies.

## Redact anything

Strings, arrays, and objects, recursively. The shape you pass in is the shape you
get back.

```js
import { redact } from 'flare-redact';

redact({
  user:     'bob@corp.com',
  password: 'hunter2',
  tokens:   ['ghp_' + 'b'.repeat(36)],
  note:     'my aws key is AKIAIOSFODNN7EXAMPLE',
});
// →
// {
//   user:     'b***@***',
//   password: '***',                     // sensitive field name
//   tokens:   ['ghp_***'],
//   note:     'my aws key is AKIA***',    // found inside free text
// }
```

## Redact prompts before they reach an LLM

Your app sends user data to OpenAI or Anthropic. Somewhere in that prompt is a
customer's email, an API key, or a card number — and now it's left your systems.
Wrap the client once, and secrets are stripped from every prompt and put back in
the reply. The model never sees the real values; your code still gets the right
answer.

```js
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI());

const res = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Email the invoice to alice@corp.com, card 4242 4242 4242 4242' }],
});
```

```
your app sends  →  Email the invoice to alice@corp.com, card 4242 4242 4242 4242
the model sees  →  Email the invoice to [EMAIL_1], card [CREDIT_CARD_1]
your app gets   →  Sent to alice@corp.com. Card 4242 4242 4242 4242 wasn't stored.
```

`wrapAnthropic` does the same for `messages.create`, including the system prompt.
Both handle streaming — placeholders are restored even when one is split across
chunks. There's a `redactPrompt(text)` too if you'd rather hold the vault
yourself.

## Ways to hide a value

Pick a `mode` depending on whether you still need to *reason* about the data
after it's hidden.

```js
redact('bob@corp.com', { mode: 'mask'  }); // 'b***@***'          (default)
redact('bob@corp.com', { mode: 'label' }); // '[REDACTED:email]'
redact('bob@corp.com', { mode: 'hash'  }); // 'email_f63d8d56'    (deterministic)
redact('bob@corp.com', { mode: 'fpe'   }); // 'kqz@rwmp.dnu'      (keeps the shape)
```

`hash` is the useful one for support work: the same input always hashes to the
same token, so you can still tell that two log lines came from the same user —
without ever storing who that user is. `fpe` (format-preserving) keeps the
*shape* — an email stays email-shaped, a card stays card-shaped — which is what
you want for realistic-but-safe test data. Both are deterministic; add `hashSalt`
to make the mapping per-service.

Or replace everything with one fixed string:

```js
redact(payload, { mask: '█' });
redact(payload, { mask: ({ detector }) => `<${detector.id}>` });
```

## Reversible redaction

When you need the originals back — the LLM case above, or handing data to a
system you don't trust and getting it back — use a vault. It swaps each secret
for a stable placeholder and remembers the mapping.

```js
import { createVault } from 'flare-redact';

const vault = createVault();
const safe = vault.redact('charge bob@corp.com on card 4242 4242 4242 4242');
// 'charge [EMAIL_1] on card [CREDIT_CARD_1]'

vault.restore(safe);
// 'charge bob@corp.com on card 4242 4242 4242 4242'
```

The same value always gets the same placeholder, so references survive the round
trip. Works on objects too, and `restore()` also takes a plain placeholder→value
map if you persisted one.

## See what leaks, and why

`scan()` finds secrets without changing the input, and explains every hit in
plain English — handy for alerts, dashboards, and understanding *why* something
matched.

```js
import { scan } from 'flare-redact';

scan('deploy with password=hunter2 and AKIAIOSFODNN7EXAMPLE');
// →
// [
//   { detector: 'generic_assignment', label: 'Assigned secret',
//     why: 'A value assigned to a sensitive-looking field name…', start: 12, … },
//   { detector: 'aws_access_key', label: 'AWS access key ID',
//     why: 'Pairs with a secret key to control cloud resources and billing.', start: 33, … },
// ]
```

Need just the shape of it?

```js
import { isClean, summary } from 'flare-redact';

isClean(payload);   // → false
summary(payload);   // → { total: 3, byDetector: { email: 1, github_token: 1, sensitive_key: 1 } }
```

## Guard your logger in one line

`wrapConsole` patches `console.*` so every argument is redacted on the way out,
and hands you a function to undo it.

```js
import { wrapConsole } from 'flare-redact';

const restore = wrapConsole();
console.log('session', { user: 'bob@x.io', token: 'ghp_…' });
// session { user: 'b***@***', token: 'ghp_***' }
restore();
```

Prefer to be explicit? Bind your options once and reuse it:

```js
import { createRedactor } from 'flare-redact';

const safe = createRedactor({ enable: ['high_entropy'] });
logger.info(safe.redact({ event: 'checkout', user }));
```

## One policy, everywhere

Define what "sensitive" means once, and apply it at every layer — your app, your
logger, your HTTP boundary, your LLM calls. Every adapter takes the same options
object, so a secret is masked the same way across the whole system.

```js
import { definePolicy } from 'flare-redact';
const policy = { enable: ['high_entropy'], allow: ['status@acme.com'] };
```

**pino** — reads the values, not a list of field paths you have to maintain:

```js
import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';

const log = pino(pinoRedact(policy));
log.info({ user: 'bob@corp.com' }); // → {"user":"b***@***"}
```

**winston** — a format that redacts every field, symbol metadata left intact:

```js
import winston from 'winston';
import { winstonRedact } from 'flare-redact/winston';

winston.format.combine(winston.format(winstonRedact(policy))(), winston.format.json());
```

**HTTP** — a safe-to-log snapshot of a request; the live request is untouched:

```js
import { httpRedactor } from 'flare-redact/http';

app.use(httpRedactor(policy));
app.use((req, _res, next) => { logger.info(req.redacted()); next(); });
// Authorization and Cookie headers, and any secret in the body or query, are masked.
```

Same `policy` object flows into `flare-redact/llm`, `wrapConsole`, `createVault`,
and `redactStream` too.

## Streams

Pipe any log stream through it — secrets are masked line by line, even when one
is split across chunks.

```js
import { redactStream } from 'flare-redact/stream';

process.stdin.pipe(redactStream()).pipe(process.stdout);
```

## Anonymize a dataset for staging

Point it at a JSON or CSV dump with `--mode fpe` and you get a copy that's safe
to hand to staging or a test suite. Format-preserving means an email stays
email-shaped and a card stays card-shaped; deterministic means the same value
maps the same way in every row — so foreign keys and joins still line up.

```bash
flare-redact --csv --mode fpe < customers.csv > customers.safe.csv
```

```
Alice,alice@corp.com,4242 4242 4242 4242      Alice,lkjjg@vfld.adz,7042 5270 7797 8929
Bob,bob@corp.com,5555 5555 5555 4444     →    Bob,yay@vjxl.fpe,0888 2706 6232 0279
Alice,alice@corp.com,4242 4242 4242 4242      Alice,lkjjg@vfld.adz,7042 5270 7797 8929
```

`redactCsv(text, opts)` is available from `flare-redact/csv` for the same thing
in code.

## Guard what leaves your app

Stop PII from reaching an analytics, telemetry, or webhook endpoint — wrap
`fetch` and name the hosts you don't trust with the real data. Every other
request goes through untouched, so your real API calls are never altered.

```js
import { wrapFetch } from 'flare-redact/fetch';

const fetch = wrapFetch(globalThis.fetch, { hosts: ['api.segment.io', 'telemetry.vendor.com'] });
// bodies sent to those hosts are redacted; everything else is left alone
```

## Fail a build when a secret sneaks in

`scan` from code, or `--scan` from the CLI (which exits non-zero on a hit) — drop
it into CI or a pre-commit hook:

```yaml
- run: git ls-files '*.env*' '*.log' '*.json' | xargs npx flare-redact --scan
```

## CLI

```bash
npm install -g flare-redact
```

```bash
tail -f app.log | flare-redact               # stream redacted logs
flare-redact --json --mode hash < event.json # deep-redact a JSON payload
flare-redact --csv --mode fpe < dump.csv     # anonymize a dataset for staging
flare-redact --scan config.env               # list findings + why (exit 1 if any)
flare-redact --summary --json < event.json   # counts per detector
flare-redact --enable high_entropy < app.log # also catch unknown-format keys
flare-redact --list                          # show every detector
```

## What it catches

On by default:

| Detector | Finds |
|---|---|
| `private_key` | PEM private key blocks (RSA/EC/OpenSSH/PGP) |
| `aws_access_key` | AWS access key IDs (`AKIA…`, `ASIA…`) |
| `github_token` | GitHub PATs and OAuth tokens (`ghp_…`, `github_pat_…`) |
| `gitlab_token` | GitLab PATs (`glpat-…`) |
| `slack_token` | Slack tokens (`xoxb-…`) |
| `stripe_key` | Stripe secret / restricted keys (`sk_live_…`, `rk_…`) |
| `openai_key` | OpenAI API keys (`sk-…`) |
| `google_api_key` | Google API keys (`AIza…`) |
| `sendgrid_key` | SendGrid API keys (`SG.…`) |
| `twilio_key` | Twilio SIDs / keys (`AC…`, `SK…`) |
| `npm_token` | npm tokens (`npm_…`) |
| `jwt` | JSON Web Tokens |
| `bearer_token` | `Authorization: Bearer …` |
| `basic_auth` | `Authorization: Basic …` |
| `url_credentials` | passwords inside connection strings |
| `generic_assignment` | `password=`, `api_key: …`, `secret=…` (any language) |
| `email` | email addresses |
| `credit_card` | card numbers (Luhn-validated) |
| `iban` | IBANs (mod-97 validated) |
| `discord_bot_token` / `telegram_bot_token` | chat bot tokens |
| `shopify_token` / `square_token` | commerce tokens |
| `digitalocean_token` / `azure_storage_key` | cloud secrets |
| `sentry_dsn` / `new_relic_key` | observability secrets |

Opt in with `enable`:

| Detector / tag | Finds |
|---|---|
| `high_entropy` | long random-looking tokens of *any* format (entropy-based) |
| `crypto` | Bitcoin & Ethereum addresses, BIP39 seed phrases |
| `finance` | SWIFT/BIC, US ABA routing numbers |
| `vehicle` | VINs (checksum-validated) |
| `network` | IPs, MAC addresses, coordinates, internal URLs |
| `phone` | E.164 phone numbers |

Plus object values whose **key name** is sensitive (`password`, `token`,
`authorization`, `cookie`, `cvv`, …) are masked regardless of content.

## Every language, every country

Secrets like API keys and card numbers don't care what language your app is in.
Neither does this — but the word-based checks do, so `password`, `secret`, and
`token` are recognized in **24 languages** (`şifrə=…`, `密码: …`, `пароль=…`,
`contraseña: …`), as assignments and as object keys.

National IDs are opt-in and **checksum-validated**, so a random run of digits is
never mistaken for one. Enable a whole group or a single country by tag:

```js
redact(text, { enable: ['pii'] });        // every national ID below
redact(text, { enable: ['tr', 'de'] });   // just Turkish and German
```

| Detector | Country | Validated by |
|---|---|---|
| `iban` | 🌐 international *(on by default)* | ISO 13616 mod-97 |
| `tr_tckn` | 🇹🇷 Turkey | TCKN checksum |
| `de_tax_id` | 🇩🇪 Germany | ISO 7064 mod-11,10 |
| `es_dni` | 🇪🇸 Spain (DNI/NIE) | control letter mod-23 |
| `it_codice_fiscale` | 🇮🇹 Italy | odd/even table |
| `br_cpf` | 🇧🇷 Brazil | two mod-11 digits |
| `nl_bsn` | 🇳🇱 Netherlands | 11-test |
| `pl_pesel` | 🇵🇱 Poland | weighted mod-10 |
| `ca_sin` | 🇨🇦 Canada | Luhn |
| `us_ssn` | 🇺🇸 United States | issued-range rules |
| `uk_nhs` | 🇬🇧 United Kingdom (NHS) | weighted mod-11 |

Every algorithm has its own tests against known-valid and known-invalid numbers,
so enabling them won't turn your logs into a wall of `[REDACTED]`.

## Custom detectors & allowlists

Teach it your own secrets, and tell it what to leave alone:

```js
redact(text, {
  custom: [{
    id: 'internal_ticket',
    label: 'Internal ticket',
    why: 'Leaks internal issue-tracker IDs.',
    pattern: /\bACME-\d{4,6}\b/g,
    mask: () => '[TICKET]',
    default: true,
  }],
  allow: ['support@acme.com'],        // never redact these exact values
  redactKeys: ['ssn', 'dob'],         // extra sensitive object keys
});
```

## API

```ts
redact<T>(input: T, opts?): T                 // masked copy, same shape
scan(input, opts?): Finding[]                 // findings + why, input untouched
isClean(input, opts?): boolean                // any secrets at all?
summary(input, opts?): { total, byDetector }  // counts per detector
createRedactor(opts) / definePolicy(opts)      // one policy: redact, scan, vault(), wrapConsole, options
wrapConsole(opts?, console?): () => void      // patch console.*, returns restore

createVault(opts?): Vault                      // reversible: redact / restore / entries
restore(input, vaultOrMap): T                  // put originals back

// adapters — each takes the same options object
pinoRedact(opts?)        // 'flare-redact/pino'    → { formatters: { log } }
winstonRedact(opts?)     // 'flare-redact/winston' → a format transform
redactHttp(req, opts?)   // 'flare-redact/http'    → safe-to-log request snapshot
httpRedactor(opts?)      // 'flare-redact/http'    → Express/Connect middleware
redactCsv(text, opts?)   // 'flare-redact/csv'     → anonymize a CSV dataset
wrapFetch(fetch, opts?)  // 'flare-redact/fetch'   → redact egress to named hosts

// from 'flare-redact/llm'
wrapOpenAI(client, opts?)                       // scrub prompts, restore replies (+streaming)
wrapAnthropic(client, opts?)                    // same for messages.create + system
redactPrompt(text, opts?): { text, vault }

// from 'flare-redact/stream'
redactStream(opts?): Transform                  // line-wise stream redaction

// opts
// {
//   only?, enable?, disable?, custom?,   // which detectors run
//   mode?: 'mask' | 'label' | 'hash' | 'fpe', hashSalt?, mask?,
//   redactKeys?: boolean | RegExp | string[],
//   allow?: RegExp | string[],
// }
```

## Why not a field allowlist?

Path-based redactors (like naming fields in a logger config) only hide the fields
you *remembered* to name. The leak is always the field you forgot — the free-text
message, the nested third-party payload, the string someone concatenated by hand.
flare-redact scans the actual values, so it doesn't depend on your memory.

And the patterns it scans with are **bounded and ReDoS-safe** — no nested
quantifiers, no `(a+)+` blow-ups. You can point it at attacker-controlled input
and it stays linear, the same principle behind its sibling
[flare-regex](https://github.com/umudhasanli/flare-regex).

## License

MIT © Umud Hasanli
