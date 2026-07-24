// Runtime-portability smoke test. Runs the dependency-free core on any ESM
// runtime — Node, Bun, Deno — without node:test or other Node-only modules.
// CI executes it under Bun and Deno; `node scripts/runtime-smoke.mjs` works too.
const { redact, scan, isClean, createVault, restore, sealVault, openVault } =
  await import(new URL('../dist/index.js', import.meta.url).href);
const { secretProbability } = await import(new URL('../dist/ml.js', import.meta.url).href);

let failures = 0;
function check(name, ok) {
  if (!ok) {
    failures++;
    console.error(`✖ ${name}`);
  } else {
    console.log(`✔ ${name}`);
  }
}

const gh = 'ghp_' + 'a'.repeat(36);

check('redacts an email', redact('mail bob@corp.com') === 'mail b***@***');
check('redacts a token in an object', !JSON.stringify(redact({ note: gh })).includes(gh));
check('scan finds and labels', scan(`k=${gh}`)[0]?.detector === 'github_token');
check('isClean on safe text', isClean('nothing sensitive here'));

const vault = createVault();
const masked = vault.redact(`send to bob@corp.com token ${gh}`);
check('vault masks', !masked.includes('bob@corp.com') && !masked.includes(gh));
check('vault restores', vault.restore(masked) === `send to bob@corp.com token ${gh}`);
check('standalone restore accepts entries', restore(masked, vault) === `send to bob@corp.com token ${gh}`);

const sealed = await sealVault(vault, 'runtime-smoke-password');
const reopened = new Map(await openVault(sealed, 'runtime-smoke-password'));
check('sealed vault round-trips via Web Crypto', restore(masked, reopened).includes('bob@corp.com'));

check('ml classifier is deterministic', secretProbability('xK9mQ2vR8jW4nP7bT3cY6hF1dL5sA0gZ') > 0.5
  && secretProbability('550e8400-e29b-41d4-a716-446655440000') < 0.5);

const runtime = typeof Bun !== 'undefined' ? `bun ${Bun.version}`
  : typeof Deno !== 'undefined' ? `deno ${Deno.version.deno}`
  : `node ${globalThis.process?.version ?? 'unknown'}`;

if (failures > 0) {
  console.error(`runtime-smoke: ${failures} failure(s) on ${runtime}`);
  globalThis.process?.exit?.(1);
  throw new Error('runtime smoke failed');
}
console.log(`runtime-smoke: all checks passed on ${runtime}`);
