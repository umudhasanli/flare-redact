import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));
const githubToken = 'ghp_' + 'a'.repeat(36);

function run(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: 'utf8',
    input: options.input,
    env: { ...process.env, ...options.env },
  });
}

test('scan pretty output includes file, line and column', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-redact-cli-'));
  try {
    const file = join(dir, 'sample.env');
    writeFileSync(file, `SAFE=true\nfound ${githubToken}\n`);
    const result = run(['--scan', file]);
    assert.equal(result.status, 1);
    assert.ok(result.stdout.includes(`${file}:2:7`));
    assert.equal(result.stdout.includes(githubToken), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scan JSON is structured and never echoes the secret value', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-redact-cli-'));
  try {
    const file = join(dir, 'sample.log');
    writeFileSync(file, `booted\n${githubToken}\n`);
    const result = run(['--scan', '--format', 'json', file]);
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schemaVersion, 2);
    assert.equal(report.summary.total, 1);
    assert.equal(report.findings[0].file, file);
    assert.equal(report.findings[0].line, 2);
    assert.equal(report.findings[0].column, 1);
    assert.equal('value' in report.findings[0], false);
    assert.equal(result.stdout.includes(githubToken), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('SARIF output contains a GitHub-compatible source location', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-redact-cli-'));
  try {
    const file = join(dir, 'sample.env');
    writeFileSync(file, `${githubToken}\n`);
    const result = run(['--sarif', file]);
    assert.equal(result.status, 1);
    const sarif = JSON.parse(result.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results[0].ruleId, 'github_token');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, file);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
    assert.equal(result.stdout.includes(githubToken), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI vault persistence is encrypted and round-trips', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-redact-cli-'));
  try {
    const vaultFile = join(dir, 'session.vault.json');
    const env = { FLARE_REDACT_VAULT_PASSWORD: 'correct horse battery staple' };
    const sealed = run(['--vault', vaultFile], { input: 'email alice@corp.com', env });
    assert.equal(sealed.status, 0, sealed.stderr);
    assert.doesNotMatch(sealed.stdout, /alice@corp\.com/);
    const stored = readFileSync(vaultFile, 'utf8');
    assert.doesNotMatch(stored, /alice@corp\.com/);
    assert.equal(JSON.parse(stored).format, 'flare-redact-vault');

    const restored = run(['--restore', vaultFile], { input: sealed.stdout, env });
    assert.equal(restored.status, 0, restored.stderr);
    assert.equal(restored.stdout, 'email alice@corp.com');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--version reflects the package.json version', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), pkg.version);
});

test('--min-confidence filters findings and rejects invalid values', () => {
  const kept = run(['--scan', '--format', 'json'], { input: `token ${githubToken}` });
  assert.equal(JSON.parse(kept.stdout).summary.total >= 1, true);
  const filtered = run(['--scan', '--format', 'json', '--min-confidence', '1'], { input: `token ${githubToken}` });
  assert.equal(filtered.status, 0);
  assert.equal(JSON.parse(filtered.stdout).summary.total, 0);
  const invalid = run(['--scan', '--min-confidence', '2'], { input: 'x' });
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /--min-confidence/);
});

test('--include-values opts scan output into raw values', () => {
  const safe = run(['--scan', '--format', 'json'], { input: githubToken });
  assert.equal(safe.stdout.includes(githubToken), false);
  const unsafe = run(['--scan', '--format', 'json', '--include-values'], { input: githubToken });
  assert.equal(unsafe.status, 1);
  assert.equal(JSON.parse(unsafe.stdout).findings[0].value, githubToken);
  const pretty = run(['--scan', '--include-values'], { input: githubToken });
  assert.ok(pretty.stdout.includes(`value: ${githubToken}`));
});

test('CLI protected transforms require a secret environment variable', () => {
  const missing = run(['--mode', 'hash'], { input: 'alice@corp.com', env: { FLARE_REDACT_SECRET: '' } });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /transformSecret/);

  const protectedRun = run(['--mode', 'hash'], {
    input: 'alice@corp.com',
    env: { FLARE_REDACT_SECRET: 'service-transform-secret' },
  });
  assert.equal(protectedRun.status, 0, protectedRun.stderr);
  assert.match(protectedRun.stdout, /^email_[0-9a-f]{32}$/);
});
