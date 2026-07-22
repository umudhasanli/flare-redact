import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));
const githubToken = 'ghp_' + 'a'.repeat(36);

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: 'utf8',
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
    assert.equal(report.schemaVersion, 1);
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
