import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean } from '../dist/index.js';

// The classic 40-char example secret from the AWS documentation.
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

test('aws_secret_key catches assignments in env, JSON, and camelCase forms', () => {
  const samples = [
    `AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
    `aws_secret_key: ${AWS_SECRET}`,
    `"secretAccessKey": "${AWS_SECRET}"`,
  ];
  for (const sample of samples) {
    const [finding] = scan(sample);
    assert.equal(finding.detector, 'aws_secret_key', sample);
    assert.equal(redact(sample).includes(AWS_SECRET), false, sample);
  }
});

test('aws_secret_key needs context — a bare 40-char string stays clean', () => {
  assert.ok(isClean(`downloaded blob ${AWS_SECRET} from cache`));
});

test('aws_secret_key wins overlap against generic_assignment', () => {
  const findings = scan(`aws_secret_access_key = ${AWS_SECRET}`);
  assert.deepEqual(findings.map((f) => f.detector), ['aws_secret_key']);
});

const TOKENS = [
  ['huggingface_token', 'hf_' + 'AbCd1234'.repeat(4) + 'Xy'],
  ['vault_token', 'hvs.' + 'CAESIJx'.repeat(4)],
  ['groq_key', 'gsk_' + 'Ab12Cd34'.repeat(6) + 'WxYz'],
  ['xai_key', 'xai-' + 'token1AB'.repeat(10)],
  ['perplexity_key', 'pplx-' + 'a1b2c3d4'.repeat(6)],
  ['openrouter_key', 'sk-or-v1-' + 'ab12'.repeat(16)],
  ['replicate_token', 'r8_' + 'Ab12Cd34'.repeat(4) + 'Wxyz5'],
  ['databricks_token', 'dapi' + 'a1b2c3d4'.repeat(4)],
  ['airtable_pat', 'pat' + 'Ab12Cd34Ef56Gh'.slice(0, 14) + '.' + 'ab12cd34'.repeat(8)],
  ['postman_key', 'PMAK-' + 'a1b2c3d4'.repeat(3) + '-' + 'ef56ab12cd34'.repeat(2) + 'a1b2c3d4ef'],
  ['linear_key', 'lin_api_' + 'Ab12Cd34'.repeat(5)],
  ['figma_token', 'figd_' + 'Ab12-Cd34_Ef56Gh78'.repeat(2) + 'Ij90'],
  ['notion_token', 'ntn_' + 'Ab12Cd34'.repeat(5) + 'Wxyz56'],
  ['notion_token', 'secret_' + 'Ab12Cd34Ef5'.repeat(4).slice(0, 43)],
  ['doppler_token', 'dp.st.prd_backend.' + 'Ab12Cd34'.repeat(5)],
  ['supabase_key', 'sbp_' + 'ab12cd34'.repeat(5)],
  ['netlify_token', 'nfp_' + 'Ab12Cd34'.repeat(5)],
  ['stripe_webhook_secret', 'whsec_' + 'Ab12Cd34'.repeat(5)],
  ['mailgun_key', 'key-' + 'ab12cd34'.repeat(4)],
  ['discord_webhook', 'https://discord.com/api/webhooks/123456789012345678/' + 'Ab12Cd34_-'.repeat(7)],
];

test('every new service token is detected under its own id and masked', () => {
  for (const [id, token] of TOKENS) {
    const text = `deploy log: ${token} done`;
    const [finding] = scan(text);
    assert.ok(finding, `${id}: no finding`);
    assert.equal(finding.detector, id, `${id}: got ${finding.detector}`);
    assert.equal(redact(text).includes(token), false, `${id}: token survived redact`);
  }
});

test('GCP service-account key ids and refresh tokens are caught by default', () => {
  const blob = `{"type": "service_account", "private_key_id": "${'ab12cd34'.repeat(5)}"}`;
  const [finding] = scan(blob);
  assert.equal(finding.detector, 'gcp_service_account');
  assert.equal(redact(blob).includes('ab12cd34'), false);

  const refresh = '1//' + 'Ab12Cd34_-'.repeat(4);
  assert.equal(scan(`token ${refresh}`)[0].detector, 'gcp_refresh_token');
  assert.equal(redact(`token ${refresh}`).includes(refresh), false);
});

test('OpenRouter and Anthropic keys never fall through to openai_key', () => {
  const openrouter = 'sk-or-v1-' + 'ab12'.repeat(16);
  const anthropic = 'sk-ant-api03-' + 'a1B2'.repeat(23) + 'A';
  assert.equal(scan(`k=${openrouter}`)[0].detector, 'openrouter_key');
  assert.equal(scan(`k=${anthropic}`)[0].detector, 'anthropic_key');
  assert.equal(scan('k=sk-' + 'x'.repeat(48))[0].detector, 'openai_key');
});
