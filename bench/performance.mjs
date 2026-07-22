import { performance } from 'node:perf_hooks';
import { scan } from '../dist/index.js';

const sizes = [1_000, 10_000, 100_000];
if (process.env.FLARE_BENCH_INCLUDE_MIB === '1') sizes.push(1_000_000);
const runs = Number(process.env.FLARE_BENCH_RUNS ?? 10);
const warmups = Number(process.env.FLARE_BENCH_WARMUPS ?? 3);

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

const results = [];
for (const size of sizes) {
  const fragment = 'INFO request completed status=200 user=alice@example.com duration=12ms\n';
  const input = fragment.repeat(Math.ceil(size / fragment.length)).slice(0, size);
  for (let i = 0; i < warmups; i++) scan(input);
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    scan(input);
    samples.push(performance.now() - start);
  }
  results.push({
    bytes: Buffer.byteLength(input),
    runs,
    p50Ms: percentile(samples, 0.5),
    p95Ms: percentile(samples, 0.95),
    p99Ms: percentile(samples, 0.99),
    throughputMiBPerSecond: (Buffer.byteLength(input) / 1024 / 1024) / (percentile(samples, 0.5) / 1000),
    rssBytes: process.memoryUsage().rss,
  });
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, node: process.version, platform: process.platform, arch: process.arch, results }, null, 2) + '\n');
