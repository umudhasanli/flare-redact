import { readFileSync, writeFileSync } from 'node:fs';
import { redact, scan, summary, createVault, restore, DETECTORS, type Mode, type RedactOptions, type Finding } from './index.js';
import { redactCsv } from './csv.js';

const VERSION = '0.8.0';
type ScanFormat = 'pretty' | 'json' | 'sarif';

const HELP = `flare-redact — hide secrets & PII before they hit a log

USAGE
  flare-redact [options] [files...]        stdin if no files

OPTIONS
  --scan            list what would be redacted, and why (input unchanged)
  --format <f>      scan output: pretty | json | sarif (default: pretty)
  --sarif           shorthand for --scan --format sarif
  --summary         print a count of findings per detector
  --json            parse input as JSON and redact recursively
  --csv             parse input as CSV and redact every cell
  --mode <m>        mask | label | hash | fpe  (default: mask)
  --hash-salt <s>   salt for --mode hash
  --only <ids>      use only these detectors (comma-separated)
  --enable <ids>    turn on extra detectors (e.g. ipv4,high_entropy)
  --disable <ids>   turn off detectors (e.g. email)
  --mask <str>      replace every secret with this string
  --allow <vals>    never redact these exact values (comma-separated)
  --term <word>     also catch this exact word/phrase (repeatable)
  --terms <file>    also catch every word/phrase in this file (one per line)
  --vault <file>    reversible: mask with placeholders, write the map to <file>
  --restore <file>  put originals back using a map written by --vault
  --list            show all detectors and exit
  -h, --help        show this help
  -v, --version     show version

EXAMPLES
  tail -f app.log | flare-redact
  flare-redact --scan config.env
  flare-redact --scan --format json .env app.log
  flare-redact --sarif .env > flare-redact.sarif
  flare-redact --json --mode hash < event.json
  flare-redact --enable high_entropy,ipv4 < app.log
`;

interface ParsedArgs {
  opts: RedactOptions;
  files: string[];
  scanMode: boolean;
  scanFormat: ScanFormat;
  summaryMode: boolean;
  jsonMode: boolean;
  csvMode: boolean;
  showHelp: boolean;
  showVersion: boolean;
  listMode: boolean;
  vaultFile?: string;
  restoreFile?: string;
}

function csv(s: string | undefined): string[] {
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : [];
}

function parseArgs(argv: string[]): ParsedArgs {
  const opts: RedactOptions = {};
  const files: string[] = [];
  let scanMode = false;
  let scanFormat: ScanFormat = 'pretty';
  let summaryMode = false;
  let jsonMode = false;
  let csvMode = false;
  let showHelp = false;
  let showVersion = false;
  let listMode = false;
  let vaultFile: string | undefined;
  let restoreFile: string | undefined;
  const terms: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case '--scan': scanMode = true; break;
      case '--format': scanFormat = parseScanFormat(argv[++i]); break;
      case '--sarif': scanMode = true; scanFormat = 'sarif'; break;
      case '--summary': summaryMode = true; break;
      case '--json': jsonMode = true; break;
      case '--csv': csvMode = true; break;
      case '--list': listMode = true; break;
      case '-h': case '--help': showHelp = true; break;
      case '-v': case '--version': showVersion = true; break;
      case '--only': opts.only = csv(argv[++i]); break;
      case '--enable': opts.enable = csv(argv[++i]); break;
      case '--disable': opts.disable = csv(argv[++i]); break;
      case '--allow': opts.allow = csv(argv[++i]); break;
      case '--mask': opts.mask = argv[++i]; break;
      case '--mode': opts.mode = argv[++i] as Mode; break;
      case '--hash-salt': opts.hashSalt = argv[++i]; break;
      case '--term': { const w = argv[++i]; if (w) terms.push(w); break; }
      case '--terms': {
        const lines = readFileSync(argv[++i]!, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        terms.push(...lines);
        break;
      }
      case '--vault': vaultFile = argv[++i]; break;
      case '--restore': restoreFile = argv[++i]; break;
      default:
        if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
        files.push(a);
    }
  }
  if (terms.length) opts.terms = terms;
  return { opts, files, scanMode, scanFormat, summaryMode, jsonMode, csvMode, showHelp, showVersion, listMode, vaultFile, restoreFile };
}

function parseScanFormat(value: string | undefined): ScanFormat {
  if (value === 'pretty' || value === 'json' || value === 'sarif') return value;
  throw new Error(`invalid scan format: ${value ?? '(missing)'} (expected pretty, json, or sarif)`);
}

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

interface LocatedFinding extends Finding {
  file?: string;
}

type ReportFinding = Omit<LocatedFinding, 'value'>;

function reportFinding({ value: _value, ...finding }: LocatedFinding): ReportFinding {
  return finding;
}

function findingLocation(f: LocatedFinding): string {
  if (f.file && f.line !== undefined) return `${f.file}:${f.line}:${f.column ?? 1}`;
  if (f.file && f.path) return `${f.file} @ ${f.path}`;
  if (f.file) return f.file;
  if (f.path) return f.path;
  if (f.line !== undefined) return `${f.line}:${f.column ?? 1}`;
  return f.start !== undefined ? `offset ${f.start}` : '';
}

function formatFindings(findings: LocatedFinding[]): string {
  if (!findings.length) return 'No secrets found.';
  const lines = findings.map((f) => {
    const location = findingLocation(f);
    const where = location ? `\n   at ${location}` : '';
    return `⚠  ${f.label} (${f.detector})${where}\n   ${f.why}`;
  });
  const noun = findings.length === 1 ? 'finding' : 'findings';
  return `${findings.length} ${noun}:\n\n${lines.join('\n\n')}`;
}

function formatJson(findings: LocatedFinding[], scannedFiles: string[]): string {
  return JSON.stringify({
    schemaVersion: 1,
    tool: { name: 'flare-redact', version: VERSION },
    summary: { total: findings.length, filesScanned: scannedFiles.length },
    findings: findings.map(reportFinding),
  }, null, 2);
}

function formatSarif(findings: LocatedFinding[]): string {
  const rules = [...new Map(findings.map((f) => [f.detector, {
    id: f.detector,
    name: f.label,
    shortDescription: { text: f.label },
    help: { text: f.why },
  }])).values()];
  const results = findings.map((f) => {
    const physicalLocation = f.file ? {
      artifactLocation: { uri: f.file },
      ...(f.line !== undefined ? { region: { startLine: f.line, startColumn: f.column ?? 1 } } : {}),
    } : undefined;
    return {
      ruleId: f.detector,
      level: 'warning',
      message: { text: `${f.label}: ${f.why}` },
      ...(physicalLocation ? { locations: [{ physicalLocation }] } : {}),
      ...(f.path ? { properties: { path: f.path } } : {}),
    };
  });
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'flare-redact', version: VERSION, informationUri: 'https://github.com/umudhasanli/flare-redact', rules } },
      results,
    }],
  }, null, 2);
}

function runScan(files: string[], jsonMode: boolean, opts: RedactOptions, format: ScanFormat): number {
  const findings: LocatedFinding[] = [];
  const inputs = files.length ? files : [undefined];
  try {
    for (const file of inputs) {
      const raw = file ? readFileSync(file, 'utf8') : readStdin();
      const data = jsonMode ? tryParse(raw, file) : raw;
      if (data === PARSE_ERROR) return 2;
      for (const finding of scan(data, opts)) findings.push(file ? { ...finding, file } : finding);
    }
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }

  const out = format === 'json'
    ? formatJson(findings, files)
    : format === 'sarif'
      ? formatSarif(findings)
      : formatFindings(findings);
  process.stdout.write(out + '\n');
  return findings.length ? 1 : 0;
}

export function main(argv: string[]): number {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { opts, files, scanMode, scanFormat, summaryMode, jsonMode, csvMode, showHelp, showVersion, listMode, vaultFile, restoreFile } = parsed;

  if (showHelp) { process.stdout.write(HELP); return 0; }
  if (showVersion) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (listMode) {
    for (const d of DETECTORS) {
      process.stdout.write(`${d.default ? '●' : '○'} ${d.id.padEnd(20)} ${d.label} — ${d.why}\n`);
    }
    return 0;
  }

  if (scanMode && !summaryMode && !vaultFile && !restoreFile) {
    return runScan(files, jsonMode, opts, scanFormat);
  }

  let raw: string;
  try {
    raw = files.length ? files.map((f) => readFileSync(f, 'utf8')).join('\n') : readStdin();
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }
  const data: unknown = jsonMode ? tryParse(raw) : raw;
  if (jsonMode && data === PARSE_ERROR) return 2;

  const emit = (out: unknown) =>
    process.stdout.write(jsonMode ? JSON.stringify(out, null, 2) + '\n' : String(out));

  if (restoreFile) {
    emit(restore(data, JSON.parse(readFileSync(restoreFile, 'utf8'))));
    return 0;
  }

  if (vaultFile) {
    const vault = createVault(opts);
    const out = vault.redact(data);
    writeFileSync(vaultFile, JSON.stringify(Object.fromEntries(vault.entries()), null, 2));
    emit(out);
    return 0;
  }

  if (summaryMode) {
    const s = summary(data, opts);
    process.stdout.write(JSON.stringify(s, null, 2) + '\n');
    return s.total ? 1 : 0;
  }

  if (jsonMode) {
    process.stdout.write(JSON.stringify(redact(data, opts), null, 2) + '\n');
    return 0;
  }

  if (csvMode) {
    process.stdout.write(redactCsv(raw, opts) + '\n');
    return 0;
  }

  process.stdout.write(redact(raw, opts));
  return 0;
}

const PARSE_ERROR = Symbol('parse-error');

function tryParse(raw: string, source?: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`invalid JSON${source ? ` in ${source}` : ''}: ${(e as Error).message}\n`);
    return PARSE_ERROR;
  }
}
