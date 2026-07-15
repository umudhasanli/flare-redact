import { readFileSync } from 'node:fs';
import { redact, scan, summary, DETECTORS, type Mode, type RedactOptions, type Finding } from './index.js';
import { redactCsv } from './csv.js';

const VERSION = '0.6.0';

const HELP = `flare-redact — hide secrets & PII before they hit a log

USAGE
  flare-redact [options] [files...]        stdin if no files

OPTIONS
  --scan            list what would be redacted, and why (input unchanged)
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
  --list            show all detectors and exit
  -h, --help        show this help
  -v, --version     show version

EXAMPLES
  tail -f app.log | flare-redact
  flare-redact --scan config.env
  flare-redact --json --mode hash < event.json
  flare-redact --enable high_entropy,ipv4 < app.log
`;

interface ParsedArgs {
  opts: RedactOptions;
  files: string[];
  scanMode: boolean;
  summaryMode: boolean;
  jsonMode: boolean;
  csvMode: boolean;
  showHelp: boolean;
  showVersion: boolean;
  listMode: boolean;
}

function csv(s: string | undefined): string[] {
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : [];
}

function parseArgs(argv: string[]): ParsedArgs {
  const opts: RedactOptions = {};
  const files: string[] = [];
  let scanMode = false;
  let summaryMode = false;
  let jsonMode = false;
  let csvMode = false;
  let showHelp = false;
  let showVersion = false;
  let listMode = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case '--scan': scanMode = true; break;
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
      default:
        if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
        files.push(a);
    }
  }
  return { opts, files, scanMode, summaryMode, jsonMode, csvMode, showHelp, showVersion, listMode };
}

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function formatFindings(findings: Finding[]): string {
  if (!findings.length) return 'No secrets found.';
  const lines = findings.map((f) => {
    const where = f.path ? `  @ ${f.path}` : f.start !== undefined ? `  @ ${f.start}` : '';
    return `⚠  ${f.label} (${f.detector})${where}\n   ${f.why}`;
  });
  const noun = findings.length === 1 ? 'finding' : 'findings';
  return `${findings.length} ${noun}:\n\n${lines.join('\n\n')}`;
}

export function main(argv: string[]): number {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { opts, files, scanMode, summaryMode, jsonMode, csvMode, showHelp, showVersion, listMode } = parsed;

  if (showHelp) { process.stdout.write(HELP); return 0; }
  if (showVersion) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (listMode) {
    for (const d of DETECTORS) {
      process.stdout.write(`${d.default ? '●' : '○'} ${d.id.padEnd(20)} ${d.label} — ${d.why}\n`);
    }
    return 0;
  }

  const raw = files.length ? files.map((f) => readFileSync(f, 'utf8')).join('\n') : readStdin();
  const data: unknown = jsonMode ? tryParse(raw) : raw;
  if (jsonMode && data === PARSE_ERROR) return 2;

  if (summaryMode) {
    const s = summary(data, opts);
    process.stdout.write(JSON.stringify(s, null, 2) + '\n');
    return s.total ? 1 : 0;
  }

  if (scanMode) {
    const findings = scan(data, opts);
    process.stdout.write(formatFindings(findings) + '\n');
    return findings.length ? 1 : 0;
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

function tryParse(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`invalid JSON: ${(e as Error).message}\n`);
    return PARSE_ERROR;
  }
}
