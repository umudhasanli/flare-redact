import { assignmentPattern } from './i18n.js';
import { LOCALE_DETECTORS } from './locales.js';
import { EXTRA_DETECTORS } from './extra.js';

export { SECRET_KEYWORDS, MULTILANG_KEY_SET } from './i18n.js';

export interface Detector {
  id: string;
  label: string;
  why: string;
  pattern: RegExp;
  validate?: (match: string) => boolean;
  mask?: (match: string) => string;
  default: boolean;
  /** Group labels — e.g. `["pii","id","tr"]` — so `enable`/`disable` can target a set. */
  tags?: string[];
  /** Privacy impact used to resolve overlapping detections. */
  risk?: 'low' | 'medium' | 'high' | 'critical';
  /** Explicit overlap priority. Higher-priority findings win. */
  priority?: number;
  /** Capture group containing the sensitive value when the full match includes context. */
  capture?: number;
  /** Starting confidence before contextual validation, from 0 to 1. */
  confidence?: number;
  /** Optional nearby evidence used to adjust confidence. */
  context?: {
    positive?: RegExp;
    negative?: RegExp;
    window?: number;
  };
  /** Cheap literal gate evaluated before the regular expression. */
  prefilter?: string[];
}

export function keepPrefix(n: number) {
  return (v: string): string => (v.length <= n ? '***' : v.slice(0, n) + '***');
}

export function keepLast(n: number) {
  return (v: string): string => {
    const digits = v.replace(/\D/g, '');
    const tail = digits.slice(-n);
    const groups = Math.max(0, Math.ceil((digits.length - n) / 4));
    return ('**** '.repeat(groups) + tail).trim();
  };
}

export function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** @deprecated Non-cryptographic fingerprint retained only for compatibility. */
export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

export const SENSITIVE_KEY_RE =
  /^(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth(?:orization)?|cookie|session[_-]?id|refresh[_-]?token|credit[_-]?card|card[_-]?number|cvv|ssn)$/i;

export const SENSITIVE_KEY_DETECTOR: Detector = {
  id: 'sensitive_key',
  label: 'Sensitive field',
  why: 'A value stored under a field name that is sensitive by convention.',
  pattern: /(?!)/,
  mask: () => '***',
  default: true,
};

export const DETECTORS: Detector[] = [
  {
    id: 'private_key',
    label: 'Private key',
    why: 'A PEM private key is a full cryptographic identity — whoever holds it is you.',
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    mask: () => '[REDACTED PRIVATE KEY]',
    default: true,
  },
  {
    id: 'aws_access_key',
    label: 'AWS access key ID',
    why: 'Pairs with a secret key to control cloud resources and billing.',
    pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)(?:[ \t-]?[A-Z0-9]){16}\b/g,
    validate: (value) => /^(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}$/.test(value.replace(/[ \t-]/g, '')),
    mask: keepPrefix(4),
    default: true,
  },
  {
    id: 'github_token',
    label: 'GitHub token',
    why: 'Grants access to repositories and account actions.',
    pattern: /\b(?:gh[posur]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g,
    mask: keepPrefix(4),
    default: true,
  },
  {
    id: 'gitlab_token',
    label: 'GitLab token',
    why: 'A GitLab personal access token grants API and repo access.',
    pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/g,
    mask: keepPrefix(6),
    default: true,
  },
  {
    id: 'slack_token',
    label: 'Slack token',
    why: 'Lets the holder read and post as your workspace app.',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,64}\b/g,
    mask: keepPrefix(5),
    default: true,
  },
  {
    id: 'stripe_key',
    label: 'Stripe secret key',
    why: 'A live secret or restricted key can move real money.',
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,64}\b/g,
    mask: (v) => v.slice(0, v.indexOf('_', v.indexOf('_') + 1) + 1) + '***',
    default: true,
  },
  {
    id: 'openai_key',
    label: 'OpenAI API key',
    why: 'Bills against your account and reaches your models and data.',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,64}\b/g,
    mask: keepPrefix(3),
    default: true,
  },
  {
    id: 'google_api_key',
    label: 'Google API key',
    why: 'Grants access to enabled Google Cloud APIs on your project.',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    mask: keepPrefix(4),
    default: true,
  },
  {
    id: 'sendgrid_key',
    label: 'SendGrid API key',
    why: 'Can send mail as your domain and read templates.',
    pattern: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g,
    mask: keepPrefix(3),
    default: true,
  },
  {
    id: 'twilio_key',
    label: 'Twilio SID / key',
    why: 'Can send messages and place calls billed to your account.',
    pattern: /\b(?:AC|SK)[a-f0-9]{32}\b/g,
    mask: keepPrefix(4),
    default: true,
  },
  {
    id: 'npm_token',
    label: 'npm token',
    why: 'Can publish packages to your npm account.',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    mask: keepPrefix(4),
    default: true,
  },
  {
    id: 'jwt',
    label: 'JSON Web Token',
    why: 'Often a live session or bearer credential — decode it and you may be signed in.',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g,
    mask: () => '[REDACTED JWT]',
    default: true,
  },
  {
    id: 'bearer_token',
    label: 'Bearer token',
    why: 'A bearer token in an Authorization header is a live credential.',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{8,}={0,2}/g,
    mask: () => 'Bearer ***',
    default: true,
  },
  {
    id: 'basic_auth',
    label: 'Basic auth header',
    why: 'Base64 in a Basic header decodes straight back to user:password.',
    pattern: /\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}/g,
    mask: () => 'Basic ***',
    default: true,
  },
  {
    id: 'url_credentials',
    label: 'Credentials in URL',
    why: 'A username:password baked into a connection string leaks the password.',
    pattern: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:@\s/]+:[^@\s/]+@/g,
    mask: (m) => m.replace(/:([^:@\s/]+)@$/, ':***@'),
    default: true,
  },
  {
    id: 'generic_assignment',
    label: 'Assigned secret',
    why: 'A value assigned to a sensitive-looking field name (password=…, 密码: …) in any language.',
    pattern: assignmentPattern(),
    mask: (m) => m.replace(/([:=]\s*["']?)([^\s"',;]{4,})(["']?)\s*$/u, '$1***$3'),
    default: true,
    tags: ['secret'],
  },
  {
    id: 'email',
    label: 'Email address',
    why: 'Personal data that usually does not belong in logs.',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
    mask: (m) => (m[0] ?? '') + '***@***',
    default: true,
    tags: ['pii'],
    prefilter: ['@'],
  },
  {
    id: 'obfuscated_email',
    label: 'Obfuscated email address',
    why: 'An email written with explicit “at” and “dot” separators to evade ordinary filters.',
    pattern: /\b[A-Za-z0-9._%+-]{1,64}\s*(?:\[at\]|\(at\))\s*[A-Za-z0-9-]{1,63}(?:\s*(?:\[dot\]|\(dot\))\s*[A-Za-z0-9-]{1,63}){1,4}\b/gi,
    mask: (m) => (m[0] ?? '') + '*** [at] *** [dot] ***',
    default: true,
    tags: ['pii', 'email', 'obfuscated'],
    risk: 'high',
    confidence: 0.84,
    priority: 45,
    prefilter: ['[at]', '(at)'],
  },
  {
    id: 'credit_card',
    label: 'Payment card number',
    why: 'A card number in logs is a PCI-DSS violation.',
    pattern: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: luhn,
    mask: keepLast(4),
    default: true,
    tags: ['pii', 'finance'],
  },
  {
    id: 'phone',
    label: 'Phone number',
    why: 'An E.164 phone number is personal data.',
    pattern: /\+[1-9]\d{7,14}\b/g,
    mask: (m) => m.slice(0, 3) + '***',
    default: false,
    tags: ['pii'],
  },
  {
    id: 'ipv4',
    label: 'IPv4 address',
    why: 'Can be personal data or reveal internal infrastructure.',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    mask: () => '***.***.***.***',
    default: false,
    tags: ['network'],
  },
  {
    id: 'ipv6',
    label: 'IPv6 address',
    why: 'Can be personal data or reveal internal infrastructure.',
    pattern: /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/g,
    mask: () => '[REDACTED IPv6]',
    default: false,
    tags: ['network'],
  },
  {
    id: 'mac_address',
    label: 'MAC address',
    why: 'A hardware address that can identify a device.',
    pattern: /\b(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}\b/g,
    mask: () => '**:**:**:**:**:**',
    default: false,
    tags: ['network'],
  },
  {
    id: 'high_entropy',
    label: 'High-entropy string',
    why: 'A long random-looking token — likely a key even if its format is unknown.',
    pattern: /\b[A-Za-z0-9+/=_-]{20,80}\b/g,
    validate: (v) => entropy(v) >= 3.5,
    mask: keepPrefix(4),
    default: false,
    tags: ['secret'],
  },
  {
    id: 'person_name',
    label: 'Person name',
    why: 'A person name appearing after an explicit identity label.',
    pattern: /(?:full[ _-]?name|customer[ _-]?name|contact[ _-]?name|name|ad[ıi]|isim|nombre|nom|nome|姓名|الاسم)\s*(?:[:=]|\bis\b)\s*["']?([\p{L}][\p{L}'’.-]{1,39}(?:\s+[\p{L}][\p{L}'’.-]{1,39}){1,3})/giu,
    capture: 1,
    mask: () => '[REDACTED PERSON]',
    default: false,
    tags: ['pii', 'contextual'],
    risk: 'high',
    confidence: 0.86,
    priority: 60,
  },
  {
    id: 'street_address',
    label: 'Street address',
    why: 'A street address appearing after an explicit address label.',
    pattern: /(?:street[ _-]?address|postal[ _-]?address|shipping[ _-]?address|address|ünvan|adres|dirección|adresse|indirizzo|地址|العنوان)\s*[:=]\s*["']?(\d{1,6}\s+[\p{L}0-9.'’ -]{2,60}\s+(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|way|küçəsi|küçe|sokak|cadde))/giu,
    capture: 1,
    mask: () => '[REDACTED ADDRESS]',
    default: false,
    tags: ['pii', 'contextual'],
    risk: 'high',
    confidence: 0.9,
    priority: 65,
  },
  {
    id: 'date_of_birth',
    label: 'Date of birth',
    why: 'A birth date is a strong quasi-identifier when linked to a person.',
    pattern: /(?:date[ _-]?of[ _-]?birth|birth[ _-]?date|dob|doğum[ _-]?tarixi|fecha[ _-]?de[ _-]?nacimiento|date[ _-]?de[ _-]?naissance|出生日期)\s*[:=]\s*["']?((?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:[12]\d|3[01]|0?[1-9])|(?:[12]\d|3[01]|0?[1-9])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2})/giu,
    capture: 1,
    mask: () => '[REDACTED DOB]',
    default: false,
    tags: ['pii', 'contextual'],
    risk: 'high',
    confidence: 0.96,
    priority: 70,
  },
  ...LOCALE_DETECTORS,
  ...EXTRA_DETECTORS,
];
