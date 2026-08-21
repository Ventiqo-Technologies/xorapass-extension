// Local secret-pattern detection for the paste guard.
//
// IMPORTANT: this module is pure and dependency-free. It performs ALL detection
// on-device -- pasted text is never sent anywhere for scanning. It is bundled
// into the content script (which runs the scan), the popup, and unit tests.
//
// The scanner returns match spans (with the raw value, for LOCAL redaction and
// masked previews only) plus the distinct set of detected TYPES. Only the type
// set is ever safe to log/transmit for auditing -- never the values.

export type SecretType =
  | 'private_key'
  | 'ssh_private_key'
  | 'aws_access_key'
  | 'github_token'
  | 'stripe_key'
  | 'jwt'
  | 'google_api_key'
  | 'slack_token'
  | 'llm_api_key'
  | 'database_url'
  | 'env_secret'
  | 'generic_secret'
  | 'password';

export interface SecretMatch {
  type: SecretType;
  /** Human-readable name for the UI, e.g. "AWS access key". */
  label: string;
  start: number;
  end: number; // exclusive
  /** The matched text. LOCAL USE ONLY (redaction, preview) -- never transmit. */
  value: string;
  /** A masked, safe-to-display rendering, e.g. "AKIA…3XPL". */
  preview: string;
}

export interface ScanResult {
  /** Merged, de-duplicated, sorted by position. */
  matches: SecretMatch[];
  /** Distinct types present. Safe to log -- contains no secret values. */
  types: SecretType[];
}

const LABELS: Record<SecretType, string> = {
  private_key: 'Private key',
  ssh_private_key: 'SSH private key',
  aws_access_key: 'AWS access key',
  github_token: 'GitHub token',
  stripe_key: 'Stripe secret key',
  jwt: 'JWT / bearer token',
  google_api_key: 'Google API key',
  slack_token: 'Slack token',
  llm_api_key: 'AI provider API key',
  database_url: 'Database connection string',
  env_secret: 'Secret in .env / assignment',
  generic_secret: 'High-entropy secret',
  password: 'Password',
};

// Higher wins when two matches overlap (more specific patterns beat generic).
const PRIORITY: Record<SecretType, number> = {
  private_key: 100,
  ssh_private_key: 100,
  aws_access_key: 90,
  github_token: 90,
  stripe_key: 90,
  google_api_key: 88,
  slack_token: 88,
  llm_api_key: 86,
  jwt: 84,
  database_url: 80,
  env_secret: 40,
  generic_secret: 10,
  password: 15,
};

/** Regex-based detectors for high-confidence, structured secret formats. */
interface RegexDetector {
  type: SecretType;
  re: RegExp; // must be global
  /** Optional refinement of the type based on the matched text. */
  refine?: (m: string) => SecretType;
}

const REGEX_DETECTORS: RegexDetector[] = [
  {
    // PEM private-key block (whole block when END is present, else the header
    // line alone -- so partial pastes are still caught). OpenSSH is refined to
    // ssh_private_key.
    type: 'private_key',
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
    refine: (m) => (/OPENSSH/.test(m) ? 'ssh_private_key' : 'private_key'),
  },
  {
    // JWT / structured bearer: three base64url segments, first two are JSON
    // (base64 of `{"` == `eyJ`). Very low false-positive rate.
    type: 'jwt',
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    type: 'aws_access_key',
    re: /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g,
  },
  {
    type: 'github_token',
    re: /\b(?:gh[posru]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
  },
  {
    type: 'stripe_key',
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/g,
  },
  {
    type: 'google_api_key',
    re: /\bAIza[A-Za-z0-9_-]{35}\b/g,
  },
  {
    type: 'slack_token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    // OpenAI / Anthropic style keys: `sk-...`, `sk-ant-...`, `sk-proj-...`.
    // Distinct from Stripe (which uses `sk_` with an underscore).
    type: 'llm_api_key',
    re: /\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    // Connection string carrying inline credentials (user:pass@host). The
    // embedded password is the secret; a credential-less URL won't match.
    type: 'database_url',
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:@/]+:[^\s@/]+@\S+/g,
  },
];

// Assignment / .env line: KEY = VALUE, optionally `export`-prefixed and quoted.
const ASSIGN_RE = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$/;
// Key names that indicate the value is a secret.
const SECRET_KEY_RE = /(pass|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|client[_-]?secret|conn(?:ection)?[_-]?str|db[_-]?url|database[_-]?url)/i;

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** True when the value has lower + upper + digit — the shape of real API keys
 *  and strong passwords, and a good filter against UUIDs, hex hashes, and
 *  single-case blobs. */
function hasMixedCaseDigit(s: string): boolean {
  return /[a-z]/.test(s) && /[A-Z]/.test(s) && /[0-9]/.test(s);
}

// Values that are clearly not secrets: booleans, ports/numbers, localhost,
// variable references, and obvious placeholders.
function isTrivialValue(v: string): boolean {
  return (
    /^(true|false|null|none|localhost|127\.0\.0\.1)$/i.test(v) ||
    /^[0-9]+$/.test(v) ||
    /^\$\{?[A-Za-z_]/.test(v) ||
    /^(x{3,}|changeme|your[_-]|<.*>|\.\.\.|example|placeholder|todo|secret_here|redacted)/i.test(v)
  );
}

/** Mask a value for display: keep a few edge chars, hide the middle. */
export function maskValue(value: string): string {
  const v = value.replace(/\s+/g, ' ').trim();
  if (v.length <= 8) return '•'.repeat(Math.max(4, v.length));
  const head = v.slice(0, 4);
  const tail = v.slice(-4);
  return `${head}…${tail}`;
}

function pushMatch(out: SecretMatch[], type: SecretType, start: number, end: number, value: string) {
  out.push({ type, label: LABELS[type], start, end, value, preview: maskValue(value) });
}

// Merge overlapping matches, keeping the higher-priority (more specific) one.
function mergeMatches(raw: SecretMatch[]): SecretMatch[] {
  const sorted = raw.slice().sort((a, b) => a.start - b.start || PRIORITY[b.type] - PRIORITY[a.type]);
  const kept: SecretMatch[] = [];
  for (const m of sorted) {
    const last = kept[kept.length - 1];
    if (last && m.start < last.end) {
      // Overlap: replace the kept one only if this is strictly higher priority
      // AND at least as long (avoid a tiny high-priority hit swallowing a block).
      if (PRIORITY[m.type] > PRIORITY[last.type] && m.end - m.start >= last.end - last.start) {
        kept[kept.length - 1] = m;
      }
      continue;
    }
    kept.push(m);
  }
  return kept;
}

const MAX_SCAN_CHARS = 100_000;

/**
 * Scans text for secret patterns entirely on-device. Returns match spans (for
 * local redaction/preview) plus the distinct set of detected types.
 */
export function scanForSecrets(input: string): ScanResult {
  const text = input.length > MAX_SCAN_CHARS ? input.slice(0, MAX_SCAN_CHARS) : input;
  const raw: SecretMatch[] = [];

  // 1) Structured, high-confidence detectors.
  for (const det of REGEX_DETECTORS) {
    det.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = det.re.exec(text)) !== null) {
      if (m[0].length === 0) {
        det.re.lastIndex++;
        continue;
      }
      const type = det.refine ? det.refine(m[0]) : det.type;
      pushMatch(raw, type, m.index, m.index + m[0].length, m[0]);
    }
  }

  // 2) Assignment / .env lines with secret-looking keys, plus generic
  //    high-entropy values. Processed line-by-line so offsets stay accurate.
  let offset = 0;
  for (const line of text.split(/\r?\n/)) {
    const am = ASSIGN_RE.exec(line);
    if (am) {
      const key = am[1];
      let value = am[2];
      // Strip surrounding quotes from the value, adjusting the span.
      let valStartInLine = line.indexOf(value, key.length);
      const quoted = /^(['"]).*\1$/.test(value);
      if (quoted) {
        value = value.slice(1, -1);
        valStartInLine += 1;
      }
      if (value.length > 0 && !/\s/.test(value) && !isTrivialValue(value)) {
        const keyLooksSecret = SECRET_KEY_RE.test(key);
        const looksHighValue =
          value.length >= 16 &&
          shannonEntropy(value) >= 3.5 &&
          hasMixedCaseDigit(value) &&
          !/^https?:\/\//i.test(value);
        // A secret-looking key flags almost any non-trivial value (covers weak
        // passwords like DB_PASSWORD=hunter2). A plain key needs a value that
        // genuinely looks like a secret, so URLs/hosts aren't flagged.
        if ((keyLooksSecret && value.length >= 6) || looksHighValue) {
          const start = offset + valStartInLine;
          pushMatch(raw, 'env_secret', start, start + value.length, value);
        }
      }
    } else {
      // 3) Standalone high-entropy token on a line of its own (a pasted key or
      //    password with no assignment context). Requires MIXED case + digits
      //    so single-case hashes, hex, UUIDs, and prose are not flagged.
      const t = line.trim();
      if (
        t.length >= 24 &&
        !/\s/.test(t) &&
        shannonEntropy(t) >= 3.7 &&
        hasMixedCaseDigit(t) &&
        !/^https?:\/\//i.test(t) &&
        !/@/.test(t)
      ) {
        const start = offset + line.indexOf(t);
        pushMatch(raw, 'generic_secret', start, start + t.length, t);
      }
    }
    offset += line.length + 1; // +1 for the split newline
  }

  const matches = mergeMatches(raw);
  const types = Array.from(new Set(matches.map((m) => m.type)));
  return { matches, types };
}

/** Replace every detected span with a redaction marker. */
export function redact(text: string, matches: SecretMatch[]): string {
  if (matches.length === 0) return text;
  const ordered = matches.slice().sort((a, b) => a.start - b.start);
  let out = '';
  let cursor = 0;
  for (const m of ordered) {
    if (m.start < cursor) continue; // skip any residual overlap
    out += text.slice(cursor, m.start) + '[REDACTED]';
    cursor = m.end;
  }
  out += text.slice(cursor);
  return out;
}

/** Convenience: does this text contain any detectable secret? */
export function containsSecret(text: string): boolean {
  return scanForSecrets(text).matches.length > 0;
}
