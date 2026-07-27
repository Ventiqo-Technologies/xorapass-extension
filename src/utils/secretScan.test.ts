import { describe, it, expect } from 'vitest';
import { scanForSecrets, redact, maskValue, containsSecret, SecretType } from './secretScan';

// All secret-looking values below are FAKE / structurally-valid examples used
// only to exercise the detector. None are real credentials.

function typesOf(text: string): SecretType[] {
  return scanForSecrets(text).types.sort();
}

describe('scanForSecrets — true positives', () => {
  it('detects an AWS access key', () => {
    expect(typesOf('key is AKIAIOSFODNN7EXAMPLE here')).toContain('aws_access_key');
  });

  it('detects a GitHub token', () => {
    expect(typesOf('ghp_1234567890abcdefABCDEF1234567890abcd')).toContain('github_token');
  });

  it('detects a fine-grained GitHub PAT', () => {
    expect(typesOf('github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz1234567890')).toContain('github_token');
  });

  it('detects a Stripe secret key', () => {
    expect(typesOf('sk_live_4eC39HqLyjWDarjtT1zdp7dc')).toContain('stripe_key');
  });

  it('does NOT flag a Stripe publishable key', () => {
    // pk_ keys are not secret.
    expect(typesOf('pk_live_4eC39HqLyjWDarjtT1zdp7dc')).not.toContain('stripe_key');
  });

  it('detects a JWT', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    expect(typesOf(jwt)).toContain('jwt');
  });

  it('detects a Google API key', () => {
    expect(typesOf('AIzaSyD-1234567890abcdefghijklmnopqrstu')).toContain('google_api_key');
  });

  it('detects a Slack token', () => {
    expect(typesOf('xoxb-1234567890-abcdefghijklmnop')).toContain('slack_token');
  });

  it('detects an OpenAI-style key', () => {
    expect(typesOf('sk-proj-abcdEFGH1234ijklMNOP5678qrstUVWX')).toContain('llm_api_key');
  });

  it('detects an Anthropic-style key', () => {
    expect(typesOf('sk-ant-api03-abcdEFGH1234ijklMNOP5678qrstUVWXyz')).toContain('llm_api_key');
  });

  it('detects a PEM private key block', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
    expect(typesOf(pem)).toContain('private_key');
  });

  it('detects an OpenSSH private key as ssh_private_key', () => {
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n-----END OPENSSH PRIVATE KEY-----';
    expect(typesOf(pem)).toContain('ssh_private_key');
  });

  it('detects a partial private-key paste (header only)', () => {
    expect(typesOf('-----BEGIN EC PRIVATE KEY-----')).toContain('private_key');
  });

  it('detects a database URL with credentials', () => {
    expect(typesOf('postgres://admin:S3cr3tPassw0rd@db.example.com:5432/prod')).toContain('database_url');
  });

  it('detects a secret in an assignment / .env line', () => {
    expect(typesOf('DB_PASSWORD=hunter2trombone')).toContain('env_secret');
  });

  it('detects a quoted .env value', () => {
    expect(typesOf('API_KEY="abcd1234EFGH5678ijkl"')).toContain('env_secret');
  });

  it('detects a standalone high-entropy mixed-case token', () => {
    expect(typesOf('Xk9pLm2Qr7Ts4Vw8Zy3Bc6Nf1Hj5Dg')).toContain('generic_secret');
  });
});

describe('scanForSecrets — false-positive avoidance', () => {
  const benign = [
    'Please summarize this document about our quarterly earnings for me.',
    'Visit https://example.com/docs/getting-started?ref=home for details.',
    'Contact john.doe@example.com or jane@example.org about the meeting.',
    '550e8400-e29b-41d4-a716-446655440000', // a UUID
    'The quick brown fox jumps over the lazy dog near the riverbank today.',
    'PORT=8080',
    'DEBUG=true',
    'HOST=db.internal.example.com',
    'BASE_URL=https://api.example.com',
    'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', // a 32-char lowercase hex (md5-like)
    'function calculateTotal(items) { return items.reduce((a, b) => a + b, 0); }',
  ];

  for (const text of benign) {
    it(`does not flag: ${text.slice(0, 40)}`, () => {
      expect(scanForSecrets(text).matches).toHaveLength(0);
    });
  }
});

describe('redact', () => {
  it('replaces detected secrets with a marker and leaves surrounding text', () => {
    const text = 'my key is AKIAIOSFODNN7EXAMPLE and nothing else';
    const { matches } = scanForSecrets(text);
    const out = redact(text, matches);
    expect(out).toBe('my key is [REDACTED] and nothing else');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('redacts multiple secrets in one string', () => {
    const text = 'AKIAIOSFODNN7EXAMPLE then sk_live_4eC39HqLyjWDarjtT1zdp7dc done';
    const { matches } = scanForSecrets(text);
    const out = redact(text, matches);
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).not.toContain('sk_live_4eC39HqLyjWDarjtT1zdp7dc');
    expect((out.match(/\[REDACTED\]/g) || []).length).toBe(2);
  });
});

describe('maskValue', () => {
  it('never reveals the full value', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    const masked = maskValue(secret);
    expect(masked).not.toBe(secret);
    expect(masked).not.toContain('OSFODNN7');
    expect(masked).toContain('…');
  });

  it('fully masks very short values', () => {
    expect(maskValue('abc')).toMatch(/^•+$/);
  });
});

describe('scanForSecrets — result shape', () => {
  it('types list contains no raw secret values', () => {
    const { types } = scanForSecrets('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(types)).not.toContain('AKIA');
  });

  it('containsSecret is a boolean convenience', () => {
    expect(containsSecret('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(containsSecret('just some ordinary words here')).toBe(false);
  });
});
