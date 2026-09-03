import { describe, it, expect } from 'vitest';
import {
  assessDomainRisk,
  decodePunycode,
  decodeHostnamePunycode,
  toHomoglyphSkeleton,
  damerauLevenshtein,
  extractBrandName,
  extractBrandProfiles,
} from './domainRisk';

describe('RFC 3492 Punycode Decoder', () => {
  it('decodes simple ASCII and internationalized labels', () => {
    // "münchen" in punycode is "mnchen-3ya"
    expect(decodePunycode('mnchen-3ya')).toBe('münchen');
    // "apple" with Cyrillic 'а' (U+0430) -> "pple-43d"
    expect(decodePunycode('pple-43d')).toBe('\u0430pple');
  });

  it('decodes full hostnames with xn-- labels', () => {
    expect(decodeHostnamePunycode('xn--pple-43d.com')).toBe('\u0430pple.com');
    expect(decodeHostnamePunycode('login.example.com')).toBe('login.example.com');
  });
});

describe('Homoglyph Normalization', () => {
  it('maps Cyrillic lookalikes to Latin equivalents', () => {
    // Cyrillic 'а' (\u0430) -> 'a', Cyrillic 'о' (\u043E) -> 'o'
    const cyrillicGoogle = '\u0433\u043E\u043E\u0433\u043B\u0435'; // Cyrillic lookalike for google
    expect(toHomoglyphSkeleton('\u0430pple')).toBe('apple');
  });

  it('maps leet speak characters', () => {
    expect(toHomoglyphSkeleton('str1pe')).toBe('strlpe');
    expect(toHomoglyphSkeleton('p4yp4l')).toBe('paypal');
  });
});

describe('Damerau-Levenshtein Distance', () => {
  it('detects single transposition', () => {
    expect(damerauLevenshtein('stripe', 'strpie')).toBe(1);
    expect(damerauLevenshtein('paypal', 'payapl')).toBe(1);
  });
  it('detects insertions and deletions', () => {
    expect(damerauLevenshtein('google', 'gooogle')).toBe(1);
    expect(damerauLevenshtein('stripe', 'stripp')).toBe(1);
  });
});

describe('Brand Extraction', () => {
  it('extracts brand names and profiles', () => {
    expect(extractBrandName('https://login.stripe.com/dashboard')).toBe('stripe');
    expect(extractBrandName('https://paypal.co.uk')).toBe('paypal');

    const profiles = extractBrandProfiles(['https://stripe.com', 'https://paypal.co.uk']);
    expect(profiles).toHaveLength(2);
    expect(profiles[0].brand).toBe('stripe');
    expect(profiles[1].brand).toBe('paypal');
  });
});

describe('Domain Risk Assessment — Acceptance Criteria', () => {
  const savedVaultHosts = [
    'https://stripe.com',
    'https://paypal.com',
    'https://accounts.google.com',
    'https://github.com',
    'https://apple.com',
  ];

  it('ALLOWS exact and legitimate subdomains with score 0', () => {
    const resExact = assessDomainRisk('stripe.com', savedVaultHosts);
    expect(resExact.decision).toBe('allow');
    expect(resExact.riskScore).toBe(0);
    expect(resExact.riskLevel).toBe('safe');

    const resSub = assessDomainRisk('dashboard.stripe.com', savedVaultHosts);
    expect(resSub.decision).toBe('allow');
    expect(resSub.riskScore).toBe(0);
  });

  it('WARNS on HTTP even when the domain has no threat-intel signals', () => {
    const res = assessDomainRisk('example.com', [], [], 'http://example.com/login');
    expect(res.decision).toBe('warn');
    expect(res.riskScore).toBe(30);
    expect(res.reasons).toContain('This site is using unencrypted HTTP instead of HTTPS.');
    expect(res.signals.isInsecureTransport).toBe(true);
  });

  it('BLOCKS brand keyword abuse: stripe-login.example for stripe.com', () => {
    const res = assessDomainRisk('stripe-login.example', savedVaultHosts);
    expect(res.decision).toBe('block');
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
    expect(res.matchedTarget).toBe('stripe.com');
    expect(res.reasons.some((r) => r.toLowerCase().includes('brand keyword abuse'))).toBe(true);
    expect(res.reasons.some((r) => r.includes('stripe'))).toBe(true);
  });

  it('BLOCKS other brand keyword variations (e.g. login-stripe.com, stripe-verify.net)', () => {
    const res1 = assessDomainRisk('login-stripe.com', savedVaultHosts);
    expect(res1.decision).toBe('block');
    expect(res1.matchedTarget).toBe('stripe.com');

    const res2 = assessDomainRisk('paypal-security-account.org', savedVaultHosts);
    expect(res2.decision).toBe('block');
    expect(res2.matchedTarget).toBe('paypal.com');
  });

  it('BLOCKS Punycode / IDN homograph domains', () => {
    // xn--pple-43d.com is Cyrillic 'а' + 'pple.com'
    const resPuny = assessDomainRisk('xn--pple-43d.com', savedVaultHosts);
    expect(resPuny.decision).toBe('block');
    expect(resPuny.riskLevel).toBe('critical');
    expect(resPuny.matchedTarget).toBe('apple.com');
    expect(resPuny.signals.hasPunycode).toBe(true);
    expect(resPuny.reasons.some((r) => r.includes('Punycode/IDN homograph'))).toBe(true);
  });

  it('BLOCKS or WARNS on typosquatting domains (e.g. paypa1.com, strpie.com)', () => {
    const resTypo1 = assessDomainRisk('paypa1.com', savedVaultHosts);
    expect(resTypo1.decision).toBe('block');
    expect(resTypo1.matchedTarget).toBe('paypal.com');
    expect(resTypo1.reasons.some((r) => r.includes('Typosquatting'))).toBe(true);

    const resTypo2 = assessDomainRisk('strpie.com', savedVaultHosts);
    expect(resTypo2.decision).toBe('block');
    expect(resTypo2.matchedTarget).toBe('stripe.com');
  });

  it('BLOCKS or WARNS on suspicious TLD changes (e.g. paypal.xyz, paypal.top)', () => {
    const resTld = assessDomainRisk('paypal.xyz', savedVaultHosts);
    expect(['warn', 'block']).toContain(resTld.decision);
    expect(resTld.matchedTarget).toBe('paypal.com');
    expect(resTld.reasons.some((r) => r.includes('Suspicious TLD change'))).toBe(true);
  });

  it('ALLOWS false positives when explicitly allowlisted by policy', () => {
    const allowlist = ['stripe-login.example', 'internal-staging.stripe-test.com'];
    const res = assessDomainRisk('stripe-login.example', savedVaultHosts, allowlist);
    expect(res.decision).toBe('allow');
    expect(res.isAllowlisted).toBe(true);
    expect(res.riskScore).toBe(0);
    expect(res.reasons.some((r) => r.includes('allowlisted'))).toBe(true);
  });

  it('produces explainable signals in the risk assessment', () => {
    const res = assessDomainRisk('stripe-login.example', savedVaultHosts);
    expect(res.signals.brandAbuse).toBeDefined();
    expect(res.signals.brandAbuse?.brand).toBe('stripe');
    expect(res.signals.suspiciousKeywords).toContain('login');
    expect(res.reasons.length).toBeGreaterThan(0);
  });

  it('does not flag unrelated benign sites', () => {
    const res = assessDomainRisk('wikipedia.org', savedVaultHosts);
    expect(res.decision).toBe('allow');
    expect(res.riskScore).toBe(0);
  });
});
