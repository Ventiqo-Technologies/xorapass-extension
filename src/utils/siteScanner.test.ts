import { describe, it, expect } from 'vitest';
import { buildSiteSafetyReport } from './siteScanner';

describe('siteScanner', () => {
  it('correctly marks a verified domain as safe with autofill allowed', () => {
    const report = buildSiteSafetyReport({
      url: 'https://github.com/login',
      title: 'Sign in to GitHub',
      savedDomains: ['github.com', 'google.com'],
      scriptCount: 5,
      externalOriginsCount: 2,
    });

    expect(report.hostname).toBe('github.com');
    expect(report.verdict).toBe('safe');
    expect(report.riskScore).toBe(0);
    expect(report.encryption.isHttps).toBe(true);
    expect(report.domainAuthenticity.status).toBe('match');
    expect(report.credentialGuard.status).toBe('autofill_allowed');
  });

  it('flags lookalike domains and blocks autofill with high risk', () => {
    const report = buildSiteSafetyReport({
      url: 'https://github-login-verify.com/auth',
      title: 'GitHub Verification',
      savedDomains: ['github.com'],
      scriptCount: 8,
    });

    expect(report.verdict).toBe('danger');
    expect(report.riskScore).toBeGreaterThanOrEqual(70);
    expect(report.domainAuthenticity.status).toBe('lookalike');
    expect(report.domainAuthenticity.matchedTarget).toBe('github.com');
    expect(report.credentialGuard.status).toBe('autofill_blocked');
  });

  it('marks unencrypted HTTP as a caution indicator', () => {
    const report = buildSiteSafetyReport({
      url: 'http://example.org',
      title: 'Example',
      savedDomains: [],
    });

    expect(report.encryption.isHttps).toBe(false);
    expect(report.verdict).toBe('caution');
    expect(report.riskScore).toBeGreaterThanOrEqual(30);
  });
});
