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

  it('marks threatIntel status as inactive when signals are absent or unavailable', () => {
    const report = buildSiteSafetyReport({
      url: 'https://example.com',
      title: 'Example',
      savedDomains: [],
    });

    expect(report.threatIntel.status).toBe('inactive');
    expect(report.threatIntel.clean).toBe(false);
    expect(report.threatIntel.label).toBe('Threat Feeds Inactive');
  });

  it('marks threatIntel status as clean when feeds confirm clean status', () => {
    const report = buildSiteSafetyReport({
      url: 'https://example.com',
      title: 'Example',
      savedDomains: [],
      riskAssessment: {
        domain: 'example.com',
        threat_intel_signals: {
          google_web_risk: 'clean',
        },
        risk_score: 0,
        risk_level: 'safe',
        reasons: [],
      },
    });

    expect(report.threatIntel.status).toBe('clean');
    expect(report.threatIntel.clean).toBe(true);
    expect(report.threatIntel.label).toBe('Threat Feeds Clean');
  });

  it('marks threatIntel status as alert when feeds report malware or threat hit', () => {
    const report = buildSiteSafetyReport({
      url: 'https://malicious-site.com',
      title: 'Malicious',
      savedDomains: [],
      riskAssessment: {
        domain: 'malicious-site.com',
        threat_intel_signals: {
          google_web_risk: 'malware_hit',
        },
        risk_score: 95,
        risk_level: 'critical',
        reasons: ['Google Web Risk malware hit'],
      },
    });

    expect(report.threatIntel.status).toBe('alert');
    expect(report.threatIntel.clean).toBe(false);
    expect(report.threatIntel.label).toBe('Threat Intelligence Alert');
  });

  it('marks threatIntel status as clean when one provider is clean even if another is unavailable', () => {
    const report = buildSiteSafetyReport({
      url: 'https://example.com',
      title: 'Example',
      savedDomains: [],
      riskAssessment: {
        domain: 'example.com',
        threat_intel_signals: {
          google_web_risk: 'clean',
          cloudflare_radar: 'provider_unavailable',
        },
        risk_score: 0,
        risk_level: 'safe',
        reasons: [],
      },
    });

    expect(report.threatIntel.status).toBe('clean');
    expect(report.threatIntel.clean).toBe(true);
    expect(report.threatIntel.label).toBe('Threat Feeds Clean');
  });

  it('marks threatIntel status as inactive when all configured providers are unavailable', () => {
    const report = buildSiteSafetyReport({
      url: 'https://example.com',
      title: 'Example',
      savedDomains: [],
      riskAssessment: {
        domain: 'example.com',
        threat_intel_signals: {
          google_web_risk: 'provider_unavailable',
          cloudflare_radar: 'provider_unavailable',
        },
        risk_score: 0,
        risk_level: 'safe',
        reasons: [],
      },
    });

    expect(report.threatIntel.status).toBe('inactive');
    expect(report.threatIntel.clean).toBe(false);
    expect(report.threatIntel.label).toBe('Threat Feeds Inactive');
  });
});
