import { describe, it, expect } from 'vitest';
import { isDomainMatch, isUserContentHost, assessDomainRisk } from './siteTrust';
import { sanitizeUrlForRiskCheck, checkDomainRiskRemote, mergeLocalAndRemoteRisk } from './domainRiskService';
import { unwrapLink, isShortenerUrl, buildLinkVerdict } from './linkInspect';
import { buildSiteSafetyReport } from './siteScanner';

describe('customer-content hosts on trusted platforms', () => {
  it('recognises user-content hosts but not the platform logins', () => {
    expect(isUserContentHost('sites.google.com')).toBe(true);
    expect(isUserContentHost('evil.blob.core.windows.net')).toBe(true);
    expect(isUserContentHost('bucket.s3.amazonaws.com')).toBe(true);
    expect(isUserContentHost('accounts.google.com')).toBe(false);
    expect(isUserContentHost('login.windows.net')).toBe(false);
  });

  it('never offers a Google credential on sites.google.com', () => {
    expect(isDomainMatch('sites.google.com', 'https://accounts.google.com')).toBe(false);
    expect(isDomainMatch('mail.google.com', 'https://accounts.google.com')).toBe(true);
    expect(isDomainMatch('tenant-a.blob.core.windows.net', 'https://tenant-b.blob.core.windows.net')).toBe(false);
    expect(isDomainMatch('tenant-a.blob.core.windows.net', 'https://tenant-a.blob.core.windows.net/x')).toBe(true);
  });

  it('does not auto-trust a blob-hosted page as a known legitimate platform', () => {
    const risk = assessDomainRisk('office365-login.blob.core.windows.net', ['microsoft.com']);
    expect(risk.matchedTarget).not.toBe('windows.net');
    const legit = assessDomainRisk('login.windows.net', ['example.com']);
    expect(legit.matchedTarget).toBe('windows.net');
  });
});

describe('risk-check payload privacy', () => {
  it('strips query, fragment and userinfo', () => {
    expect(sanitizeUrlForRiskCheck('https://u:p@Example.com/reset?token=abc#x')).toBe('https://example.com/reset');
    expect(sanitizeUrlForRiskCheck('example.com')).toBe('https://example.com/');
    expect(sanitizeUrlForRiskCheck('javascript:alert(1)')).toBe('');
  });

  it('never sends a query string to the backend', async () => {
    let body: any = null;
    const fetchFn = (async (_url: string, init: any) => {
      body = JSON.parse(init.body);
      return { ok: true, json: async () => ({ decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [] }) };
    }) as unknown as typeof fetch;
    await checkDomainRiskRemote(
      'https://privacy-test.example/magic?token=SECRET#frag',
      '',
      { actionUrl: 'https://privacy-test.example/login?next=SECRET2' },
      undefined,
      'standard',
      fetchFn,
      async () => ''
    );
    expect(body.current_url).toBe('https://privacy-test.example/magic');
    expect(body.form_context.action_url).toBe('https://privacy-test.example/login');
    expect(JSON.stringify(body)).not.toContain('SECRET');
  });

  it('carries threat-intel signals through the merge', () => {
    const local = assessDomainRisk('example.org', ['github.com']);
    const merged = mergeLocalAndRemoteRisk(local, {
      decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [],
      threat_intel_signals: { google_web_risk: 'clean' },
    });
    expect(merged.threatIntelSignals).toEqual({ google_web_risk: 'clean' });
  });
});

describe('Link Guard', () => {
  it('unwraps mail and social redirectors offline', () => {
    expect(unwrapLink('https://www.google.com/url?q=https://evil.example/login&sa=D').url).toBe('https://evil.example/login');
    const safelink =
      'https://nam02.safelinks.protection.outlook.com/?url=' + encodeURIComponent('https://paypa1.com/x') + '&data=1';
    expect(unwrapLink(safelink).url).toBe('https://paypa1.com/x');
    expect(unwrapLink('https://l.facebook.com/l.php?u=' + encodeURIComponent('https://a.example/')).url).toBe('https://a.example/');
    expect(
      unwrapLink('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path&d=x').url
    ).toBe('https://evil.example/path');
    // Nested wrappers
    const inner = 'https://www.google.com/url?q=' + encodeURIComponent('https://evil.example/');
    const r = unwrapLink('https://l.facebook.com/l.php?u=' + encodeURIComponent(inner));
    expect(r.url).toBe('https://evil.example/');
    expect(r.hops).toHaveLength(2);
    // Refuses to unwrap to a non-web scheme
    expect(unwrapLink('https://www.google.com/url?q=javascript:alert(1)').url).toContain('google.com');
  });

  it('detects shorteners', () => {
    expect(isShortenerUrl('https://bit.ly/abc')).toBe(true);
    expect(isShortenerUrl('https://example.com/abc')).toBe(false);
  });

  it('flags a typosquat of a saved or well-known brand', () => {
    const risk = assessDomainRisk('paypa1.com', ['paypal.com']);
    const v = buildLinkVerdict({ finalUrl: 'https://paypa1.com/', risk, hops: 0, unresolvedShortener: false, isCustomScheme: false });
    expect(v.verdict).toBe('high_risk');
  });

  it('treats an unresolvable shortener as suspicious, not safe', () => {
    const risk = assessDomainRisk('bit.ly', ['paypal.com']);
    const v = buildLinkVerdict({ finalUrl: 'https://bit.ly/x', risk, hops: 0, unresolvedShortener: true, isCustomScheme: false });
    expect(v.verdict).toBe('suspicious');
  });
});

describe('Site Scanner inputs', () => {
  it('honours the user allowlist', () => {
    const report = buildSiteSafetyReport({
      url: 'https://github-login-verify.com/auth',
      savedDomains: ['github.com'],
      allowlist: ['github-login-verify.com'],
    });
    expect(report.verdict).toBe('safe');
  });

  it('respects a business policy over the user allowlist', () => {
    const report = buildSiteSafetyReport({
      url: 'https://github-login-verify.com/auth',
      savedDomains: ['github.com'],
      allowlist: ['github-login-verify.com'],
      riskAssessment: {
        decision: 'block', risk_score: 95, risk_level: 'critical', reasons: ['org policy'], reason_codes: [], policy_enforced: true,
      },
    });
    expect(report.verdict).toBe('danger');
  });

  it('produces no phishing verdict when Domain Risk is off for the account', () => {
    const report = buildSiteSafetyReport({
      url: 'https://github-login-verify.com/auth',
      savedDomains: ['github.com'],
      domainRiskEnabled: false,
    });
    expect(report.verdict).toBe('safe');
    expect(report.summary).toMatch(/off for this account/);
  });

  it('reads script origins and cross-origin form from page signals', () => {
    const report = buildSiteSafetyReport({
      url: 'https://example.com/',
      savedDomains: [],
      pageSignals: { external_script_origins: 4, form_action_cross_origin: true },
    });
    expect(report.trackersAndScripts.externalOriginsCount).toBe(4);
    expect(report.trackersAndScripts.hasCrossDomainForm).toBe(true);
    expect(report.trackersAndScripts.label).toBe('4 external script origins');
  });
});
