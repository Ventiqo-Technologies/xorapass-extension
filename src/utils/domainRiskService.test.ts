import { describe, it, expect, vi } from 'vitest';
import {
  checkDomainRiskRemote,
  getCachedRemoteRisk,
  mergeLocalAndRemoteRisk,
  type RemoteDomainRiskResponse,
} from './domainRiskService';
import type { DomainRiskAssessment } from './domainRisk';

describe('domainRiskService — Privacy & Zero-Knowledge Contract', () => {
  it('sends metadata only and NEVER sends raw secrets/passwords/vault keys', async () => {
    let capturedBody: any = null;

    const mockFetch = vi.fn().mockImplementation(async (url: string, init: any) => {
      capturedBody = JSON.parse(init.body);
      return {
        ok: true,
        json: async () => ({
          decision: 'block',
          risk_score: 95,
          risk_level: 'critical',
          reasons: ['Punycode homograph detected'],
          reason_codes: ['HOMOGRAPH_PUNYCODE_ATTACK'],
          safe_warning_message: 'Dangerous spoofing domain',
          matched_target: 'apple.com',
        }),
      };
    });

    const res = await checkDomainRiskRemote(
      'https://xn--pple-43d.com/login',
      'apple.com',
      {
        isLoginForm: true,
        hasPasswordField: true,
        hasMfaField: false,
        actionUrl: 'https://evil-harvest.xyz/steal',
        numInputs: 2,
      },
      {
        isAISession: false,
      },
      'high',
      mockFetch as any
    );

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(res).toBeDefined();
    expect(res?.decision).toBe('block');
    expect(res?.risk_score).toBe(95);

    // Verify request payload contract strictly
    expect(capturedBody).toBeDefined();
    expect(capturedBody.current_domain).toBe('xn--pple-43d.com');
    expect(capturedBody.saved_domain).toBe('apple.com');
    expect(capturedBody.credential_sensitivity).toBe('high');
    expect(capturedBody.form_context.is_login_form).toBe(true);

    // Strict Zero-Knowledge verifications
    expect(capturedBody.password).toBeUndefined();
    expect(capturedBody.username).toBeUndefined();
    expect(capturedBody.token).toBeUndefined();
    expect(capturedBody.secret).toBeUndefined();
    expect(capturedBody.vaultKey).toBeUndefined();
    expect(capturedBody.totp).toBeUndefined();
  });

  it('serves cached responses for repeated queries to avoid API latency', async () => {
    const mockFetch = vi.fn().mockImplementation(async () => ({
      ok: true,
      json: async () => ({
        decision: 'allow',
        risk_score: 0,
        risk_level: 'safe',
        reasons: [],
        reason_codes: [],
        matched_target: 'github.com',
      }),
    }));

    // First call (fetches remote)
    const first = await checkDomainRiskRemote('https://github.com', 'github.com', undefined, undefined, 'standard', mockFetch as any);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(first?.risk_score).toBe(0);

    // Second call (hits client cache)
    const second = await checkDomainRiskRemote('https://github.com', 'github.com', undefined, undefined, 'standard', mockFetch as any);
    expect(mockFetch).toHaveBeenCalledTimes(1); // Not called again!
    expect(second?.cached).toBe(true);
  });

  it('safely handles network errors and falls back without throwing', async () => {
    const brokenFetch = vi.fn().mockRejectedValue(new Error('Network Offline'));

    const res = await checkDomainRiskRemote('https://unreachable-backend-test.org', '', undefined, undefined, 'standard', brokenFetch as any);
    expect(res).toBeNull(); // Clean graceful fallback
  });
});

describe('mergeLocalAndRemoteRisk', () => {
  const baseLocal: DomainRiskAssessment = {
    pageHostname: 'paypa1.com',
    registrableDomain: 'paypa1.com',
    riskScore: 80,
    riskLevel: 'high',
    decision: 'block',
    reasons: ['Typosquatting detected'],
    matchedTarget: 'paypal.com',
    isAllowlisted: false,
    signals: {
      isExactMatch: false,
      isSubdomainMatch: false,
      isSameRegistrableDomain: false,
      hasPunycode: false,
      isHomograph: false,
      suspiciousKeywords: [],
      isHighRiskTld: false,
      subdomainCount: 2,
    },
  };

  it('upgrades decision and risk score if remote threat intel discovers higher severity', () => {
    const remote: RemoteDomainRiskResponse = {
      decision: 'block',
      risk_score: 95,
      risk_level: 'critical',
      reasons: ['Known phishing campaign threat intel blocklist'],
      reason_codes: ['THREAT_INTEL_PHISHING_CAMPAIGN'],
      matched_target: 'paypal.com',
    };

    const merged = mergeLocalAndRemoteRisk(baseLocal, remote);
    expect(merged.riskScore).toBe(95);
    expect(merged.riskLevel).toBe('critical');
    expect(merged.decision).toBe('block');
    expect(merged.reasons).toContain('Typosquatting detected');
    expect(merged.reasons).toContain('Known phishing campaign threat intel blocklist');
  });

  it('preserves allowlisted status when policy dictates domain is trusted', () => {
    const allowlistedLocal: DomainRiskAssessment = {
      ...baseLocal,
      isAllowlisted: true,
      decision: 'allow',
      riskScore: 0,
      riskLevel: 'safe',
      reasons: ['Allowlisted by policy'],
    };

    const remote: RemoteDomainRiskResponse = {
      decision: 'block',
      risk_score: 90,
      risk_level: 'critical',
      reasons: ['Third party report'],
      reason_codes: ['BLOCKED'],
    };

    const merged = mergeLocalAndRemoteRisk(allowlistedLocal, remote);
    expect(merged.isAllowlisted).toBe(true);
    expect(merged.decision).toBe('allow');
  });

  it('escalates confirmed threat intel phishing hit to block and interstitial', () => {
    const cleanLocal: DomainRiskAssessment = {
      pageHostname: 'mucopnexo.z13.web.core.windows.net',
      decision: 'allow',
      riskScore: 0,
      riskLevel: 'safe',
      reasons: [],
    };

    const remote: RemoteDomainRiskResponse = {
      decision: 'warn',
      risk_score: 40,
      risk_level: 'low',
      reasons: ['One or more threat-intel providers flag this domain as suspected phishing.'],
      reason_codes: ['THREAT_INTEL_PHISHING_HIT'],
      threat_intel_signals: { google_web_risk: 'phishing_hit' },
    };

    const merged = mergeLocalAndRemoteRisk(cleanLocal, remote);
    expect(merged.decision).toBe('block');
    expect(merged.riskScore).toBeGreaterThanOrEqual(85);
    expect(merged.riskLevel).toBe('high');
    expect(merged.showInterstitial).toBe(true);
  });

  it('escalates confirmed threat intel malware hit to block and interstitial', () => {
    const cleanLocal: DomainRiskAssessment = {
      pageHostname: 'malware-sample.pages.dev',
      decision: 'allow',
      riskScore: 10,
      riskLevel: 'safe',
      reasons: [],
    };

    const remote: RemoteDomainRiskResponse = {
      decision: 'warn',
      risk_score: 35,
      risk_level: 'low',
      reasons: ['One or more threat-intel providers flag this domain as likely distributing malware.'],
      reason_codes: ['THREAT_INTEL_MALWARE_HIT'],
      threat_intel_signals: { virustotal: 'malware_hit' },
    };

    const merged = mergeLocalAndRemoteRisk(cleanLocal, remote);
    expect(merged.decision).toBe('block');
    expect(merged.riskScore).toBeGreaterThanOrEqual(85);
    expect(merged.showInterstitial).toBe(true);
  });
});
