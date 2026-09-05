// Regressions for the phishing-protection audit fixes. Each block names the
// concrete failure it locks out, so a future refactor that reintroduces one
// fails here rather than in production.
import { describe, it, expect } from 'vitest';
import {
  registrableDomain,
  isDomainMatch,
  stripPublicSuffix,
} from './siteTrust';
import {
  assessDomainRisk,
  hasConfusableChars,
  toHomoglyphSkeleton,
} from './domainRisk';
import { mergeLocalAndRemoteRisk, type RemoteDomainRiskResponse } from './domainRiskService';

describe('shared-tenant hosting suffixes', () => {
  it('treats each tenant of a shared host as its own registrable domain', () => {
    expect(registrableDomain('evil.github.io')).toBe('evil.github.io');
    expect(registrableDomain('victim.github.io')).toBe('victim.github.io');
    expect(registrableDomain('app.tenant.vercel.app')).toBe('tenant.vercel.app');
    expect(registrableDomain('acme.atlassian.net')).toBe('acme.atlassian.net');
  });

  it('does not offer one tenant credentials on another tenant', () => {
    // The bug: both reduced to "github.io", so isDomainMatch returned true and
    // a credential saved for victim.github.io was autofilled on evil.github.io.
    expect(isDomainMatch('evil.github.io', 'https://victim.github.io/login')).toBe(false);
    expect(isDomainMatch('evil.pages.dev', 'https://victim.pages.dev')).toBe(false);
    expect(isDomainMatch('attacker.vercel.app', 'https://real.vercel.app')).toBe(false);
  });

  it('still matches a tenant against itself and its subdomains', () => {
    expect(isDomainMatch('victim.github.io', 'https://victim.github.io')).toBe(true);
    expect(isDomainMatch('docs.victim.github.io', 'https://victim.github.io')).toBe(true);
  });

  it('leaves ordinary and ccTLD domains alone', () => {
    expect(registrableDomain('login.example.com')).toBe('example.com');
    expect(registrableDomain('login.example.co.uk')).toBe('example.co.uk');
    expect(isDomainMatch('login.example.com', 'https://example.com')).toBe(true);
  });
});

describe('stripPublicSuffix', () => {
  it('removes the registry-controlled part only', () => {
    expect(stripPublicSuffix('login.example.co.uk')).toBe('login.example');
    expect(stripPublicSuffix('paypa1.com')).toBe('paypa1');
    expect(stripPublicSuffix('evil.github.io')).toBe('evil');
  });
});

describe('homograph detection vs leet substitution', () => {
  it('does not treat digits as evidence of a homograph attack', () => {
    // toHomoglyphSkeleton maps '3'->'e' and '0'->'o', so comparing a hostname
    // to its own skeleton reported true for perfectly ordinary hosts.
    expect(toHomoglyphSkeleton('web3')).not.toBe('web3');
    expect(hasConfusableChars('web3.example.com')).toBe(false);
    expect(hasConfusableChars('s3-backup.example.com')).toBe(false);
  });

  it('still detects non-ASCII confusables', () => {
    expect(hasConfusableChars('pаypal.com')).toBe(true); // Cyrillic a
    expect(hasConfusableChars('gοogle.com')).toBe(true); // Greek omicron
  });

  it('does not score an ordinary digit-bearing host as a homograph attack', () => {
    const risk = assessDomainRisk('web3.example.com', ['https://example.org'], [], 'https://web3.example.com');
    expect(risk.signals.isHomograph).toBe(false);
  });

  it('still blocks a real Cyrillic lookalike of a saved site', () => {
    const risk = assessDomainRisk('pаypal.com', ['https://paypal.com'], [], 'https://pаypal.com');
    expect(risk.decision).toBe('block');
    expect(risk.signals.isHomograph).toBe(true);
  });
});

describe('allowlist must not override an admin policy', () => {
  const allowlisted: DomainRiskAssessmentLike = {
    pageHostname: 'blocked.example',
    registrableDomain: 'blocked.example',
    riskScore: 0,
    riskLevel: 'safe',
    decision: 'allow',
    reasons: [],
    matchedTarget: null,
    isAllowlisted: true,
    signals: {
      isExactMatch: false,
      isSubdomainMatch: false,
      isSameRegistrableDomain: false,
      hasPunycode: false,
      isHomograph: false,
      suspiciousKeywords: [],
      isInsecureTransport: false,
      isHighRiskTld: false,
      subdomainCount: 2,
    },
  };

  const remote = (policyEnforced: boolean): RemoteDomainRiskResponse => ({
    decision: 'block',
    risk_score: 95,
    risk_level: 'critical',
    reasons: ['Blocked by organisation policy'],
    reason_codes: ['POLICY_BLOCKLIST'],
    policy_enforced: policyEnforced,
  });

  it('lets a personal allowlist suppress ordinary heuristic noise', () => {
    const merged = mergeLocalAndRemoteRisk(allowlisted as never, remote(false));
    expect(merged.decision).toBe('allow');
  });

  it('does NOT let a personal allowlist suppress a policy-enforced block', () => {
    const merged = mergeLocalAndRemoteRisk(allowlisted as never, remote(true));
    expect(merged.decision).toBe('block');
    expect(merged.riskScore).toBe(95);
  });
});

// Local structural alias so the fixture above stays readable.
type DomainRiskAssessmentLike = Parameters<typeof mergeLocalAndRemoteRisk>[0];
