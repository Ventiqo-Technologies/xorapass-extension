import { describe, expect, it } from 'vitest';
import { emailInsightSummary, normalizeEmailScanResult, emailScanHttpFailure, emailAIWarningCopy, EMAIL_SCAN_FAILURE_TEXT } from './emailScanResult';
import { summarizeEmailLocal } from './emailGuard';
import { BRAND_DOMAINS, senderDomainMatchesBrand, isSameBrandOrAlias } from './webmailGuard';

describe('email scan API validation', () => {
  it('rejects the Google screenshot contradiction using the real sender', () => {
    const result = { verdict: 'suspicious', risk_score: 45, impersonated_brand: 'google', sender_matches_brand: false, sender_domain: 'google.com' };
    expect(normalizeEmailScanResult(result, 'noreply-accounts@google.com')).toEqual({ verdict: 'unavailable', reason: 'inconsistent_evidence' });
    expect(EMAIL_SCAN_FAILURE_TEXT.inconsistent_evidence).toContain('On-device');
  });
  it('checks contradictions for every cataloged brand and domain, not just Google', () => {
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      for (const domain of domains) {
        expect(senderDomainMatchesBrand(brand, `notify.${domain}`)).toBe(true);
        expect(senderDomainMatchesBrand(brand, `${domain}.evil.example`)).toBe(false);
        const result = { verdict: 'scam', risk_score: 90, impersonated_brand: brand, sender_matches_brand: false };
        expect(normalizeEmailScanResult(result, `notice@notify.${domain}`).reason).toBe('inconsistent_evidence');
      }
    }
  });
  it('cannot authenticate a sender or erase a grounded warning through a matching domain', () => {
    const result = { verdict: 'scam', risk_score: 90, impersonated_brand: 'google', sender_matches_brand: true, sender_domain: 'google.com', red_flags: ['Threat or blackmail'] };
    expect(normalizeEmailScanResult(result, 'notice@google.com')).toEqual(result);
  });
  it('rejects stale or fabricated sender-domain metadata', () => {
    expect(normalizeEmailScanResult({ verdict: 'legit', risk_score: 0, sender_domain: 'google.com' }, 'notice@evil.example').reason).toBe('inconsistent_evidence');
  });
  it('preserves an independent confirmed threat even when model sender metadata contradicts the catalog', () => {
    const result = { verdict: 'phishing', risk_score: 90, confirmed_threat: true, impersonated_brand: 'google', sender_matches_brand: false, links: [{ index: 0, host: 'evil.example', reason: 'Known phishing site (threat intelligence)' }] };
    const normalized = normalizeEmailScanResult(result, 'notice@google.com');
    expect(normalized.verdict).toBe('phishing');
    expect(emailAIWarningCopy(normalized.verdict, normalized.confirmed_threat).title).toBe('Known dangerous link');
    expect(emailInsightSummary({ danger: false, cautions: 0, findings: [] }, normalized).summary).toContain('Known dangerous link');
  });
  it('never guesses brand ownership from a shared stem or mail suffix', () => {
    expect(isSameBrandOrAlias('paypal.com', 'paypalmail.com')).toBe(false);
    expect(isSameBrandOrAlias('google.com', 'google.xyz')).toBe(false);
    expect(senderDomainMatchesBrand('paypal', 'paypal.xyz')).toBe(false);
    for (const token of ['__proto__', 'constructor', 'toString']) {
      expect(senderDomainMatchesBrand(token, 'google.com')).toBe(false);
    }
  });
  it.each(['scam', 'phishing', 'suspicious'] as const)('labels %s as an email AI assessment, not confirmed fraud on a page', verdict => {
    const copy = emailAIWarningCopy(verdict);
    expect(copy.title).toContain('AI assessment');
    expect(copy.message).toContain('not proof');
    expect(copy.message).not.toMatch(/this page|is a scam|verified sender$/i);
  });
  it.each([[401, 'auth_required'], [403, 'not_available'], [429, 'rate_limited'], [500, 'service_unavailable'], [503, 'service_unavailable'], [400, 'error']] as const)('preserves the failure category for HTTP %s', (status, reason) => {
    const result = emailScanHttpFailure(status);
    expect(normalizeEmailScanResult(result)).toEqual({ verdict: 'unavailable', reason });
    expect(EMAIL_SCAN_FAILURE_TEXT[reason]).toMatch(/On-device/);
  });
  it('keeps missing-model, consent and metering failures actionable', () => {
    for (const reason of ['no_model', 'consent_required', 'metering_unavailable', 'network_error', 'auth_required']) {
      expect(EMAIL_SCAN_FAILURE_TEXT[reason]).toBeTruthy();
      expect(EMAIL_SCAN_FAILURE_TEXT[reason]).toMatch(/On-device/);
    }
  });
  it.each([
    null, [], {}, { verdict: 'trusted', risk_score: 0 }, { verdict: 'legit' },
    { verdict: 'legit', risk_score: '0' }, { verdict: 'legit', risk_score: NaN },
    { verdict: 'legit', risk_score: Infinity }, { verdict: 'legit', risk_score: -1 },
    { verdict: 'legit', risk_score: 0.1 }, { verdict: 'legit', risk_score: 101 },
    { verdict: 'legit', risk_score: 90 }, { verdict: 'scam', risk_score: 0 },
    { verdict: 'legit', risk_score: 0, red_flags: 'safe' },
    { verdict: 'legit', risk_score: 0, links: [null] },
    { verdict: 'legit', risk_score: 0, sender_matches_brand: 'true' },
    { verdict: 'phishing', risk_score: 90, confirmed_threat: 'true' },
    { verdict: 'legit', risk_score: 0, confirmed_threat: true },
    { verdict: 'phishing', risk_score: 90, confirmed_threat: true, links: [] },
    { verdict: 'legit', risk_score: 0, red_flags: ['Asks for payment'] },
    { verdict: 'phishing', risk_score: 90, links: [{ index: 20, host: 'evil.example', reason: 'bad' }] },
  ])('rejects malformed or inconsistent data: %j', value => {
    expect(normalizeEmailScanResult(value)).toEqual({ verdict: 'unavailable', reason: 'invalid_response' });
  });
  it.each(['phishing', 'scam', 'suspicious', 'legit'] as const)('accepts a bounded %s response', verdict => {
    const value = { verdict, risk_score: verdict === 'legit' ? 0 : 90 };
    expect(normalizeEmailScanResult(value)).toEqual(value);
  });
});

describe('email findings cannot be downgraded by AI', () => {
  const legit = normalizeEmailScanResult({ verdict: 'legit', risk_score: 0, sender_matches_brand: true });
  it.each([
    { sender: 'PayPal <alerts@evil.example>', links: [], attachments: [] },
    { sender: 'Team <team@example.com>', replyTo: 'pay@gmail.com', links: [], attachments: [] },
    { sender: 'Team <team@example.com>', links: [{ text: 'Sign in', href: 'https://127.0.0.1/login' }], attachments: [] },
    { sender: 'Team <team@example.com>', links: [], attachments: ['invoice.pdf.exe'] },
  ])('preserves deterministic danger: %j', input => {
    const local = summarizeEmailLocal(input);
    expect(local.danger).toBe(true);
    for (const ai of [legit, normalizeEmailScanResult({}), { verdict: 'unavailable' } as const]) {
      expect(emailInsightSummary(local, ai).level).toBe('danger');
      expect(emailInsightSummary(local, ai).summary).not.toMatch(/verified|no scam|nothing suspicious/i);
    }
  });
  it('preserves attachment caution even when AI finds no scam', () => {
    const local = summarizeEmailLocal({ sender: 'Team <team@example.com>', links: [], attachments: ['invoice.html'] });
    expect(local.cautions).toBe(1);
    expect(emailInsightSummary(local, legit).level).toBe('caution');
  });
  it('shows inconclusive rather than a green assurance on a failed check', () => {
    const local = summarizeEmailLocal({ sender: 'Team <team@example.com>', links: [], attachments: [] });
    expect(emailInsightSummary(local, normalizeEmailScanResult({}))).toEqual({ level: 'neutral', summary: 'AI check inconclusive — on-device checks still apply' });
    expect(emailInsightSummary(local, legit).summary).toContain('sender not authenticated');
  });
  it('allows an AI warning to raise a clean local result', () => {
    const local = summarizeEmailLocal({ sender: 'Team <team@example.com>', links: [], attachments: [] });
    expect(emailInsightSummary(local, { verdict: 'scam', risk_score: 90 }).level).toBe('danger');
    expect(emailInsightSummary(local, { verdict: 'suspicious', risk_score: 45 }).level).toBe('caution');
  });
});
