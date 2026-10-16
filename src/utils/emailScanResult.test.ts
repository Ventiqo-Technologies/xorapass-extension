import { describe, expect, it } from 'vitest';
import { emailInsightSummary, normalizeEmailScanResult } from './emailScanResult';
import { summarizeEmailLocal } from './emailGuard';

describe('email scan API validation', () => {
  it.each([
    null, [], {}, { verdict: 'trusted', risk_score: 0 }, { verdict: 'legit' },
    { verdict: 'legit', risk_score: '0' }, { verdict: 'legit', risk_score: NaN },
    { verdict: 'legit', risk_score: Infinity }, { verdict: 'legit', risk_score: -1 },
    { verdict: 'legit', risk_score: 0.1 }, { verdict: 'legit', risk_score: 101 },
    { verdict: 'legit', risk_score: 90 }, { verdict: 'scam', risk_score: 0 },
    { verdict: 'legit', risk_score: 0, red_flags: 'safe' },
    { verdict: 'legit', risk_score: 0, links: [null] },
    { verdict: 'legit', risk_score: 0, sender_matches_brand: 'true' },
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
