import { describe, expect, it } from 'vitest';
import { analyzeEmailLink, isEspTrackingHost, summarizeEmailLocal } from './emailGuard';
import { analyzeEmailSender } from './webmailGuard';
import { emailInsightSummary, normalizeEmailScanResult } from './emailScanResult';

describe('email evidence boundaries', () => {
  it.each([['Google', 'google.co.uk'], ['Google', 'google.co.jp'], ['Amazon', 'amazon.in'], ['Amazon', 'amazon.com.au']])('retains explicitly cataloged regional %s sender %s', (brand, domain) => {
    expect(analyzeEmailSender(`${brand} Security <notice@${domain}>`).isImpersonation).toBe(false);
  });
  it('does not excuse a deceptive destination because From claims the displayed domain', () => {
    expect(analyzeEmailLink('google.com', 'https://credential-collector.example/login', [], 'google.com')?.level).toBe('danger');
  });
  it.each(['sendib-attacker.com', 'acems-evil.com', 'cmail-scam.com'])('does not guess ESP ownership for %s', host => {
    expect(isEspTrackingHost(host)).toBe(false);
    expect(analyzeEmailLink('google.com', `https://${host}/login`)?.level).toBe('danger');
  });
  it('keeps explicit ESP redirects and known sister domains working', () => {
    expect(isEspTrackingHost('click.resend-links.com')).toBe(true);
    expect(analyzeEmailLink('google.com', 'https://mail.googlemail.com/account')).toBeNull();
  });
  it.each(['paypalmail.com', 'paypal.xyz', 'paypal.com.evil.example'])('does not trust %s as a PayPal sender', domain => {
    expect(analyzeEmailSender(`PayPal Security <notice@${domain}>`).isImpersonation).toBe(true);
  });
  it('keeps local danger when the AI result contradicts known domain association', () => {
    const local = summarizeEmailLocal({ sender: 'Google <notice@google.com>', attachments: ['invoice.pdf.exe'], links: [] });
    const ai = normalizeEmailScanResult({ verdict: 'scam', risk_score: 90, impersonated_brand: 'google', sender_matches_brand: false }, 'notice@google.com');
    expect(ai.verdict).toBe('unavailable');
    expect(emailInsightSummary(local, ai).level).toBe('danger');
  });
});
