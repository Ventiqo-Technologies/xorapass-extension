import { describe, it, expect } from 'vitest';
import { analyzePromptSafety } from './promptSafety';

describe('analyzePromptSafety', () => {
  it('returns safe verdict when input is empty', () => {
    const res = analyzePromptSafety('');
    expect(res.verdict).toBe('safe');
    expect(res.riskScore).toBe(0);
    expect(res.extractedUrls).toHaveLength(0);
  });

  it('detects high-urgency scam text without links', () => {
    const text = 'Urgent: Your account is suspended due to suspicious activity. Action required within 24 hours.';
    const res = analyzePromptSafety(text);
    expect(res.threatSignals.length).toBeGreaterThan(0);
    expect(res.riskScore).toBeGreaterThanOrEqual(70);
    expect(res.verdict).toBe('phishing');
  });

  it('detects moderate urgency text as suspicious', () => {
    const text = 'Action required: Please reschedule delivery for your parcel.';
    const res = analyzePromptSafety(text);
    expect(res.threatSignals.length).toBeGreaterThan(0);
    expect(res.riskScore).toBeGreaterThanOrEqual(35);
    expect(res.verdict).toBe('suspicious');
  });

  it('detects brand mismatch when message mentions Telegram but points to unrelated domain', () => {
    const text = 'Your Telegram account has been flagged. Confirm here: https://m-zhifeixi.com.cn/article/10037.html';
    const res = analyzePromptSafety(text);
    expect(res.detectedBrands).toContain('Telegram');
    expect(res.extractedUrls).toContain('https://m-zhifeixi.com.cn/article/10037.html');
    expect(res.threatSignals.some((s) => s.includes('Brand mismatch'))).toBe(true);
    expect(res.verdict).toBe('phishing');
    expect(res.riskScore).toBeGreaterThanOrEqual(70);
  });

  it('extracts multi-part domains and paths without protocol', () => {
    const text = 'Visit m-zhifeixi.com.cn/article/10037.html immediately';
    const res = analyzePromptSafety(text);
    expect(res.extractedUrls[0]).toBe('m-zhifeixi.com.cn/article/10037.html');
  });

  it('does not flag legitimate brand domain as mismatch', () => {
    const text = 'Official Telegram web login: https://telegram.org/apps';
    const res = analyzePromptSafety(text);
    expect(res.detectedBrands).toContain('Telegram');
    expect(res.threatSignals.some((s) => s.includes('Brand mismatch'))).toBe(false);
    expect(res.verdict).toBe('safe');
  });

  it('detects obfuscated shortlinks', () => {
    const text = 'Claim your payout at bit.ly/free-reward';
    const res = analyzePromptSafety(text);
    expect(res.threatSignals.some((s) => s.includes('shortlink'))).toBe(true);
    expect(res.verdict).toBe('suspicious');
  });

  it('does not flag legitimate retailer product URLs with brand in path as brand mismatch', () => {
    const url = 'https://celltronics.lk/product-category/laptops/apple-laptops/';
    const res = analyzePromptSafety(url);
    expect(res.threatSignals.some((s) => s.includes('Brand mismatch'))).toBe(false);
    expect(res.verdict).toBe('safe');
    expect(res.riskScore).toBe(0);
  });

  it('flags fake shop brand impersonation link (https://amazongroceryhq.shop/) as phishing', () => {
    const text = 'Check out our special discounts here: https://amazongroceryhq.shop/';
    const res = analyzePromptSafety(text);
    expect(res.verdict).toBe('phishing');
    expect(res.riskScore).toBeGreaterThanOrEqual(85);
    expect(res.threatSignals.some((s) => s.includes('impersonates "amazon"'))).toBe(true);
  });
});

