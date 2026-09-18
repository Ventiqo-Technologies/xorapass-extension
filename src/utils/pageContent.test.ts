import { describe, it, expect } from 'vitest';
import { redactText, detectScamCues, shouldAiScan } from './pageContent';
import { coerceShieldConfig } from './shieldConfig';

describe('page text redaction', () => {
  it('strips personal data before anything leaves the device', () => {
    const out = redactText(
      'Call +1 (800) 555-0199 or mail jane@example.com, order 12345678, https://x.example/pay?token=SECRET#f',
      500
    );
    for (const leaked of ['555-0199', 'jane@', '12345678', 'SECRET']) expect(out).not.toContain(leaked);
    expect(out).toContain('[phone]');
    expect(out).toContain('[email]');
    expect(out).toContain('[number]');
    expect(out).toContain('https://x.example/pay');
  });

  it('truncates', () => {
    expect(redactText('a'.repeat(50), 10)).toHaveLength(10);
  });
});

describe('local scam cues', () => {
  const cases: [string, string][] = [
    ['WARNING! Your computer is infected. Call Microsoft Support toll-free now', 'tech_support'],
    ['Verify you are human: press Win + R, then press Ctrl + V and Enter', 'clickfix'],
    ['Official giveaway: send 0.5 BTC and receive double back. Double your bitcoin today!', 'crypto_scam'],
    ["Congratulations! You've won an iPhone 16. Claim your prize now", 'prize_scam'],
    ['Your browser is out of date. Download the required update to continue', 'fake_download'],
    ['Guaranteed returns of 30% daily with our AI trading bot', 'investment_scam'],
    ['Closing down sale - 90% off everything! Payment only via gift cards', 'fake_shop'],
  ];
  for (const [text, cat] of cases) {
    it(`detects ${cat}`, () => {
      expect(detectScamCues(text)).toContain(cat);
    });
  }

  it('stays quiet on ordinary pages', () => {
    expect(detectScamCues('Welcome to our bakery. Fresh bread daily, open 8am to 6pm. Contact us for orders.')).toEqual([]);
    expect(detectScamCues('Sign in to your account. Forgot password? Create account.')).toEqual([]);
  });

  it('only scans when there is a reason to', () => {
    expect(shouldAiScan([], 0)).toBe(false);
    expect(shouldAiScan(['urgency'], 0)).toBe(false);
    expect(shouldAiScan(['urgency'], 15)).toBe(true);
    expect(shouldAiScan(['tech_support'], 0)).toBe(true);
    expect(shouldAiScan([], 30)).toBe(true);
  });
});

describe('ai_scan config', () => {
  it('defaults on and honours the remote switch', () => {
    expect(coerceShieldConfig({}).ai_scan.enabled).toBe(true);
    expect(coerceShieldConfig({ ai_scan: { enabled: false } }).ai_scan.enabled).toBe(false);
  });
});
