import { describe, it, expect } from 'vitest';
import {
  brandTokensIn,
  analyzeUrl,
  brandsFromResourceOrigins,
  looksLikeFakeBrowserChrome,
  isWorthAssessing,
  BRAND_LEXICON,
  type ChromeCandidate,
} from './pageSignals';

describe('brandTokensIn', () => {
  it('reports lexicon membership, never the text itself', () => {
    expect(brandTokensIn('Sign in to your PayPal account')).toEqual(['paypal']);
    expect(brandTokensIn('Microsoft 365 login')).toEqual(['microsoft']);
  });

  it('folds multi-word brand spellings', () => {
    expect(brandTokensIn('Office 365 sign in')).toEqual(['office365']);
    expect(brandTokensIn('Wells Fargo online banking')).toEqual(['wellsfargo']);
  });

  it('matches whole tokens only', () => {
    // "upside" must not match "ups"; "applesauce" must not match "apple".
    expect(brandTokensIn('upside down applesauce')).toEqual([]);
  });

  it('returns nothing for ordinary copy', () => {
    expect(brandTokensIn('Welcome to our internal staff portal')).toEqual([]);
    expect(brandTokensIn('')).toEqual([]);
  });
});

describe('analyzeUrl', () => {
  it('reads URL shape without carrying query values', () => {
    const s = analyzeUrl('https://login.secure.acct.evil.top/a/b/c?token=abc123');
    expect(s.subdomain_depth).toBe(3);
    expect(s.path_depth).toBe(3);
    expect(JSON.stringify(s)).not.toContain('abc123');
  });

  it('detects @-obfuscated authority', () => {
    // Everything before @ is userinfo; the real host is evil.top.
    expect(analyzeUrl('https://paypal.com@evil.top/login').has_at_symbol).toBe(true);
    expect(analyzeUrl('https://example.com/path?a=b@c').has_at_symbol).toBe(false);
  });

  it('detects IP hosts, punycode and odd ports', () => {
    expect(analyzeUrl('http://192.168.1.20/login').has_ip_host).toBe(true);
    expect(analyzeUrl('https://xn--pypal-4ve.com/').punycode_labels).toBe(1);
    expect(analyzeUrl('https://example.com:8443/').non_standard_port).toBe(true);
    expect(analyzeUrl('https://example.com/').non_standard_port).toBe(false);
  });

  it('flags a brand parked in the path rather than the domain', () => {
    expect(analyzeUrl('https://evil.top/paypal/verify').path_brand_tokens).toEqual(['paypal']);
  });

  it('survives an unparseable URL', () => {
    expect(analyzeUrl('not a url')).toEqual({});
  });
});

describe('brandsFromResourceOrigins', () => {
  it('flags a page hotlinking a real brand CDN', () => {
    const found = brandsFromResourceOrigins(
      ['https://www.paypalobjects.com/logo.png', 'https://paypal.com/assets/x.png', '/local.png'],
      'evil.top'
    );
    expect(found).toEqual(['paypal']);
  });

  it('ignores the page serving its own assets', () => {
    expect(brandsFromResourceOrigins(['https://cdn.paypal.com/logo.png'], 'paypal.com')).toEqual([]);
  });
});

describe('looksLikeFakeBrowserChrome', () => {
  const base: ChromeCandidate = {
    position: 'absolute',
    top: 40,
    width: 640,
    hasLockGlyph: false,
    hasUrlText: false,
    hasWindowControls: false,
  };

  it('detects a fake address bar with a padlock', () => {
    expect(looksLikeFakeBrowserChrome([{ ...base, hasUrlText: true, hasLockGlyph: true }])).toBe(true);
  });

  it('detects a fake window with controls and a URL', () => {
    expect(looksLikeFakeBrowserChrome([{ ...base, hasUrlText: true, hasWindowControls: true }])).toBe(true);
  });

  it('does not fire on a URL alone', () => {
    // An ordinary banner that happens to display a link is not an attack.
    expect(looksLikeFakeBrowserChrome([{ ...base, hasUrlText: true }])).toBe(false);
  });

  it('does not fire on a padlock alone', () => {
    expect(looksLikeFakeBrowserChrome([{ ...base, hasLockGlyph: true }])).toBe(false);
  });

  it('ignores static-flow and small or low elements', () => {
    expect(looksLikeFakeBrowserChrome([{ ...base, position: 'static', hasUrlText: true, hasLockGlyph: true }])).toBe(false);
    expect(looksLikeFakeBrowserChrome([{ ...base, width: 120, hasUrlText: true, hasLockGlyph: true }])).toBe(false);
    expect(looksLikeFakeBrowserChrome([{ ...base, top: 900, hasUrlText: true, hasLockGlyph: true }])).toBe(false);
  });

  it('is false for an empty page', () => {
    expect(looksLikeFakeBrowserChrome([])).toBe(false);
  });
});

describe('isWorthAssessing', () => {
  it('skips an ordinary content page', () => {
    expect(isWorthAssessing({ password_field_count: 0, path_depth: 2 })).toBe(false);
  });

  it('assesses any credential form, brand claim, or fake chrome', () => {
    expect(isWorthAssessing({ password_field_count: 1 })).toBe(true);
    expect(isWorthAssessing({ title_brand_tokens: ['paypal'] })).toBe(true);
    expect(isWorthAssessing({ fake_browser_chrome: true })).toBe(true);
  });
});

describe('lexicon parity with the server', () => {
  it('holds the brands page_classifier.go also knows', () => {
    // A token present here but absent there is silently dropped server-side,
    // so the two lists must not drift apart unnoticed.
    for (const brand of ['paypal', 'microsoft', 'office365', 'wellsfargo', 'royalmail', 'coinbase']) {
      expect(BRAND_LEXICON.has(brand)).toBe(true);
    }
    expect(BRAND_LEXICON.size).toBe(41);
  });
});
