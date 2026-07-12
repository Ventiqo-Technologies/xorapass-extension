import { describe, it, expect } from 'vitest';
import {
  normalizeHostname,
  extractHostname,
  registrableDomain,
  isSubdomainOf,
  isDomainMatch,
  levenshtein,
  hasPunycode,
  findLookalikeTarget,
  isThirdPartyFrame,
} from './siteTrust';

describe('normalizeHostname', () => {
  it('lowercases, trims, strips trailing dot and leading www', () => {
    expect(normalizeHostname('  WWW.Example.COM.  ')).toBe('example.com');
    expect(normalizeHostname('sub.example.com')).toBe('sub.example.com');
    expect(normalizeHostname('')).toBe('');
  });
});

describe('extractHostname', () => {
  it('parses full and scheme-less urls', () => {
    expect(extractHostname('https://www.example.com/login?x=1')).toBe('example.com');
    expect(extractHostname('example.com')).toBe('example.com');
    expect(extractHostname('http://sub.example.co.uk')).toBe('sub.example.co.uk');
  });
  it('returns empty for empty input', () => {
    expect(extractHostname('')).toBe('');
  });
});

describe('registrableDomain', () => {
  it('reduces multi-label hosts to the registrable domain', () => {
    expect(registrableDomain('a.b.example.com')).toBe('example.com');
    expect(registrableDomain('login.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('example.com')).toBe('example.com');
  });
  it('returns IPs and localhost unchanged', () => {
    expect(registrableDomain('127.0.0.1')).toBe('127.0.0.1');
    expect(registrableDomain('localhost')).toBe('localhost');
  });
});

describe('isSubdomainOf', () => {
  it('is true for equal or child hosts only', () => {
    expect(isSubdomainOf('example.com', 'example.com')).toBe(true);
    expect(isSubdomainOf('a.example.com', 'example.com')).toBe(true);
    expect(isSubdomainOf('example.com', 'a.example.com')).toBe(false);
    expect(isSubdomainOf('notexample.com', 'example.com')).toBe(false);
  });
});

describe('isDomainMatch — legitimate matches', () => {
  it('matches exact host', () => {
    expect(isDomainMatch('example.com', 'https://example.com')).toBe(true);
  });
  it('matches subdomains and parent domains (same site)', () => {
    expect(isDomainMatch('app.example.com', 'https://example.com')).toBe(true);
    expect(isDomainMatch('example.com', 'https://login.example.com')).toBe(true);
    expect(isDomainMatch('mail.google.com', 'https://accounts.google.com')).toBe(true);
  });
  it('ignores www and scheme differences', () => {
    expect(isDomainMatch('www.example.com', 'example.com')).toBe(true);
  });
});

describe('isDomainMatch — attack rejection (regression for substring bug)', () => {
  it('rejects suffix-confusion domains', () => {
    expect(isDomainMatch('example.com.evil.com', 'https://example.com')).toBe(false);
    expect(isDomainMatch('bank.com.attacker.net', 'https://bank.com')).toBe(false);
  });
  it('rejects unrelated hosts that merely share a substring', () => {
    expect(isDomainMatch('notexample.com', 'https://example.com')).toBe(false);
    expect(isDomainMatch('example.com', 'https://myexample.com')).toBe(false);
  });
  it('rejects empty inputs', () => {
    expect(isDomainMatch('', 'https://example.com')).toBe(false);
    expect(isDomainMatch('example.com', '')).toBe(false);
  });
});

describe('levenshtein', () => {
  it('computes edit distance', () => {
    expect(levenshtein('paypal', 'paypal')).toBe(0);
    expect(levenshtein('paypal', 'paypa1')).toBe(1);
    expect(levenshtein('google', 'gooogle')).toBe(1);
  });
});

describe('hasPunycode', () => {
  it('detects xn-- labels', () => {
    expect(hasPunycode('xn--pple-43d.com')).toBe(true);
    expect(hasPunycode('apple.com')).toBe(false);
  });
});

describe('findLookalikeTarget', () => {
  const known = ['https://paypal.com', 'https://google.com'];

  it('flags typosquats of a known domain', () => {
    const r = findLookalikeTarget('paypa1.com', known);
    expect(r?.target).toBe('paypal.com');
    expect(r?.reason).toBe('typosquat');
  });

  it('flags punycode homograph domains close to a known site', () => {
    const r = findLookalikeTarget('xn--googe-8na.com', ['https://google.com']);
    expect(r?.reason).toBe('punycode');
  });

  it('does not flag a legitimately matching site', () => {
    expect(findLookalikeTarget('accounts.google.com', known)).toBeNull();
    expect(findLookalikeTarget('paypal.com', known)).toBeNull();
  });

  it('does not flag unrelated sites', () => {
    expect(findLookalikeTarget('completely-different.org', known)).toBeNull();
  });
});

describe('isThirdPartyFrame', () => {
  it('is false for the top frame', () => {
    expect(isThirdPartyFrame({ isTop: true, selfOrigin: 'https://a.com', topOrigin: 'https://a.com' })).toBe(false);
  });
  it('is false for a same-origin sub-frame', () => {
    expect(
      isThirdPartyFrame({ isTop: false, selfOrigin: 'https://a.com', topOrigin: 'https://a.com', ancestorOrigins: ['https://a.com'] })
    ).toBe(false);
  });
  it('is true when the top origin is unreadable (cross-origin)', () => {
    expect(isThirdPartyFrame({ isTop: false, selfOrigin: 'https://a.com', topOrigin: null })).toBe(true);
  });
  it('is true when the top origin differs', () => {
    expect(isThirdPartyFrame({ isTop: false, selfOrigin: 'https://a.com', topOrigin: 'https://evil.com' })).toBe(true);
  });
  it('is true when any ancestor is cross-origin', () => {
    expect(
      isThirdPartyFrame({ isTop: false, selfOrigin: 'https://a.com', topOrigin: 'https://a.com', ancestorOrigins: ['https://a.com', 'https://evil.com'] })
    ).toBe(true);
  });
});
