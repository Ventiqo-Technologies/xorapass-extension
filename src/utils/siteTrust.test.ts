import { describe, it, expect } from 'vitest';
import {
  normalizeHostname,
  extractHostname,
  registrableDomain,
  stripPublicSuffix,
  isSubdomainOf,
  isDomainMatch,
  levenshtein,
  hasPunycode,
  findLookalikeTarget,
  isThirdPartyFrame,
  isUserContentHost,
  FREE_HOSTING_SUFFIXES,
} from './siteTrust';
import { isTrustedHost } from './shieldEngine';

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
    expect(isDomainMatch('myaccount.google.com', 'https://accounts.google.com')).toBe(true);
    expect(isDomainMatch('accounts.google.com', 'https://myaccount.google.com')).toBe(true);
    expect(isDomainMatch('google.com', 'https://accounts.google.com')).toBe(true);
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

describe('SHIELD-001 — registrable tenant credential authorization', () => {
  it.each(FREE_HOSTING_SUFFIXES)('separates credentials and saved trust across %s tenants', (suffix) => {
    const saved = `victim.${suffix}`;
    const other = `evil.${suffix}`;
    expect(isDomainMatch(other, `https://${saved}/login`)).toBe(false);
    expect(isDomainMatch(saved, `https://${other}/login`)).toBe(false);
    expect(isDomainMatch(saved, `https://${saved}/login`)).toBe(true);
    expect(isTrustedHost(other, [saved], [])).toBe(false);
  });

  it.each(['framer.app', 'github.io', 'pages.dev', 'vercel.app', 'awsapps.com'])(
    'does not authorize a %s tenant through a saved provider suffix', (suffix) => {
      expect(isDomainMatch(`victim.${suffix}`, `https://${suffix}`)).toBe(false);
      expect(isDomainMatch(suffix, `https://victim.${suffix}`)).toBe(false);
    }
  );

  it('preserves normal subdomain logins within one shared-hosting tenant', () => {
    expect(isDomainMatch('docs.victim.framer.app', 'https://victim.framer.app')).toBe(true);
    expect(isDomainMatch('victim.framer.app', 'https://login.victim.framer.app')).toBe(true);
    expect(isDomainMatch('docs.victim.region.run.app', 'https://victim.region.run.app')).toBe(true);
    expect(isDomainMatch('evil.region.run.app', 'https://victim.region.run.app')).toBe(false);
  });

  it('honors three-label ICANN suffixes and PSL wildcard/exception boundaries', () => {
    expect(registrableDomain('login.school.act.edu.au')).toBe('school.act.edu.au');
    expect(isDomainMatch('evil.act.edu.au', 'https://victim.act.edu.au')).toBe(false);
    expect(registrableDomain('a.b.ck')).toBe('a.b.ck');
    expect(isDomainMatch('evil.b.ck', 'https://victim.b.ck')).toBe(false);
    expect(registrableDomain('login.www.ck')).toBe('www.ck');
    expect(isDomainMatch('login.www.ck', 'https://www.ck')).toBe(true);
  });

  it('never normalizes a www hosting tenant into the provider hostname', () => {
    expect(normalizeHostname('WWW.Framer.APP.')).toBe('www.framer.app');
    expect(extractHostname('https://www.framer.app/login')).toBe('www.framer.app');
    expect(isDomainMatch('www.framer.app', 'https://framer.app')).toBe(false);
    expect(isDomainMatch('framer.app', 'https://www.framer.app')).toBe(false);
    expect(normalizeHostname('www.victim.framer.app')).toBe('victim.framer.app');
    expect(isDomainMatch('www.victim.framer.app', 'https://victim.framer.app')).toBe(true);
  });

  it('uses the same private/wildcard boundary for brand stripping', () => {
    expect(stripPublicSuffix('evil.framer.app')).toBe('evil');
    expect(stripPublicSuffix('login.school.act.edu.au')).toBe('login.school');
    expect(stripPublicSuffix('a.b.ck')).toBe('a');
    expect(stripPublicSuffix('login.www.ck')).toBe('login.www');
  });

  it('does not release AWS portal credentials to a different organization or realm', () => {
    expect(isDomainMatch('evil.awsapps.com', 'https://victim.awsapps.com')).toBe(false);
    expect(isDomainMatch('evil.signin.aws', 'https://victim.signin.aws')).toBe(false);
    expect(isDomainMatch('victim.signin.aws', 'https://victim.awsapps.com')).toBe(false);
    expect(isDomainMatch('console.aws.amazon.com', 'https://victim.awsapps.com')).toBe(false);
    expect(isDomainMatch('victim.awsapps.com', 'https://victim.awsapps.com/start')).toBe(true);
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

describe('isUserContentHost', () => {
  it('recognizes Azure multi-segment subdomains under core.windows.net', () => {
    expect(isUserContentHost('mucopnexo.z13.web.core.windows.net')).toBe(true);
    expect(isUserContentHost('sample.blob.core.windows.net')).toBe(true);
    expect(isUserContentHost('custom.file.core.windows.net')).toBe(true);
    expect(isUserContentHost('storageaccount.core.windows.net')).toBe(true);
  });

  it('recognizes Google and AWS user-content platforms', () => {
    expect(isUserContentHost('sites.google.com')).toBe(true);
    expect(isUserContentHost('mybucket.s3.amazonaws.com')).toBe(true);
    expect(isUserContentHost('forms.office.com')).toBe(true);
  });

  it('does not classify top-level or unrelated domains as user-content hosts', () => {
    expect(isUserContentHost('google.com')).toBe(false);
    expect(isUserContentHost('microsoft.com')).toBe(false);
    expect(isUserContentHost('windows.net')).toBe(false);
    expect(isUserContentHost('example.com')).toBe(false);
  });
});

