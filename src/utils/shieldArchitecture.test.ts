import { describe, it, expect } from 'vitest';
import { coerceShieldConfig, DEFAULT_SHIELD_CONFIG } from './shieldConfig';
import { canonicalizeUrl, urlExpressions, sha256Bytes, toHex, prefixOf, hashUrlExpressions } from './urlHashing';
import { PrefixSet, prefixHex } from './shieldBlocklist';
import { decideNavigation, shouldEscalateRemote, isTrustedHost } from './shieldEngine';
import { assessDomainRisk } from './domainRisk';

function canon(u: string): string | null {
  const c = canonicalizeUrl(u);
  return c ? `http://${c.host}${c.path}${c.query !== null ? '?' + c.query : ''}` : null;
}

describe('shield config', () => {
  it('falls back to defaults for missing or malformed input', () => {
    expect(coerceShieldConfig(undefined)).toEqual(DEFAULT_SHIELD_CONFIG);
    expect(coerceShieldConfig('nope')).toEqual(DEFAULT_SHIELD_CONFIG);
  });

  it('clamps values, filters rules and honours the kill switch', () => {
    const c = coerceShieldConfig({
      shield_enabled: false,
      nav_guard: { block_score: 5, typing_guard_ms: 99999 },
      heuristics: { disabled_rules: ['Typosquat', 'evil', 'typosquat'], warn_score: 80, block_score: 60 },
      remote: { min_local_score: -4 },
      trusted_domains: ['Example.com', 'not a host', 'www.acme.io'],
    });
    expect(c.shield_enabled).toBe(false);
    expect(c.nav_guard.block_score).toBe(50);
    expect(c.nav_guard.typing_guard_ms).toBe(5000);
    expect(c.heuristics.disabled_rules).toEqual(['typosquat']);
    expect(c.heuristics.block_score).toBeGreaterThan(c.heuristics.warn_score);
    expect(c.remote.min_local_score).toBe(0);
    expect(c.trusted_domains).toEqual(['example.com', 'acme.io']);
  });
});

describe('URL canonicalization (Safe Browsing rules)', () => {
  const cases: [string, string][] = [
    ['http://host/%25%32%35', 'http://host/%25'],
    ['http://host/%25%32%35%25%32%35', 'http://host/%25%25'],
    ['http://www.google.com/blah/..', 'http://www.google.com/'],
    ['http://www.GOOgle.com/', 'http://www.google.com/'],
    ['http://www.google.com.../', 'http://www.google.com/'],
    ['http://www.google.com/foo\tbar\rbaz\n2', 'http://www.google.com/foobarbaz2'],
    ['http://www.google.com/q?', 'http://www.google.com/q?'],
    ['http://www.google.com/q?r?s', 'http://www.google.com/q?r?s'],
    ['http://evil.com/foo#bar#baz', 'http://evil.com/foo'],
    ['http://3279880203/blah', 'http://195.127.0.11/blah'],
    ['http://www.gotaport.com:1234/', 'http://www.gotaport.com/'],
    [
      'http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/',
      'http://168.188.99.26/.secure/www.ebay.com/',
    ],
    ['http://host.com//twoslashes?more//slashes', 'http://host.com/twoslashes?more//slashes'],
    ['http://notrailingslash.com', 'http://notrailingslash.com/'],
    ['http://user:pass@Host.COM/a/./b/../c', 'http://host.com/a/c'],
  ];
  for (const [input, want] of cases) {
    it(`canonicalizes ${JSON.stringify(input)}`, () => {
      expect(canon(input)).toBe(want);
    });
  }

  it('rejects non-web schemes', () => {
    expect(canonicalizeUrl('javascript:alert(1)')).toBeNull();
    expect(canonicalizeUrl('ftp://x.com/')).toBeNull();
  });
});

describe('lookup expressions', () => {
  it('matches the spec example with a query', () => {
    expect(new Set(urlExpressions('http://a.b.c/1/2.html?param=1'))).toEqual(
      new Set([
        'a.b.c/1/2.html?param=1',
        'a.b.c/1/2.html',
        'a.b.c/',
        'a.b.c/1/',
        'b.c/1/2.html?param=1',
        'b.c/1/2.html',
        'b.c/',
        'b.c/1/',
      ])
    );
  });

  it('uses at most the last five host labels', () => {
    expect(new Set(urlExpressions('http://a.b.c.d.e.f.g/1.html'))).toEqual(
      new Set([
        'a.b.c.d.e.f.g/1.html',
        'a.b.c.d.e.f.g/',
        'c.d.e.f.g/1.html',
        'c.d.e.f.g/',
        'd.e.f.g/1.html',
        'd.e.f.g/',
        'e.f.g/1.html',
        'e.f.g/',
        'f.g/1.html',
        'f.g/',
      ])
    );
  });

  it('does not generate host suffixes for IPs', () => {
    expect(new Set(urlExpressions('http://1.2.3.4/1/'))).toEqual(new Set(['1.2.3.4/1/', '1.2.3.4/']));
  });

  it('never produces more than 30 expressions', () => {
    expect(urlExpressions('http://a.b.c.d.e.f.g.h/1/2/3/4/5/6/7.html?x=1').length).toBeLessThanOrEqual(30);
  });
});

describe('hashing and prefix set', () => {
  it('hashes with SHA-256 and takes a big-endian 4-byte prefix', async () => {
    const h = await sha256Bytes('abc');
    expect(toHex(h)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(prefixOf(h)).toBe(0xba7816bf);
    expect(prefixHex(prefixOf(h))).toBe('ba7816bf');
  });

  it('finds a hashed expression in a server-format blob', async () => {
    const [target] = (await hashUrlExpressions('http://evil.example/')).filter((e) => e.expression === 'evil.example/');
    const values = [1, 42, target.prefix, 0xffffffff].sort((a, b) => a - b);
    const buf = new ArrayBuffer(values.length * 4);
    const view = new DataView(buf);
    values.forEach((v, i) => view.setUint32(i * 4, v, false));
    const set = PrefixSet.fromBigEndianBytes(buf);
    expect(set.size).toBe(4);
    expect(set.has(target.prefix)).toBe(true);
    expect(set.has(43)).toBe(false);
    expect(PrefixSet.empty().has(1)).toBe(false);
  });

  it('rejects unsorted or truncated blobs', () => {
    const bad = new ArrayBuffer(8);
    new DataView(bad).setUint32(0, 5);
    new DataView(bad).setUint32(4, 1);
    expect(() => PrefixSet.fromBigEndianBytes(bad)).toThrow();
    expect(() => PrefixSet.fromBigEndianBytes(new ArrayBuffer(5))).toThrow();
  });
});

describe('Shield decision pipeline', () => {
  const base = {
    config: DEFAULT_SHIELD_CONFIG,
    active: true,
    userAllowlist: [] as string[],
    knownHosts: ['paypal.com'],
    blocklistHit: null,
    local: null,
  };

  it('does nothing when inactive or kill-switched', () => {
    expect(decideNavigation({ ...base, url: 'https://x.example/', active: false }).layer).toBe('disabled');
    expect(
      decideNavigation({ ...base, url: 'https://x.example/', config: { ...DEFAULT_SHIELD_CONFIG, shield_enabled: false } })
        .layer
    ).toBe('disabled');
  });

  it('blocks a confirmed blocklist hit, even on a trusted platform', () => {
    const d = decideNavigation({
      ...base,
      url: 'https://docs.github.com/evil',
      blocklistHit: { threatType: 'SOCIAL_ENGINEERING', source: 'google_web_risk' },
    });
    expect(d.action).toBe('block');
    expect(d.layer).toBe('blocklist');
  });

  it('lets the user allowlist win over the blocklist', () => {
    const d = decideNavigation({
      ...base,
      url: 'https://intranet.example/',
      userAllowlist: ['intranet.example'],
      blocklistHit: { threatType: 'MALWARE', source: 'xorapass' },
    });
    expect(d.action).toBe('allow');
  });

  it('blocks a critical lookalike only above the nav threshold', () => {
    const homograph = assessDomainRisk('xn--pypal-4ve.com', ['paypal.com']);
    expect(decideNavigation({ ...base, url: 'https://xn--pypal-4ve.com/', local: homograph }).action).toBe('block');
    const typo = assessDomainRisk('paypa1.com', ['paypal.com']);
    const d = decideNavigation({ ...base, url: 'https://paypa1.com/', local: typo });
    expect(d.action).toBe('warn'); // 80 < nav block score 90: left to the page-level check
  });

  it('treats saved and major-platform hosts as trusted, customer-content hosts not', () => {
    expect(isTrustedHost('www.paypal.com', ['paypal.com'], [])).toBe(true);
    expect(isTrustedHost('learn.microsoft.com', [], [])).toBe(true);
    expect(isTrustedHost('evil.blob.core.windows.net', [], [])).toBe(false);
    expect(isTrustedHost('portal.acme.io', [], ['acme.io'])).toBe(true);
  });

  it('only escalates to the server when there is something to ask about', () => {
    const clean = assessDomainRisk('news.example', ['paypal.com']);
    const cfg = DEFAULT_SHIELD_CONFIG;
    expect(shouldEscalateRemote({ config: cfg, local: clean, trusted: false })).toBe(false);
    expect(shouldEscalateRemote({ config: cfg, local: clean, trusted: false, pageSignals: { password_field_count: 1 } })).toBe(true);
    expect(shouldEscalateRemote({ config: cfg, local: clean, trusted: true, hasCredentialForm: true })).toBe(false);
    expect(shouldEscalateRemote({ config: cfg, local: clean, trusted: true, crossOriginFormAction: true })).toBe(true);
    const typo = assessDomainRisk('paypa1.com', ['paypal.com']);
    expect(shouldEscalateRemote({ config: cfg, local: typo, trusted: false })).toBe(true);
    expect(
      shouldEscalateRemote({ config: { ...cfg, remote: { ...cfg.remote, enabled: false } }, local: typo, trusted: false })
    ).toBe(false);
  });
});

describe('remote-tunable local heuristics', () => {
  it('can switch off a single rule', () => {
    expect(assessDomainRisk('paypa1.com', ['paypal.com']).decision).toBe('block');
    const off = assessDomainRisk('paypa1.com', ['paypal.com'], [], '', { disabledRules: ['typosquat'] });
    expect(off.signals.typosquatTarget).toBeUndefined();
    expect(off.decision).not.toBe('block');
  });

  it('can move the block threshold', () => {
    const r = assessDomainRisk('paypa1.com', ['paypal.com'], [], '', { blockScore: 85 });
    expect(r.decision).toBe('warn');
  });
});
