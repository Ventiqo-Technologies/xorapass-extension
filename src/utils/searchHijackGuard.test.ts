import { describe, it, expect } from 'vitest';
import {
  inspectSearchUrl,
  isKnownSearchHijacker,
  isTrustedSearchDomain,
  auditExtensionsForSearchHijack,
} from './searchHijackGuard';

describe('searchHijackGuard', () => {
  it('detects direct visits to known search hijackers', () => {
    const verdict = inspectSearchUrl('https://searchbaron.com/v?q=cheap+flights');
    expect(verdict.isHijacked).toBe(true);
    expect(verdict.threatType).toBe('search_redirector');
    expect(verdict.matchedDomain).toBe('searchbaron.com');
    expect(verdict.reasons.length).toBeGreaterThan(0);
  });

  it('detects subdomains of known search hijackers', () => {
    const verdict = inspectSearchUrl('https://feed.sonic-search.com/search?q=test');
    expect(verdict.isHijacked).toBe(true);
    expect(verdict.threatType).toBe('search_redirector');
  });

  it('allows trusted search engines without flagging', () => {
    expect(inspectSearchUrl('https://www.google.com/search?q=xorapass').isHijacked).toBe(false);
    expect(inspectSearchUrl('https://duckduckgo.com/?q=security').isHijacked).toBe(false);
    expect(inspectSearchUrl('https://www.bing.com/search?q=news').isHijacked).toBe(false);
  });

  it('identifies embedded redirects to search hijackers', () => {
    const verdict = inspectSearchUrl(
      'https://tracking-relay.com/click?url=https%3A%2F%2Fsearchpulse.net%2Fquery%3Fq%3Dshoes'
    );
    expect(verdict.isHijacked).toBe(true);
    expect(verdict.threatType).toBe('suspicious_intermediary');
    expect(verdict.matchedDomain).toBe('searchpulse.net');
  });

  it('flags unverified search portals with multiple affiliate tracking tags', () => {
    const verdict = inspectSearchUrl(
      'https://random-unknown-search.biz/results?q=laptop&affid=99281&subid=trackerX'
    );
    expect(verdict.isHijacked).toBe(true);
    expect(verdict.threatType).toBe('adware_portal');
  });

  it('correctly audits installed extensions requesting hijacker permissions', () => {
    const extensions = [
      {
        id: 'safe-ext',
        name: 'Safe Developer Tool',
        enabled: true,
        hostPermissions: ['https://api.github.com/*'],
      },
      {
        id: 'malicious-search-ext',
        name: 'Free PDF Converter Search',
        enabled: true,
        hostPermissions: ['*://*.searchbaron.com/*', '<all_urls>'],
      },
      {
        id: 'disabled-bad-ext',
        name: 'Old Adware',
        enabled: false,
        hostPermissions: ['*://*.searchpulse.net/*'],
      },
    ];

    const findings = auditExtensionsForSearchHijack(extensions);
    expect(findings.length).toBe(1);
    expect(findings[0].extensionId).toBe('malicious-search-ext');
    expect(findings[0].reason).toContain('searchbaron.com');
  });

  it('safely handles non-http protocols and malformed URLs', () => {
    expect(inspectSearchUrl('about:blank').isHijacked).toBe(false);
    expect(inspectSearchUrl('chrome://settings').isHijacked).toBe(false);
    expect(inspectSearchUrl('not a valid url').isHijacked).toBe(false);
    expect(inspectSearchUrl('').isHijacked).toBe(false);
  });
});

