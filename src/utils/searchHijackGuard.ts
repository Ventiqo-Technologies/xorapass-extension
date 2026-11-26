// Search Engine & New-Tab Hijacker Protection Service
// Detects adware redirectors, rogue search engines, and malicious new-tab takeovers.

export interface SearchHijackVerdict {
  isHijacked: boolean;
  threatType?: 'search_redirector' | 'adware_portal' | 'suspicious_intermediary' | 'newtab_takeover';
  matchedDomain?: string;
  reasons: string[];
  details: string;
}

export interface SearchHijackExtensionFinding {
  extensionId: string;
  name: string;
  reason: string;
  threatType: 'search_provider' | 'newtab_override';
}

// Known malicious search redirectors and adware query interceptors
export const KNOWN_SEARCH_HIJACK_DOMAINS = new Set([
  // Prominent redirectors
  'searchbaron.com',
  'searchpulse.net',
  'boysearch.com',
  'feed.sonic-search.com',
  'search.findwhatever.com',
  'mybrowser-search.com',
  'search.myway.com',
  'search.hemailhere.com',
  'anysearch.net',
  'chill-tab.com',
  'safefinder.com',
  'search.conduit.com',
  'trovi.com',
  'search.zone',
  'smarthistorysearch.com',
  'search.pdf-converter-pro.com',
  'search.searchtoolhub.com',
  'search-fine.com',
  'search-alpha.com',
  'searchpoweronline.com',
  'search-location.com',
  'searchitup.info',
  'mysearches.net',
  'searchallmac.com',
  'search-quick.com',
  'searchlee.com',
  'gosearchresults.com',
  'nearbyme.io',
  'feed.helperbar.com',
  'search.mysearch.com',
  'topsearchresults.biz',
]);

// Trusted legitimate search engine root domains
export const TRUSTED_SEARCH_DOMAINS = new Set([
  'google.com',
  'google.co.uk',
  'google.ca',
  'google.com.au',
  'google.de',
  'google.fr',
  'google.co.jp',
  'google.co.in',
  'bing.com',
  'duckduckgo.com',
  'brave.com',
  'ecosia.org',
  'startpage.com',
  'kagi.com',
  'qwant.com',
  'baidu.com',
  'yandex.com',
  'yandex.ru',
]);

// Suspicious URL parameters commonly used by affiliate hijack redirectors
const SUSPICIOUS_AFFILIATE_PARAMS = [
  'affid',
  'subid',
  'installer_id',
  'tracking_id',
  'clickid',
  'campid',
  'ptag',
  'fwsid',
];

/**
 * Extracts normalized hostname from URL
 */
export function extractHostnameFromUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

/**
 * Checks whether a hostname matches or ends with any known search hijacker domain
 */
export function isKnownSearchHijacker(hostname: string): boolean {
  if (!hostname) return false;
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  if (KNOWN_SEARCH_HIJACK_DOMAINS.has(clean)) return true;

  for (const domain of KNOWN_SEARCH_HIJACK_DOMAINS) {
    if (clean.endsWith(`.${domain}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether a hostname belongs to a known trusted search provider
 */
export function isTrustedSearchDomain(hostname: string): boolean {
  if (!hostname) return false;
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  if (TRUSTED_SEARCH_DOMAINS.has(clean)) return true;

  for (const domain of TRUSTED_SEARCH_DOMAINS) {
    if (clean === domain || clean.endsWith(`.${domain}`)) {
      return true;
    }
  }
  return false;
}

/**
 * Evaluates a navigation URL for search hijacking patterns:
 * 1. Direct hit on known adware search redirectors
 * 2. Intermediate bounce chains carrying affiliate query trackers
 * 3. Fake search results portals
 */
export function inspectSearchUrl(url: string): SearchHijackVerdict {
  if (!url || typeof url !== 'string') {
    return { isHijacked: false, reasons: [], details: '' };
  }

  // Skip internal browser protocols and about:blank
  if (/^(chrome|edge|about|chrome-extension|moz-extension|brave):/i.test(url)) {
    return { isHijacked: false, reasons: [], details: '' };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { isHijacked: false, reasons: [], details: '' };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');

  // 1. Direct match on known search hijacker domains
  if (isKnownSearchHijacker(hostname)) {
    return {
      isHijacked: true,
      threatType: 'search_redirector',
      matchedDomain: hostname,
      reasons: [
        `Target domain "${hostname}" is a known browser search hijacker.`,
        'Adware often redirects web searches through this intermediary to display unauthorized ads.',
      ],
      details: `Your search traffic was routed through "${hostname}", a flagged adware redirector.`,
    };
  }

  // 2. Check for intermediate redirect bounces wrapping legitimate search queries
  // (e.g. http://bad-tracker.com/out?url=https%3A%2F%2Fgoogle.com%2Fsearch%3Fq%3D...)
  const searchParams = parsed.searchParams;
  for (const key of ['url', 'target', 'rurl', 'redirect', 'dest', 'u']) {
    const embeddedUrl = searchParams.get(key);
    if (embeddedUrl && embeddedUrl.startsWith('http')) {
      const embeddedHost = extractHostnameFromUrl(embeddedUrl);
      if (isKnownSearchHijacker(embeddedHost)) {
        return {
          isHijacked: true,
          threatType: 'suspicious_intermediary',
          matchedDomain: embeddedHost,
          reasons: [
            `Navigation carries an embedded redirect to search hijacker "${embeddedHost}".`,
            'Traffic is being bounced through tracking intermediaries before reaching results.',
          ],
          details: `Search traffic contains hidden redirect to adware domain "${embeddedHost}".`,
        };
      }
    }
  }

  // 3. Check for suspicious affiliate tagging on generic search endpoints
  if (!isTrustedSearchDomain(hostname)) {
    const isSearchPath = /\/(search|results|find|query)\b/i.test(parsed.pathname) || searchParams.has('q');
    if (isSearchPath) {
      let affiliateCount = 0;
      for (const param of SUSPICIOUS_AFFILIATE_PARAMS) {
        if (searchParams.has(param)) affiliateCount++;
      }
      if (affiliateCount >= 2) {
        return {
          isHijacked: true,
          threatType: 'adware_portal',
          matchedDomain: hostname,
          reasons: [
            `Unverified search portal "${hostname}" contains multiple adware affiliate tracking tags.`,
            'Your queries may have been hijacked by an unauthorized search extension.',
          ],
          details: `Unverified search portal "${hostname}" detected with affiliate tracking parameters.`,
        };
      }
    }
  }

  return { isHijacked: false, reasons: [], details: '' };
}

/**
 * Audits installed browser extensions for newtab or search hijacking declarations
 */
export function auditExtensionsForSearchHijack(
  extensions: Array<{
    id: string;
    name: string;
    enabled: boolean;
    permissions?: string[];
    hostPermissions?: string[];
    installType?: string;
  }>
): SearchHijackExtensionFinding[] {
  const findings: SearchHijackExtensionFinding[] = [];

  for (const ext of extensions) {
    if (!ext.enabled) continue;
    // Skip built-in development / admin extensions
    if (ext.installType === 'development' || ext.id === 'addon@xorapass.com') continue;

    const hosts = ext.hostPermissions || [];
    for (const host of hosts) {
      for (const hijacker of KNOWN_SEARCH_HIJACK_DOMAINS) {
        if (host.includes(hijacker)) {
          findings.push({
            extensionId: ext.id,
            name: ext.name,
            threatType: 'search_provider',
            reason: `Requests host permissions for known search hijacker domain "${hijacker}".`,
          });
          break;
        }
      }
    }
  }

  return findings;
}

