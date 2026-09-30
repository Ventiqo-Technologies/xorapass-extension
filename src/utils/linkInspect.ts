// Link Guard helpers ("Inspect Link with XoraPass").
//
// Pure and DOM-free so it can be unit-tested and bundled into the background.
//
// Resolving where a link REALLY goes is done offline wherever possible: most
// links people are phished with are wrapped by a mail/social redirector
// (Google, Outlook SafeLinks, Proofpoint, Facebook, ...) that carries the
// destination in its own query string. Unwrapping those needs no request at
// all. Only a genuine URL shortener (bit.ly, ...) hides its destination
// server-side, and for those alone the background makes one credential-less
// HEAD request (redirects followed as HEAD) — never a GET, which could consume
// a one-time link or confirm to a phisher that the address is live.

import { extractHostname, registrableDomain } from './siteTrust';
import type { DomainRiskAssessment } from './domainRisk';
import { DEFAULT_REDIRECTOR_RULES, type ShieldRedirectorRule } from './shieldConfig';

let activeRedirectorRules: readonly ShieldRedirectorRule[] = DEFAULT_REDIRECTOR_RULES;

export function setActiveRedirectorRules(rules: readonly ShieldRedirectorRule[]): void {
  if (Array.isArray(rules) && rules.length > 0) {
    activeRedirectorRules = rules;
  }
}

export function getActiveRedirectorRules(): readonly ShieldRedirectorRule[] {
  return activeRedirectorRules;
}

export function matchesHostPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/^www\./, '');
  const p = pattern.toLowerCase().trim();
  if (p.startsWith('*.')) {
    const root = p.slice(2);
    return h === root || h.endsWith(`.${root}`);
  }
  return h === p;
}

/** Link shorteners whose destination is only knowable by asking them. */
export const SHORTENER_HOSTS: ReadonlySet<string> = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'ow.ly', 'buff.ly',
  'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly', 'bl.ink', 'lnkd.in', 'goo.gl',
  'qrco.de', 'shorturl.com', 's.id', 'v.gd', 'x.co', 'short.io', 'snip.ly', 'urlz.fr',
]);

export function isShortenerUrl(url: string): boolean {
  const host = extractHostname(url);
  return !!host && SHORTENER_HOSTS.has(host);
}

function safeUrl(raw: string): URL | null {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u : null;
  } catch {
    return null;
  }
}

/** Decodes Proofpoint URL Defense v2 (`u=` with -→% and _→/) and v3 (`__URL__`). */
function decodeProofpoint(u: URL): string | null {
  if (u.pathname.startsWith('/v2/')) {
    const enc = u.searchParams.get('u');
    if (!enc) return null;
    try {
      return decodeURIComponent(enc.replace(/-/g, '%').replace(/_/g, '/'));
    } catch {
      return null;
    }
  }
  const m = u.href.match(/\/v3\/__(.+?)__;/);
  return m ? m[1] : null;
}

/**
 * If `raw` is a known redirector wrapper, returns the URL it wraps; else null.
 */
export function unwrapOnce(raw: string, customRules?: readonly ShieldRedirectorRule[]): string | null {
  const u = safeUrl(raw);
  if (!u) return null;
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  const reg = registrableDomain(host);
  const q = (k: string) => u.searchParams.get(k);

  const rules = customRules && customRules.length > 0 ? customRules : activeRedirectorRules;

  // 1. Check dynamic rules (synced from backend Shield remote config)
  for (const rule of rules) {
    if (!matchesHostPattern(host, rule.host_pattern)) continue;
    if (rule.path_prefix && !u.pathname.toLowerCase().startsWith(rule.path_prefix.toLowerCase())) continue;

    if (rule.type === 'proofpoint') {
      const decoded = decodeProofpoint(u);
      if (decoded && safeUrl(decoded)) return decoded;
    } else if (rule.type === 'raw_query') {
      const decoded = u.search ? u.search.slice(1) : null;
      if (decoded && safeUrl(decoded)) return decoded;
    } else if (rule.query_param) {
      const val = q(rule.query_param);
      if (val && safeUrl(val)) return val;
    }
  }

  // 2. Built-in hardcoded fallbacks
  let target: string | null = null;
  if (reg.startsWith('google.') && u.pathname === '/url') target = q('q') || q('url');
  else if (host.endsWith('safelinks.protection.outlook.com')) target = q('url');
  else if (host.includes('.static.microsoft') && u.pathname.includes('/safelinks/')) target = q('url');
  else if (host === 'urldefense.proofpoint.com' || host === 'urldefense.com') target = decodeProofpoint(u);
  else if ((host === 'l.facebook.com' || host === 'lm.facebook.com') && u.pathname === '/l.php') target = q('u');
  else if (host === 'l.instagram.com') target = q('u');
  else if (host === 'out.reddit.com') target = q('url');
  else if (host === 'slack-redir.net') target = q('url');
  else if (host === 'youtube.com' && u.pathname === '/redirect') target = q('q');
  else if (host === 'linkedin.com' && u.pathname.startsWith('/redir/')) target = q('url');
  else if (host === 'steamcommunity.com' && u.pathname.startsWith('/linkfilter')) target = q('url') || q('u');
  else if (host === 'href.li') target = u.search ? u.search.slice(1) : null;

  if (target && safeUrl(target)) return target;

  // 3. Generic redirection heuristic for any host carrying an absolute destination URL
  const COMMON_REDIRECT_PARAMS = ['url', 'target', 'dest', 'destination', 'redirect', 'redirect_url', 'next', 'link'];
  for (const param of COMMON_REDIRECT_PARAMS) {
    const val = q(param);
    if (val && safeUrl(val)) {
      const valHost = extractHostname(val);
      if (valHost && valHost !== host) {
        return val;
      }
    }
  }

  return null;
}

/** Repeatedly unwraps redirector wrappers (bounded). */
export function unwrapLink(raw: string, maxDepth = 6, customRules?: readonly ShieldRedirectorRule[]): { url: string; hops: string[] } {
  const hops: string[] = [];
  let current = raw;
  for (let i = 0; i < maxDepth; i++) {
    const next = unwrapOnce(current, customRules);
    if (!next || next === current) break;
    hops.push(current);
    current = next;
  }
  return { url: current, hops };
}

export interface LinkVerdict {
  verdict: 'safe' | 'suspicious' | 'high_risk';
  riskScore: number;
  threats: string[];
}

/**
 * Combines the destination's (merged local+remote) risk with link-specific
 * signals into the verdict shown on the inspection card.
 */
export function buildLinkVerdict(opts: {
  finalUrl: string;
  risk: DomainRiskAssessment;
  hops: number;
  unresolvedShortener: boolean;
  isCustomScheme: boolean;
}): LinkVerdict {
  const { finalUrl, risk, hops, unresolvedShortener, isCustomScheme } = opts;
  const threats: string[] = [];
  let score = risk.riskScore;

  if (risk.signals.hasPunycode || risk.signals.isHomograph) threats.push('Punycode / homograph domain structure');
  if (risk.signals.brandAbuse) threats.push(`Brand impersonation of ${risk.signals.brandAbuse.brand}`);
  if (risk.signals.typosquatTarget) threats.push(`Mimics ${risk.signals.typosquatTarget}`);
  if (risk.signals.isHighRiskTld) threats.push('Registered under a high-risk phishing TLD');
  for (const code of Object.entries(risk.threatIntelSignals || {})) {
    if (code[1] === 'phishing_hit' || code[1] === 'malware_hit') {
      threats.push('Flagged by threat-intelligence feeds');
      break;
    }
  }
  if (/^http:\/\//i.test(finalUrl)) {
    threats.push('Unencrypted HTTP connection');
    score = Math.max(score, 30);
  }
  if (unresolvedShortener) {
    threats.push('Destination hidden behind a link shortener and could not be verified');
    score = Math.max(score, 40);
  }
  if (hops >= 3) {
    threats.push(`Passes through ${hops} redirectors before the destination`);
    score = Math.max(score, 35);
  }
  if (isCustomScheme) threats.push('Opens an external app rather than a web page');

  const verdict: LinkVerdict['verdict'] =
    risk.decision === 'block' || score >= 70 ? 'high_risk' : score >= 35 || risk.decision !== 'allow' ? 'suspicious' : 'safe';
  return { verdict, riskScore: Math.min(100, score), threats: Array.from(new Set(threats)) };
}
