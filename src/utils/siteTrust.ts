// Shared, dependency-free site-trust utilities.
//
// IMPORTANT: keep this module free of DOM / chrome API usage so it stays pure
// and unit-testable, and so it can be bundled into both the background service
// worker and the popup (both ES-module contexts). It is intentionally NOT
// imported by the content script, which must remain a self-contained classic
// script.

// Public suffixes under which registrations are made. Two kinds live here:
//
//  1. ccTLD second-level registries (co.uk, com.au, ...) — the classic case.
//  2. Shared-tenant hosting suffixes (github.io, vercel.app, ...). These matter
//     for exactly the same reason: every customer is registered directly under
//     the suffix, so if the suffix itself were treated as the registrable
//     domain then every tenant would be "same site" as every other tenant.
//     Without github.io in this list, evil.github.io and victim.github.io both
//     reduce to github.io, and isDomainMatch() happily offers one tenant's
//     saved credentials on another tenant's page.
//
// This is deliberately not the full Public Suffix List. Unknown suffixes fall
// back to the last two labels, which is the stricter (safe) direction for the
// ccTLD case — but note it is the UNSAFE direction for case 2, which is why
// shared-hosting suffixes must be added here explicitly as they are adopted.
export const MULTI_PART_SUFFIXES = new Set([
  // ── ccTLD second-level registries ──────────────────────────────────────
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'lg.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'org.nz', 'govt.nz', 'net.nz', 'ac.nz',
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'firm.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.mx', 'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'com.sg', 'com.hk', 'com.tw', 'com.ar', 'com.co', 'com.pe', 'com.ec',
  'com.uy', 'com.py', 'com.bo', 'com.do', 'com.gt', 'com.sv', 'com.ni',
  'com.pa', 'com.ve', 'co.cr',
  'co.kr', 'or.kr', 'co.il', 'org.il', 'net.il', 'co.id', 'web.id', 'my.id', 'biz.id', 'co.th', 'in.th',
  'com.ua', 'net.ua', 'org.ua', 'com.pl', 'net.pl', 'org.pl',
  'com.ru', 'com.ph', 'com.my', 'com.vn', 'com.pk', 'com.bd', 'com.np',
  'com.lk', 'com.kh', 'com.mm',
  'com.ng', 'co.ke', 'co.tz', 'co.ug', 'com.gh', 'com.eg', 'com.ma', 'com.dz',
  'com.sa', 'com.qa', 'com.kw', 'com.bh', 'com.om', 'com.jo', 'com.lb',
  'co.at', 'or.at', 'ac.at', 'gv.at', 'com.es', 'com.pt', 'com.gr', 'com.cy',
  'com.hr', 'com.ro', 'com.ee', 'com.lv',

  // ── Shared-tenant hosting (see note 2 above) ───────────────────────────
  'github.io', 'gitlab.io', 'github.dev', 'pages.dev', 'workers.dev', 'r2.dev',
  'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com', 'appspot.com',
  'herokuapp.com', 'onrender.com', 'fly.dev', 'railway.app', 'koyeb.app',
  'surge.sh', 'glitch.me', 'repl.co', 'replit.dev', 'cloudfront.net',
  'azurewebsites.net', 'azurestaticapps.net', 'blogspot.com', 'wordpress.com',
  'myshopify.com', 'squarespace.com', 'webflow.io', 'wixsite.com',
  'zendesk.com', 'freshdesk.com', 'atlassian.net', 'sharepoint.com',
  'notion.site', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com',
]);

// Hosts on otherwise-trusted platforms that serve content authored by
// arbitrary customers — static-site buckets, form builders, script hosts.
// Phishing kits live on exactly these (a Google Form, an Azure blob page "on
// microsoft's domain"), so a page here must never inherit the platform's
// KNOWN_LEGITIMATE_DOMAINS trust, and must never be "same site" with a
// credential saved on a DIFFERENT host of the same platform.
//
// Kept in lockstep with UserContentHostSuffixes in the backend's
// apps/core-api/modules/domainrisk/domain_risk.go.
export const USER_CONTENT_HOST_SUFFIXES: readonly string[] = [
  // Google
  'sites.google.com', 'docs.google.com', 'script.google.com', 'forms.gle',
  'storage.googleapis.com', 'firebasestorage.googleapis.com', 'googleusercontent.com',
  // Microsoft
  'blob.core.windows.net', 'web.core.windows.net', 'file.core.windows.net',
  'forms.office.com', 'forms.microsoft.com', 'sway.office.com', 'sway.cloud.microsoft',
  // AWS — every *.amazonaws.com host is customer-controlled (S3, API Gateway,
  // Lambda URLs). AWS's own sign-in lives on amazon.com / signin.aws / awsapps.com.
  'amazonaws.com', 'amazoncognito.com',
  // Salesforce Sites / Experience Cloud
  'force.com', 'my.site.com',
  // Misc
  'canva.site', 'dropboxusercontent.com', 'box.net',
];

/**
 * Free web-hosting, serverless and tunnel domains where anyone can publish a
 * page in minutes. Harmless on their own; a brand LOGIN page on one is a
 * strong phishing signal (see utils/pageRisk.ts).
 */
export const FREE_HOSTING_SUFFIXES: readonly string[] = [
  'pages.dev', 'workers.dev', 'r2.dev', 'web.app', 'firebaseapp.com', 'netlify.app', 'vercel.app',
  'github.io', 'gitlab.io', 'glitch.me', 'repl.co', 'replit.dev', 'replit.app', 'herokuapp.com',
  'onrender.com', 'fly.dev', 'railway.app', 'surge.sh', 'deno.dev', 'azurewebsites.net',
  'azurestaticapps.net', 'appspot.com', 'cloudfunctions.net', 'run.app', 'ngrok.io', 'ngrok.app',
  'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'duckdns.org', 'no-ip.org',
  'ddns.net', '000webhostapp.com', 'weebly.com', 'wixsite.com', 'webflow.io', 'square.site',
  'blogspot.com', 'wordpress.com', 'godaddysites.com', 'mystrikingly.com', 'jimdosite.com',
  'ipfs.io', 'dweb.link', 'ipfs.dweb.link', 'framer.app', 'framer.website', 'notion.site',
  'typedream.app', 'carrd.co', 'tiiny.site',
];

export function isFreeHostingHost(host: string): boolean {
  const h = normalizeHostname(host);
  if (!h) return false;
  return FREE_HOSTING_SUFFIXES.some((suf) => h.endsWith('.' + suf));
}

/** True when `host` is (or is under) a customer-content hosting suffix. */
export function isUserContentHost(host: string): boolean {
  const h = normalizeHostname(host);
  if (!h) return false;
  return USER_CONTENT_HOST_SUFFIXES.some((suf) => h === suf || h.endsWith('.' + suf));
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Lower-cases, trims and strips a trailing dot and a leading `www.`. */
export function normalizeHostname(host: string): string {
  let h = (host || '').trim().toLowerCase();
  h = h.replace(/\.+$/, '');
  h = h.replace(/^www\./, '');
  return h;
}

/**
 * Extracts a normalized hostname from an arbitrary user-entered URL or bare
 * host. Missing schemes are tolerated. Returns '' when nothing usable is found.
 */
export function extractHostname(input: string): string {
  if (!input) return '';
  let s = input.trim().toLowerCase();
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) {
    s = 'https://' + s;
  }
  try {
    return normalizeHostname(new URL(s).hostname);
  } catch {
    // Best-effort fallback: take the authority-looking part.
    const m = input.trim().toLowerCase().match(/^[a-z]*:?\/*([^/?#\s]+)/);
    return normalizeHostname(m ? m[1] : input);
  }
}

/**
 * Computes the registrable ("same site") domain for a host, e.g.
 *   login.example.co.uk -> example.co.uk
 *   a.b.example.com      -> example.com
 * IP addresses and `localhost` are returned unchanged.
 */
export function registrableDomain(host: string): string {
  const h = normalizeHostname(host);
  if (!h || h === 'localhost' || IPV4_RE.test(h) || h.includes(':')) return h;

  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Returns `host` with its public suffix removed, e.g.
 *   login.example.co.uk -> login.example
 *   paypa1.com          -> paypa1
 *
 * Homoglyph/brand comparisons run over this rather than the whole hostname:
 * the suffix is registry-controlled and identical across legitimate and
 * deceptive domains alike, so including it only adds noise (and, once the
 * leet-substitution entries in HOMOGLYPH_MAP are applied, false signal).
 */
export function stripPublicSuffix(host: string): string {
  const h = normalizeHostname(host);
  if (!h) return '';
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 1) return h;
  // The suffix is two labels for a known multi-part suffix (co.uk, github.io),
  // one otherwise. Mirrors registrableDomain's rule, so the two never disagree
  // about where the registrable part of a hostname begins.
  const suffixLabels = MULTI_PART_SUFFIXES.has(parts.slice(-2).join('.')) ? 2 : 1;
  if (parts.length <= suffixLabels) return h;
  return parts.slice(0, parts.length - suffixLabels).join('.');
}

/** True when `host` equals `base` or is a subdomain of it. */
export function isSubdomainOf(host: string, base: string): boolean {
  const h = normalizeHostname(host);
  const b = normalizeHostname(base);
  if (!h || !b) return false;
  return h === b || h.endsWith('.' + b);
}

/**
 * Decides whether a stored credential (whose saved URL/host is `credInput`) may
 * be offered for the page at `pageHost`.
 *
 * A match requires an exact host, a genuine sub/parent-domain relationship, or
 * an identical registrable domain. This rejects the classic suffix-confusion
 * attacks (e.g. `example.com.evil.com` will NOT match `example.com`) that the
 * previous `includes()`-based logic allowed.
 */
export function isDomainMatch(pageHost: string, credInput: string): boolean {
  const page = normalizeHostname(pageHost);
  const cred = extractHostname(credInput);
  if (!page || !cred) return false;

  if (page === cred) return true;

  // On a customer-content host only the exact saved host counts — sharing
  // google.com with accounts.google.com does not make sites.google.com/view/x
  // Google's page, and the same goes for tenants on *.blob.core.windows.net.
  if (isUserContentHost(page) || isUserContentHost(cred)) return false;

  if (isSubdomainOf(page, cred) || isSubdomainOf(cred, page)) return true;

  const rp = registrableDomain(page);
  const rc = registrableDomain(cred);
  if (rp && rc && rp === rc) return true;

  // AWS SSO / IAM Identity Center cross-domain compatibility:
  // AWS SSO portals live on *.awsapps.com, *.signin.aws, and *.aws.amazon.com
  const isAwsDomain = (h: string) =>
    h.endsWith('.awsapps.com') ||
    h === 'awsapps.com' ||
    h.endsWith('.signin.aws') ||
    h === 'signin.aws' ||
    h.endsWith('.aws.amazon.com') ||
    h === 'aws.amazon.com';

  if (isAwsDomain(page) && isAwsDomain(cred)) {
    return true;
  }

  return false;
}

export interface FrameContext {
  /** Whether the script runs in the top-level frame. */
  isTop: boolean;
  /** Origin of this frame. */
  selfOrigin: string;
  /**
   * Origin of the top frame, or null when it could not be read (which itself
   * implies a cross-origin top frame).
   */
  topOrigin: string | null;
  /** location.ancestorOrigins contents, if available. */
  ancestorOrigins?: string[];
}

/**
 * Pure decision used to gate autofill inside iframes. Returns true when the
 * frame is a third-party (cross-origin) sub-frame, where autofill must be
 * blocked. The content script mirrors this logic against the live `window`.
 */
export function isThirdPartyFrame(ctx: FrameContext): boolean {
  if (ctx.isTop) return false;

  // Unreadable top origin => cross-origin parent => third-party.
  if (ctx.topOrigin === null || ctx.topOrigin !== ctx.selfOrigin) return true;

  // Any cross-origin ancestor also makes this a third-party embedding.
  if (ctx.ancestorOrigins) {
    for (const origin of ctx.ancestorOrigins) {
      if (origin !== ctx.selfOrigin) return true;
    }
  }
  return false;
}

/** Classic Levenshtein edit distance. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array(b.length + 1).fill(0);

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

/** True when any label of the host is IDN/punycode-encoded (`xn--`). */
export function hasPunycode(host: string): boolean {
  return normalizeHostname(host)
    .split('.')
    .some((label) => label.startsWith('xn--'));
}

export interface LookalikeResult {
  /** The known/legitimate host the page appears to be impersonating. */
  target: string;
  /** Why it was flagged. */
  reason: 'punycode' | 'typosquat' | 'brand_abuse' | 'suspicious_tld' | string;
  /** Optional risk score (0-100). */
  riskScore?: number;
  /** Explainable threat reasons. */
  reasons?: string[];
}

/**
 * Detects whether `pageHost` looks like a deceptive variant of one of the
 * user's known credential hosts (`knownHosts`) without actually matching it.
 * Returns null when the page is either a legitimate match or unrelated.
 *
 * Checks:
 *  - IDN/punycode homograph domains.
 *  - Brand keyword abuse (e.g. stripe-login.example).
 *  - Typosquats within a small edit distance of a known registrable domain.
 *  - Suspicious TLD changes for saved brands.
 */
export function findLookalikeTarget(
  pageHost: string,
  knownHosts: string[],
  allowlist: string[] = []
): LookalikeResult | null {
  const pageReg = registrableDomain(pageHost);
  if (!pageReg) return null;

  // Allowlist check – if the current host is explicitly allowed, skip lookalike detection
  const isAllowlisted = allowlist.some((allowed) => {
    const a = normalizeHostname(allowed);
    return (
      a &&
      (pageHost === a ||
        isSubdomainOf(pageHost, a) ||
        registrableDomain(pageHost) === registrableDomain(a))
    );
  });
  if (isAllowlisted) return null;

  // An IDN/punycode page is a homograph-attack risk on its own: its encoded
  // form can't be meaningfully edit-distance-compared, so it is treated as
  // suspicious whenever it does not match a known site.
  const pageIsPuny = hasPunycode(pageHost);

  let bestTypo: string | null = null;
  let bestTypoDistance = Infinity;
  let closestKnown: string | null = null;
  let closestDistance = Infinity;
  
  for (const raw of knownHosts) {
    const knownReg = registrableDomain(extractHostname(raw));
    if (!knownReg) continue;

    // A legitimate, matching site is never a lookalike.
    if (knownReg === pageReg || isDomainMatch(pageHost, raw)) return null;
    const distance = levenshtein(pageReg, knownReg);
    if (distance < closestDistance) {
      closestDistance = distance;
      closestKnown = knownReg;
    }

    // Typosquat: a tiny, non-zero edit distance on domains long enough that a
    // 1-2 char change is unlikely to be coincidental.
    const minLen = Math.min(pageReg.length, knownReg.length);
    if (
      distance > 0 &&
      distance <= 2 &&
      minLen >= 5 &&
      Math.abs(pageReg.length - knownReg.length) <= 2 &&
      distance < bestTypoDistance
    ) {
      bestTypoDistance = distance;
      bestTypo = knownReg;
    }
  }

  if (bestTypo) return { target: bestTypo, reason: 'typosquat' };
  if (pageIsPuny && closestKnown) return { target: closestKnown, reason: 'punycode' };
  return null;
}

export * from './domainRisk';

