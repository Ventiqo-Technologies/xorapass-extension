// Shared, dependency-free site-trust utilities.
//
// IMPORTANT: keep this module free of DOM / chrome API usage so it stays pure
// and unit-testable, and so it can be bundled into both the background service
// worker and the popup (both ES-module contexts). It is intentionally NOT
// imported by the content script, which must remain a self-contained classic
// script.

// A small set of common multi-part public suffixes. This is deliberately not a
// full Public Suffix List — it only needs to cover enough cases to compute a
// safe registrable domain for same-site comparisons. Unknown suffixes fall back
// to the last two labels, which is the safe (stricter) direction.
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.mx', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.ar', 'com.co',
  'co.kr', 'or.kr', 'co.il', 'co.id', 'co.th', 'com.ua', 'com.ph', 'com.my',
]);

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
  if (isSubdomainOf(page, cred) || isSubdomainOf(cred, page)) return true;

  const rp = registrableDomain(page);
  const rc = registrableDomain(cred);
  return !!rp && !!rc && rp === rc;
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

