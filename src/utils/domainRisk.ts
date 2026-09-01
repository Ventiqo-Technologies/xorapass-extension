// Pure, dependency-free domain risk and phishing detection engine.
//
// Detects:
// 1. Brand keyword abuse (e.g. stripe-login.example, login-stripe.com for stripe.com)
// 2. Punycode & IDN homograph attacks (e.g. xn--strpe-v1a.com, Cyrillic аpple.com)
// 3. Typosquatting / edit distance variations (e.g. paypa1.com, strpie.com)
// 4. Suspicious TLD changes and high-risk disposable phishing TLDs
// 5. Suspicious auth/security keyword patterns on unfamiliar domains
//
// Kept free of DOM and chrome APIs for universal unit-testability and reuse
// across background, popup, and content script contexts.

import {
  extractHostname,
  normalizeHostname,
  registrableDomain,
  isDomainMatch,
  isSubdomainOf,
  hasPunycode,
} from './siteTrust';

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type Decision = 'allow' | 'warn' | 'require_approval' | 'block';

export interface DomainRiskSignals {
  isExactMatch: boolean;
  isSubdomainMatch: boolean;
  isSameRegistrableDomain: boolean;
  hasPunycode: boolean;
  isHomograph: boolean;
  decodedPunycode?: string;
  homoglyphTarget?: string;
  editDistance?: number;
  typosquatTarget?: string;
  brandAbuse?: { brand: string; pattern: string; matchedTarget: string };
  suspiciousKeywords: string[];
  suspiciousTldChange?: { savedTld: string; currentTld: string; brand: string };
  isHighRiskTld: boolean;
  subdomainCount: number;
}

export interface DomainRiskAssessment {
  pageHostname: string;
  registrableDomain: string;
  riskScore: number; // 0 to 100
  riskLevel: RiskLevel;
  decision: Decision;
  reasons: string[];
  matchedTarget: string | null;
  isAllowlisted: boolean;
  signals: DomainRiskSignals;
  // User-friendly explanation from the backend (static or OpenAI-generated).
  // The local heuristic engine never sets this — only mergeLocalAndRemoteRisk
  // does, from the remote response's safe_warning_message.
  safeWarningMessage?: string;
}

/** Known phishing and credential-harvesting action keywords. */
export const SUSPICIOUS_KEYWORDS = new Set([
  'login',
  'signin',
  'sign-in',
  'log-in',
  'secure',
  'security',
  'verify',
  'verification',
  'account',
  'accounts',
  'support',
  'helpdesk',
  'reset',
  'password',
  'auth',
  'authorize',
  'authorization',
  'portal',
  'update',
  'billing',
  'confirm',
  'confirmation',
  'banking',
  'wallet',
  'service',
  'service-desk',
  'checkout',
  'pay',
  'payment',
  'online',
  'webscr',
  'identity',
  'validate',
  'validation',
  'recovery',
  'session',
]);

/** High-risk and frequently abused phishing/disposable TLDs. */
export const HIGH_RISK_TLDS = new Set([
  'top',
  'xyz',
  'work',
  'click',
  'fit',
  'surf',
  'stream',
  'gq',
  'cf',
  'ml',
  'tk',
  'ga',
  'rest',
  'icu',
  'zip',
  'mov',
  'cam',
  'monster',
  'cfd',
  'buzz',
  'sbs',
  'quest',
  'beauty',
  'hair',
  'skin',
  'country',
  'download',
  'racing',
  'win',
  'bid',
  'loan',
  'date',
  'faith',
  'review',
  'party',
  'trade',
  'accountant',
  'science',
]);

/**
 * Homoglyph translation table mapping common Cyrillic, Greek, lookalike Latin,
 * and leet-speak characters to standard ASCII Latin equivalents.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  '\u0430': 'a', // Cyrillic small letter a
  '\u0410': 'a', // Cyrillic capital letter A
  '\u0431': 'b', // Cyrillic small letter be
  '\u0432': 'b', // Cyrillic small letter ve
  '\u0433': 'r', // Cyrillic small letter ghe
  '\u0434': 'd', // Cyrillic small letter de
  '\u0435': 'e', // Cyrillic small letter ie
  '\u0415': 'e', // Cyrillic capital letter IE
  '\u0451': 'e', // Cyrillic small letter io
  '\u0437': 'z', // Cyrillic small letter ze
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0406': 'i', // Cyrillic capital letter BYELORUSSIAN-UKRAINIAN I
  '\u0457': 'i', // Cyrillic small letter yi
  '\u0458': 'j', // Cyrillic small letter je
  '\u043A': 'k', // Cyrillic small letter ka
  '\u041A': 'k', // Cyrillic capital letter KA
  '\u043C': 'm', // Cyrillic small letter em
  '\u041C': 'm', // Cyrillic capital letter EM
  '\u043D': 'h', // Cyrillic small letter en
  '\u041D': 'h', // Cyrillic capital letter EN
  '\u043E': 'o', // Cyrillic small letter o
  '\u041E': 'o', // Cyrillic capital letter O
  '\u043F': 'n', // Cyrillic small letter pe
  '\u0440': 'p', // Cyrillic small letter er
  '\u0420': 'p', // Cyrillic capital letter ER
  '\u0441': 'c', // Cyrillic small letter es
  '\u0421': 'c', // Cyrillic capital letter ES
  '\u0442': 't', // Cyrillic small letter te
  '\u0422': 't', // Cyrillic capital letter TE
  '\u0443': 'y', // Cyrillic small letter u
  '\u0423': 'y', // Cyrillic capital letter U
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0425': 'x', // Cyrillic capital letter HA
  '\u0455': 's', // Cyrillic small letter dze
  '\u0501': 'd', // Cyrillic small letter komi de
  '\u051B': 'q', // Cyrillic small letter qa
  '\u051D': 'w', // Cyrillic small letter we

  // Greek lookalikes
  '\u03B1': 'a', // Greek small letter alpha
  '\u0391': 'a', // Greek capital letter ALPHA
  '\u03B2': 'b', // Greek small letter beta
  '\u0392': 'b', // Greek capital letter BETA
  '\u03B5': 'e', // Greek small letter epsilon
  '\u0395': 'e', // Greek capital letter EPSILON
  '\u03B6': 'z', // Greek small letter zeta
  '\u03B7': 'n', // Greek small letter eta
  '\u03B9': 'i', // Greek small letter iota
  '\u0399': 'i', // Greek capital letter IOTA
  '\u03BA': 'k', // Greek small letter kappa
  '\u039A': 'k', // Greek capital letter KAPPA
  '\u03BD': 'v', // Greek small letter nu
  '\u03BF': 'o', // Greek small letter omicron
  '\u039F': 'o', // Greek capital letter OMICRON
  '\u03C1': 'p', // Greek small letter rho
  '\u03A1': 'p', // Greek capital letter RHO
  '\u03C4': 't', // Greek small letter tau
  '\u03A4': 't', // Greek capital letter TAU
  '\u03C5': 'u', // Greek small letter upsilon
  '\u03A5': 'y', // Greek capital letter UPSILON
  '\u03C7': 'x', // Greek small letter chi
  '\u03A7': 'x', // Greek capital letter CHI
  '\u03C9': 'w', // Greek small letter omega

  // Leet / Number substitutes
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's',
};

/**
 * Standard RFC 3492 Punycode decoder.
 * Converts a punycode string (without 'xn--') to decoded Unicode string.
 */

// RFC 3492 Punycode constants (module-scoped so adaptBias can access them)
const PUNYCODE_BASE = 36;
const PUNYCODE_TMIN = 1;
const PUNYCODE_TMAX = 26;
const PUNYCODE_DAMP = 700;
const PUNYCODE_INITIAL_BIAS = 72;
const PUNYCODE_INITIAL_N = 128;
const PUNYCODE_DELIMITER = '-';

function adaptBias(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / PUNYCODE_DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) >> 1) {
    d = Math.floor(d / (PUNYCODE_BASE - PUNYCODE_TMIN));
    k += PUNYCODE_BASE;
  }
  return k + Math.floor(((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * d) / (d + 38));
}

export function decodePunycode(input: string): string {
  const output: number[] = [];
  let n = PUNYCODE_INITIAL_N;
  let i = 0;
  let bias = PUNYCODE_INITIAL_BIAS;

  let basic = input.lastIndexOf(PUNYCODE_DELIMITER);
  if (basic < 0) {
    basic = 0;
  } else {
    for (let j = 0; j < basic; ++j) {
      const code = input.charCodeAt(j);
      if (code >= 0x80) return input;
      output.push(code);
    }
    ++basic;
  }

  while (basic < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
      if (basic >= input.length) return input;
      const char = input.charAt(basic++);
      let digit: number;
      if (char >= '0' && char <= '9') {
        digit = char.charCodeAt(0) - 22;
      } else if (char >= 'a' && char <= 'z') {
        digit = char.charCodeAt(0) - 97;
      } else if (char >= 'A' && char <= 'Z') {
        digit = char.charCodeAt(0) - 65;
      } else {
        return input;
      }

      i += digit * w;
      const t = k <= bias ? PUNYCODE_TMIN : k >= bias + PUNYCODE_TMAX ? PUNYCODE_TMAX : k - bias;
      if (digit < t) break;
      w *= PUNYCODE_BASE - t;
    }

    const outLen = output.length + 1;
    bias = adaptBias(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;

    output.splice(i, 0, n);
    ++i;
  }

  return String.fromCodePoint(...output);
}

/**
 * Decodes all `xn--` punycode labels in a hostname into their Unicode representation.
 */
export function decodeHostnamePunycode(hostname: string): string {
  const normalized = normalizeHostname(hostname);
  return normalized
    .split('.')
    .map((label) => {
      if (label.startsWith('xn--')) {
        try {
          return decodePunycode(label.slice(4));
        } catch {
          return label;
        }
      }
      return label;
    })
    .join('.');
}

/**
 * Translates homoglyphs, confusable Cyrillic/Greek, and leet characters to standard ASCII skeleton.
 */
export function toHomoglyphSkeleton(str: string): string {
  let out = '';
  for (const char of str.toLowerCase()) {
    out += HOMOGLYPH_MAP[char] || char;
  }
  return out;
}

/**
 * Extracts the primary brand name (second-level domain or base token) from a host.
 * e.g., 'stripe.com' -> 'stripe', 'login.paypal.co.uk' -> 'paypal'
 */
export function extractBrandName(hostOrUrl: string): string {
  const reg = registrableDomain(extractHostname(hostOrUrl));
  if (!reg) return '';
  const parts = reg.split('.');
  return parts[0] || '';
}

/**
 * Damerau-Levenshtein distance calculation (handles insertions, deletions, substitutions, and transpositions).
 */
export function damerauLevenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const la = a.length;
  const lb = b.length;
  const d: number[][] = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));

  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );

      // Transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }

  return d[la][lb];
}

export interface BrandProfile {
  brand: string; // e.g. "stripe"
  targetDomain: string; // e.g. "stripe.com"
  tld: string; // e.g. "com"
  rawHost: string;
}

/**
 * Builds normalized brand profiles from saved credential hosts or vault items.
 */
export function extractBrandProfiles(knownHosts: string[]): BrandProfile[] {
  const profiles: BrandProfile[] = [];
  const seen = new Set<string>();

  for (const raw of knownHosts) {
    const host = extractHostname(raw);
    const reg = registrableDomain(host);
    if (!reg || seen.has(reg)) continue;
    seen.add(reg);

    const parts = reg.split('.');
    const brand = parts[0];
    const tld = parts.slice(1).join('.');

    if (brand && brand.length >= 3) {
      profiles.push({
        brand: brand.toLowerCase(),
        targetDomain: reg.toLowerCase(),
        tld: tld.toLowerCase(),
        rawHost: host,
      });
    }
  }

  return profiles;
}

/**
 * Analyzes a hostname against known legitimate brand hosts and explicit allowlists.
 * Returns a comprehensive risk score, decision ('allow' | 'warn' | 'block'), and explainable reasons.
 */
export function assessDomainRisk(
  pageHost: string,
  knownHosts: string[],
  allowlist: string[] = []
): DomainRiskAssessment {
  const pageHostname = normalizeHostname(pageHost);
  const pageReg = registrableDomain(pageHostname);

  // Default clean assessment
  const assessment: DomainRiskAssessment = {
    pageHostname,
    registrableDomain: pageReg,
    riskScore: 0,
    riskLevel: 'safe',
    decision: 'allow',
    reasons: [],
    matchedTarget: null,
    isAllowlisted: false,
    signals: {
      isExactMatch: false,
      isSubdomainMatch: false,
      isSameRegistrableDomain: false,
      hasPunycode: false,
      isHomograph: false,
      suspiciousKeywords: [],
      isHighRiskTld: false,
      subdomainCount: pageHostname ? pageHostname.split('.').length : 0,
    },
  };

  if (!pageHostname) {
    return assessment;
  }

  // 1. Check Allowlist: if user/admin explicitly allowlisted this domain, allow immediately
  const isAllowlisted = allowlist.some((allowed) => {
    const a = normalizeHostname(allowed);
    return a && (pageHostname === a || isSubdomainOf(pageHostname, a) || registrableDomain(pageHostname) === registrableDomain(a));
  });

  if (isAllowlisted) {
    assessment.isAllowlisted = true;
    assessment.reasons.push('Domain is explicitly allowlisted by user policy');
    return assessment;
  }

  // 2. Check for Exact or Legitimate Match with Saved Credentials
  for (const raw of knownHosts) {
    if (isDomainMatch(pageHostname, raw)) {
      assessment.signals.isExactMatch = pageHostname === extractHostname(raw);
      assessment.signals.isSubdomainMatch = isSubdomainOf(pageHostname, extractHostname(raw));
      assessment.signals.isSameRegistrableDomain = true;
      assessment.matchedTarget = registrableDomain(extractHostname(raw));
      return assessment; // 0 risk, safe match
    }
  }

  // If there are no saved credentials to protect, return safe
  if (!knownHosts || knownHosts.length === 0) {
    return assessment;
  }

  const brandProfiles = extractBrandProfiles(knownHosts);
  const pageParts = pageHostname.split('.');
  const pageTld = pageParts.slice(pageParts.length > 2 ? -2 : -1).join('.');
  const pageBaseTld = pageParts[pageParts.length - 1] || '';
  const pageSld = pageParts.length >= 2 ? pageParts[pageParts.length - 2] : pageHostname;

  const isPuny = hasPunycode(pageHostname);
  assessment.signals.hasPunycode = isPuny;

  const decodedPageHost = isPuny ? decodeHostnamePunycode(pageHostname) : pageHostname;
  if (isPuny) {
    assessment.signals.decodedPunycode = decodedPageHost;
  }

  const pageSkeleton = toHomoglyphSkeleton(decodedPageHost);

  // Check for high-risk TLD
  if (HIGH_RISK_TLDS.has(pageBaseTld) || HIGH_RISK_TLDS.has(pageTld)) {
    assessment.signals.isHighRiskTld = true;
  }

  // Check for suspicious keywords in domain or subdomains
  const domainTokens = pageHostname
    .toLowerCase()
    .split(/[\.-]/)
    .filter(Boolean);
  for (const token of domainTokens) {
    if (SUSPICIOUS_KEYWORDS.has(token)) {
      if (!assessment.signals.suspiciousKeywords.includes(token)) {
        assessment.signals.suspiciousKeywords.push(token);
      }
    }
  }

  let highestScore = 0;
  const detectedReasons: string[] = [];

  for (const profile of brandProfiles) {
    const brand = profile.brand;
    const target = profile.targetDomain;
    // const targetSkeleton = toHomoglyphSkeleton(target); // unused – removed
    const brandSkeleton = toHomoglyphSkeleton(brand);

    // ──────────────────────────────────────────────────────────────────────────
    // Threat A: Punycode & IDN Homograph Attacks
    // e.g. xn--strpe-v1a.com or Cyrillic аpple.com (using U+0430) vs apple.com
    // ──────────────────────────────────────────────────────────────────────────
    const decodedReg = registrableDomain(decodedPageHost);
    const decodedRegSkeleton = toHomoglyphSkeleton(decodedReg);
    const decodedSld = decodedReg.split('.')[0] || '';
    const decodedSldSkeleton = toHomoglyphSkeleton(decodedSld);

    if (
      (isPuny || decodedPageHost !== pageHostname || pageSkeleton !== pageHostname) &&
      (decodedRegSkeleton === target ||
        decodedSldSkeleton === brand ||
        damerauLevenshtein(decodedSldSkeleton, brand) <= 1 ||
        pageSkeleton.includes(brandSkeleton))
    ) {
      const score = 95;
      if (score > highestScore) {
        highestScore = score;
        assessment.matchedTarget = target;
      }
      assessment.signals.isHomograph = true;
      assessment.signals.homoglyphTarget = target;
      detectedReasons.push(
        `Punycode/IDN homograph attack detected: deceptive characters visually mimicking "${target}" (decoded: "${decodedPageHost}")`
      );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Threat B: Brand Keyword Abuse & Deceptive Phishing Combinations
    // e.g. stripe-login.example, login-stripe.com, stripe-verify.com, account-stripe.xyz
    // ──────────────────────────────────────────────────────────────────────────
    const isBrandInHost = pageHostname.includes(brand) || decodedPageHost.includes(brand) || pageSkeleton.includes(brandSkeleton);
    const hasSuspiciousKeyword = assessment.signals.suspiciousKeywords.length > 0;

    if (isBrandInHost && pageReg !== target) {
      // Check if brand is combined with login/secure/verify keywords or hyphenated/subdomain
      const brandRegex = new RegExp(`(^|[-._])${brand}([-._]|$)`, 'i');
      const isTokenMatch = brandRegex.test(pageHostname) || brandRegex.test(pageSld) || brandRegex.test(decodedPageHost);

      if (isTokenMatch && hasSuspiciousKeyword) {
        const score = 90;
        if (score > highestScore) {
          highestScore = score;
          assessment.matchedTarget = target;
        }
        const kwList = assessment.signals.suspiciousKeywords.join(', ');
        assessment.signals.brandAbuse = {
          brand,
          pattern: `${brand} + [${kwList}]`,
          matchedTarget: target,
        };
        detectedReasons.push(
          `Brand keyword abuse: Brand "${brand}" (for "${target}") combined with security keywords [${kwList}] on unauthorized domain "${pageReg}"`
        );
      } else if (isTokenMatch) {
        // Brand name used as a prefix/suffix or token on an unrelated domain
        // e.g. stripe-portal.net, stripe-app.org
        const score = 80;
        if (score > highestScore) {
          highestScore = score;
          assessment.matchedTarget = target;
        }
        assessment.signals.brandAbuse = {
          brand,
          pattern: `${brand} token in domain`,
          matchedTarget: target,
        };
        detectedReasons.push(
          `Unauthorized brand domain: Brand token "${brand}" from saved "${target}" found in unfamiliar domain "${pageReg}"`
        );
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Threat C: Suspicious TLD / Domain Extension Changes
    // e.g. user has paypal.com, current site is paypal.xyz or paypal.top
    // ──────────────────────────────────────────────────────────────────────────
    const pageSldClean = pageSld.toLowerCase();
    if (pageSldClean === brand && pageReg !== target) {
      const isHighTld = assessment.signals.isHighRiskTld;
      const score = isHighTld ? 85 : 75;
      if (score > highestScore) {
        highestScore = score;
        assessment.matchedTarget = target;
      }
      assessment.signals.suspiciousTldChange = {
        savedTld: profile.tld,
        currentTld: pageTld,
        brand,
      };
      detectedReasons.push(
        `Suspicious TLD change: Exact brand name "${brand}" from saved "${target}" hosted on unexpected ${
          isHighTld ? 'high-risk ' : ''
        }TLD ".${pageTld}"`
      );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Threat D: Typosquatting / Edit Distance Variations
    // e.g. paypa1.com, strpie.com, gooogle.com, amazn.com
    // ──────────────────────────────────────────────────────────────────────────
    const distReg = damerauLevenshtein(pageReg, target);
    const distSld = damerauLevenshtein(pageSldClean, brand);
    const minLen = Math.min(pageSldClean.length, brand.length);

    if (distReg !== 0 && pageReg !== target) {
      // 1-2 char typosquats on brand name or registrable domain
      if (
        (distSld > 0 && distSld <= 2 && minLen >= 4 && Math.abs(pageSldClean.length - brand.length) <= 2) ||
        (distReg > 0 && distReg <= 2 && target.length >= 6 && Math.abs(pageReg.length - target.length) <= 2)
      ) {
        const score = 80;
        if (score > highestScore) {
          highestScore = score;
          assessment.matchedTarget = target;
        }
        assessment.signals.editDistance = Math.min(distReg, distSld);
        assessment.signals.typosquatTarget = target;
        detectedReasons.push(
          `Typosquatting detected: Domain "${pageReg}" is within ${assessment.signals.editDistance} edit distance of saved "${target}"`
        );
      }
    }
  }

  // Generic check for high-risk TLD with security keywords (even if brand not directly recognized)
  if (assessment.signals.isHighRiskTld && assessment.signals.suspiciousKeywords.length >= 2 && highestScore < 60) {
    highestScore = 65;
    detectedReasons.push(
      `Suspicious pattern: Multiple auth/login keywords [${assessment.signals.suspiciousKeywords.join(
        ', '
      )}] on high-risk disposable TLD ".${pageBaseTld}"`
    );
  }

  // Deduplicate reasons
  assessment.reasons = Array.from(new Set(detectedReasons));
  assessment.riskScore = highestScore;

  // Determine Risk Level and Decision
  if (highestScore >= 75) {
    assessment.riskLevel = highestScore >= 90 ? 'critical' : 'high';
    assessment.decision = 'block';
  } else if (highestScore >= 40) {
    assessment.riskLevel = 'medium';
    assessment.decision = 'warn';
  } else if (highestScore > 0) {
    assessment.riskLevel = 'low';
    assessment.decision = 'allow';
  } else {
    assessment.riskLevel = 'safe';
    assessment.decision = 'allow';
  }

  return assessment;
}
