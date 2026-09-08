// On-device page feature extraction for the phishing classifier.
//
// ── The privacy contract ────────────────────────────────────────────────────
// PageSignals is the ENTIRE page-derived payload that ever leaves the device,
// and it is structural only: booleans, counts, and brand names drawn from a
// FIXED PUBLIC LEXICON below. No page text, no form values, no user input, no
// screenshot, no URL beyond its shape. The type is the guarantee — there is no
// field here that free text could occupy, which is what keeps the zero-
// knowledge claim in SECURITY_ASVS_ASSESSMENT.md true for this feature.
//
// The server re-verifies every brand token against its own copy of the lexicon
// (filterKnownBrands in page_classifier.go) before scoring or building a model
// payload, so a compromised content script cannot smuggle strings outward
// either. Both halves of that check are deliberate; keep both.
//
// Pure by design: the functions here take primitives so they can be unit-tested
// under the node test environment. collectPageSignals is the one DOM adapter.

import { extractHostname, registrableDomain } from './siteTrust';

export interface PageSignals {
  visible_brand_tokens?: string[];
  title_brand_tokens?: string[];
  path_brand_tokens?: string[];
  external_brand_origins?: string[];
  favicon_cross_origin?: boolean;
  has_favicon?: boolean;

  password_field_count?: number;
  hidden_input_count?: number;
  offscreen_input_count?: number;
  form_action_cross_origin?: boolean;
  form_action_insecure?: boolean;
  autocomplete_disabled?: boolean;

  subdomain_depth?: number;
  path_depth?: number;
  has_at_symbol?: boolean;
  has_ip_host?: boolean;
  punycode_labels?: number;
  encoded_char_count?: number;
  non_standard_port?: boolean;

  noindex?: boolean;
  external_script_origins?: number;
  inline_script_bytes?: number;
  blocks_context_menu?: boolean;
  fake_browser_chrome?: boolean;
}

/**
 * Commonly impersonated brands. Must stay in step with BrandLexicon in
 * apps/core-api/modules/domainrisk/page_classifier.go — the server drops
 * anything it does not recognise, so a token added only here is silently
 * ignored rather than acted on.
 */
export const BRAND_LEXICON: ReadonlySet<string> = new Set([
  'paypal', 'microsoft', 'office365', 'outlook',
  'google', 'gmail', 'apple', 'icloud',
  'amazon', 'aws', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'linkedin', 'twitter',
  'github', 'gitlab', 'dropbox', 'slack',
  'zoom', 'docusign', 'adobe', 'stripe',
  'coinbase', 'binance', 'metamask', 'kraken',
  'chase', 'wellsfargo', 'hsbc', 'barclays',
  'citibank', 'revolut', 'wise', 'westernunion',
  'dhl', 'fedex', 'ups', 'usps', 'royalmail',
]);

/** Multi-word brand spellings folded to their lexicon token. */
const BRAND_ALIASES: ReadonlyArray<[RegExp, string]> = [
  [/\boffice\s*365\b/g, 'office365'],
  [/\bwells\s*fargo\b/g, 'wellsfargo'],
  [/\bwestern\s*union\b/g, 'westernunion'],
  [/\broyal\s*mail\b/g, 'royalmail'],
];

const MAX_TOKENS = 8;

/**
 * Lexicon brands named in a piece of page text. Returns membership only - the
 * text itself never leaves this function.
 */
export function brandTokensIn(text: string): string[] {
  if (!text) return [];
  let normalized = text.toLowerCase();
  for (const [pattern, token] of BRAND_ALIASES) {
    normalized = normalized.replace(pattern, token);
  }
  const found = new Set<string>();
  for (const token of normalized.split(/[^a-z0-9]+/)) {
    if (token && BRAND_LEXICON.has(token)) {
      found.add(token);
      if (found.size >= MAX_TOKENS) break;
    }
  }
  return Array.from(found).sort();
}

/** Shape of a URL - never its query values, only counts and flags. */
export function analyzeUrl(rawUrl: string): Pick<
  PageSignals,
  'subdomain_depth' | 'path_depth' | 'has_at_symbol' | 'has_ip_host' | 'punycode_labels' | 'encoded_char_count' | 'non_standard_port' | 'path_brand_tokens'
> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return {};
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split('.').filter(Boolean);
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

  return {
    // Labels beyond the registrable domain. login.secure.acct.evil.top -> 3.
    subdomain_depth: Math.max(0, labels.length - registrableDomain(host).split('.').length),
    path_depth: url.pathname.split('/').filter(Boolean).length,
    // An @ in the authority makes everything before it userinfo, not the host,
    // so the visible "paypal.com" in paypal.com@evil.top is decoration.
    has_at_symbol: rawUrl.includes('@') && rawUrl.indexOf('@') < (rawUrl.indexOf('/', 8) === -1 ? rawUrl.length : rawUrl.indexOf('/', 8)),
    has_ip_host: isIpv4 || host.startsWith('['),
    punycode_labels: labels.filter((l) => l.startsWith('xn--')).length,
    encoded_char_count: (rawUrl.match(/%[0-9a-f]{2}/gi) || []).length,
    non_standard_port: !!url.port && url.port !== '80' && url.port !== '443',
    // A brand in the path carries no authority - evil.top/paypal/verify.
    path_brand_tokens: brandTokensIn(decodeSafely(url.pathname + ' ' + url.search)),
  };
}

function decodeSafely(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Official OAuth / OIDC / Federated Identity SDK and asset hosts. Loading SDK scripts
 * or official sign-in button icons from these hosts on a third-party site is standard
 * web practice and should NOT be flagged as asset hotlinking or impersonation.
 */
export const FEDERATED_SSO_ASSET_HOSTS: ReadonlySet<string> = new Set([
  'accounts.google.com',
  'apis.google.com',
  'appleid.apple.com',
  'appleid.cdn-apple.com',
  'login.microsoftonline.com',
  'connect.facebook.net',
]);

/**
 * Lexicon brands whose OWN domains serve subresources to this page. A page
 * hotlinking the real brand's asset CDN while living elsewhere is copying a
 * login page, which is cheap to detect and expensive for an attacker to avoid.
 */
export function brandsFromResourceOrigins(urls: string[], pageHost: string): string[] {
  const pageReg = registrableDomain(extractHostname(pageHost));
  const found = new Set<string>();
  for (const raw of urls) {
    const host = extractHostname(raw);
    if (!host) continue;
    if (FEDERATED_SSO_ASSET_HOSTS.has(host)) continue;
    const reg = registrableDomain(host);
    if (!reg || reg === pageReg) continue;
    const brand = reg.split('.')[0];
    if (BRAND_LEXICON.has(brand)) found.add(brand);
    if (found.size >= MAX_TOKENS) break;
  }
  return Array.from(found).sort();
}

/**
 * A descriptor of one positioned element, as read from the DOM. Kept as plain
 * data so the detection rule below is testable without a browser.
 */
export interface ChromeCandidate {
  /** CSS position of the element. */
  position: string;
  /** Distance from the top of the viewport, in pixels. */
  top: number;
  /** Width, in pixels. */
  width: number;
  /** Whether a descendant renders a padlock (SVG/img/emoji). */
  hasLockGlyph: boolean;
  /** Whether a descendant's text reads as an absolute https URL. */
  hasUrlText: boolean;
  /** Whether a descendant looks like window controls (close/minimise dots). */
  hasWindowControls: boolean;
}

/**
 * Browser-in-the-browser detection: a page drawing an imitation browser window,
 * complete with its own address bar and padlock, so the victim reads a URL and
 * a lock that belong to a <div> rather than to the browser.
 *
 * No hostname or URL heuristic can see this attack - the real address bar shows
 * the attacker's domain the whole time, and the victim is looking at the fake
 * one. It is only visible from the DOM, which is why this signal exists.
 *
 * Requires a positioned element near the top of the page that renders BOTH a
 * URL-like string AND either a padlock or window controls. Any one of those
 * alone is ordinary web design.
 */
export function looksLikeFakeBrowserChrome(candidates: ChromeCandidate[]): boolean {
  return candidates.some(
    (c) =>
      (c.position === 'fixed' || c.position === 'absolute') &&
      c.top < 250 &&
      c.width > 300 &&
      c.hasUrlText &&
      (c.hasLockGlyph || c.hasWindowControls)
  );
}

/** True when a page has enough going on to be worth a server-side verdict. */
export function isWorthAssessing(signals: PageSignals): boolean {
  return (
    (signals.password_field_count || 0) > 0 ||
    (signals.title_brand_tokens || []).length > 0 ||
    (signals.visible_brand_tokens || []).length > 0 ||
    !!signals.fake_browser_chrome
  );
}

// ── DOM adapter ─────────────────────────────────────────────────────────────
// The one function here that touches the page. Everything above is pure and
// unit-tested; this assembles their inputs from the live document.

const URL_TEXT_RE = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i;
const LOCK_HINT_RE = /lock|padlock|secure|ssl/i;
const WINDOW_CONTROL_RE = /titlebar|window-control|traffic-light|close-btn|window-header/i;

/**
 * Reads the current page into a PageSignals vector. Returns counts, booleans
 * and lexicon membership only - see the privacy contract at the top of this
 * file. Never throws: a page that resists inspection yields fewer signals, not
 * an exception on the autofill path.
 */
export function collectPageSignals(): PageSignals {
  try {
    const loc = window.location;
    const signals: PageSignals = { ...analyzeUrl(loc.href) };

    // ── Brand claims ──
    signals.title_brand_tokens = brandTokensIn(document.title || '');

    // Headings, link text and image alt text - the places a page announces
    // whose login it claims to be. Bounded so a huge DOM can't stall the page.
    const visibleParts: string[] = [];
    const headings = Array.from(document.querySelectorAll('h1, h2, h3, [role="heading"]')).slice(0, 20);
    for (const el of headings) visibleParts.push(el.textContent || '');
    const imgs = Array.from(document.querySelectorAll('img[alt]')).slice(0, 30);
    for (const el of imgs) visibleParts.push(el.getAttribute('alt') || '');
    const labels = Array.from(document.querySelectorAll('label, button, a')).slice(0, 60);
    for (const el of labels) visibleParts.push(el.textContent || '');
    signals.visible_brand_tokens = brandTokensIn(visibleParts.join(' '));

    // ── Resource origins ──
    const resourceUrls: string[] = [];
    const scripts = Array.from(document.querySelectorAll('script[src]')).slice(0, 60);
    for (const el of scripts) resourceUrls.push(el.getAttribute('src') || '');
    const images = Array.from(document.querySelectorAll('img[src]')).slice(0, 60);
    for (const el of images) resourceUrls.push(el.getAttribute('src') || '');
    signals.external_brand_origins = brandsFromResourceOrigins(resourceUrls, loc.hostname);

    const externalOrigins = new Set<string>();
    for (const raw of resourceUrls) {
      const host = extractHostname(raw);
      if (host && host !== extractHostname(loc.hostname)) externalOrigins.add(host);
    }
    signals.external_script_origins = externalOrigins.size;

    // ── Favicon ──
    const icon = document.querySelector('link[rel~="icon"]');
    signals.has_favicon = !!icon;
    if (icon) {
      const iconHost = extractHostname(icon.getAttribute('href') || '');
      signals.favicon_cross_origin = !!iconHost && iconHost !== extractHostname(loc.hostname);
    }

    // ── Form shape ──
    const allInputs = Array.from(document.querySelectorAll('input'));
    const passwords = allInputs.filter((el) => el.type === 'password');
    signals.password_field_count = passwords.length;
    signals.hidden_input_count = allInputs.filter((el) => el.type === 'hidden').length;
    signals.offscreen_input_count = allInputs.filter((el) => {
      if (el.type === 'hidden') return false; // legitimately invisible by design
      const r = el.getBoundingClientRect();
      return r.width === 0 || r.height === 0 || r.right < 0 || r.bottom < 0 || r.left > window.innerWidth * 2;
    }).length;
    signals.autocomplete_disabled = passwords.some(
      (el) => (el.getAttribute('autocomplete') || '').toLowerCase() === 'off'
    );

    const form = passwords[0]?.closest('form') || document.querySelector('form');
    const rawAction = form?.getAttribute('action');
    if (rawAction) {
      try {
        const action = new URL(rawAction, loc.href);
        signals.form_action_insecure = action.protocol === 'http:' && action.hostname !== 'localhost';
        signals.form_action_cross_origin =
          registrableDomain(action.hostname) !== registrableDomain(extractHostname(loc.hostname));
      } catch {
        /* unparseable action - report nothing rather than something wrong */
      }
    }

    // ── Provenance and evasion ──
    const robots = document.querySelector('meta[name="robots"]');
    signals.noindex = /noindex/i.test(robots?.getAttribute('content') || '');

    let inlineBytes = 0;
    const inline = Array.from(document.querySelectorAll('script:not([src])')).slice(0, 40);
    for (const el of inline) inlineBytes += (el.textContent || '').length;
    signals.inline_script_bytes = inlineBytes;

    signals.blocks_context_menu =
      !!document.body?.getAttribute('oncontextmenu') || !!document.documentElement.getAttribute('oncontextmenu');

    // ── Browser-in-the-browser ──
    signals.fake_browser_chrome = looksLikeFakeBrowserChrome(readChromeCandidates());

    return signals;
  } catch {
    return {};
  }
}

/** Builds ChromeCandidate descriptors from positioned elements near the top. */
function readChromeCandidates(): ChromeCandidate[] {
  const out: ChromeCandidate[] = [];
  try {
    const els = Array.from(document.querySelectorAll('div, section, header')).slice(0, 400);
    for (const el of els) {
      const style = window.getComputedStyle(el);
      if (style.position !== 'fixed' && style.position !== 'absolute') continue;
      const rect = el.getBoundingClientRect();
      if (rect.top > 250 || rect.width < 300) continue;

      const text = (el.textContent || '').slice(0, 400);
      const html = el.innerHTML.slice(0, 4000);
      out.push({
        position: style.position,
        top: rect.top,
        width: rect.width,
        hasUrlText: URL_TEXT_RE.test(text),
        hasLockGlyph: text.includes('\u{1F512}') || LOCK_HINT_RE.test(html),
        hasWindowControls: WINDOW_CONTROL_RE.test(html),
      });
      if (out.length >= 12) break;
    }
  } catch {
    /* inspection blocked - fall through with what we have */
  }
  return out;
}
