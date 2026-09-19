// Local page-structure scoring (no network, no AI).
//
// The same page signals the server's classifier receives
// (utils/pageSignals.ts) — brand names shown vs. the real domain, password
// fields, form targets, fake browser windows, hosting type — scored ON THE
// DEVICE, so "says Microsoft 365, lives on some-host.pages.dev, asks for a
// password" is caught offline, while locked, and for free users.
//
// Conservative by design while it is new: capped at PAGE_RISK_CAP (a warning,
// never a block) except for fake browser windows asking for a password.

import type { PageSignals } from './pageSignals';
import { BRAND_CATALOG, brandOwnsHost, type CatalogBrand } from './brandCatalog';
import { isFreeHostingHost, isUserContentHost, normalizeHostname } from './siteTrust';

export const PAGE_RISK_CAP = 70;
const FAKE_WINDOW_SCORE = 85;

/** Sign-in-with buttons name these without impersonating them. */
const IDENTITY_PROVIDERS = new Set(['google', 'apple', 'microsoft', 'github', 'facebook', 'twitter', 'linkedin']);

export interface PageRisk {
  score: number;
  reasons: string[];
  /** Catalog brand the page claims to be but isn't. */
  impersonated?: string;
  impersonatedDomain?: string;
}

function hostCarriesBrand(host: string, token: string): boolean {
  return new RegExp(`(^|[.-])${token}([.-]|$)`).test(host);
}

export function scorePageSignals(
  sig: PageSignals | undefined | null,
  pageHost: string,
  brands: readonly CatalogBrand[] = BRAND_CATALOG
): PageRisk {
  const out: PageRisk = { score: 0, reasons: [] };
  if (!sig) return out;
  const host = normalizeHostname(pageHost);
  if (!host) return out;
  const pw = (sig.password_field_count || 0) > 0;
  const byToken = new Map(brands.map((b) => [b.token, b] as const));
  const userContent = isUserContentHost(host);
  const freeHost = isFreeHostingHost(host);

  // Brands the page presents itself as (title and icon are strong; body text
  // is weaker and ignores "Sign in with Google"-style buttons).
  const strong = new Set<string>([...(sig.title_brand_tokens || [])]);
  if (sig.favicon_brand) strong.add(sig.favicon_brand);
  const weak = new Set<string>((sig.visible_brand_tokens || []).filter((t) => !strong.has(t) && !IDENTITY_PROVIDERS.has(t)));

  const mismatch = (token: string): CatalogBrand | null => {
    const b = byToken.get(token);
    if (!b) return null;
    if (brandOwnsHost(b, host)) return null;
    // brand-in-the-name hosts (paypal-login.xyz) are the domain rules' job,
    // except on shared hosting where the name proves nothing.
    if (!userContent && !freeHost && hostCarriesBrand(host, token)) return null;
    return b;
  };

  let score = 0;
  const add = (n: number, reason: string) => {
    score += n;
    out.reasons.push(reason);
  };

  let claimed: CatalogBrand | null = null;
  for (const t of strong) claimed = claimed || mismatch(t);
  if (claimed && pw) {
    add(55, `This page presents itself as ${claimed.name} but is not on ${claimed.domains[0]}`);
  } else {
    let weakClaim: CatalogBrand | null = null;
    for (const t of weak) weakClaim = weakClaim || mismatch(t);
    if (weakClaim && pw) {
      claimed = weakClaim;
      add(25, `This login page mentions ${weakClaim.name} but is not on ${weakClaim.domains[0]}`);
    }
  }
  if (claimed) {
    out.impersonated = claimed.name;
    out.impersonatedDomain = claimed.domains[0];
  }

  if (pw && freeHost) add(20, 'Login page on a free hosting service, where anyone can publish a page');
  else if (pw && userContent && claimed) add(15, 'Login form inside a shared document or file-hosting page');
  if (pw && sig.has_ip_host) add(25, 'Login page on a raw IP address instead of a website name');
  if (sig.has_at_symbol) add(30, 'The address hides the real site behind an "@"');
  if (pw && sig.form_action_insecure) add(15, 'The login form sends your password unencrypted');
  if (pw && sig.form_action_cross_origin && claimed) add(10, 'The login form sends your password to a different site');
  if (pw && claimed && (sig.external_brand_origins || []).length) add(10, "Loads the real brand's images from its servers");
  if (pw && (sig.subdomain_depth || 0) >= 4) add(10, 'Unusually long, deeply nested web address');

  if (sig.fake_browser_chrome && pw) {
    score = Math.max(score, FAKE_WINDOW_SCORE);
    out.reasons.unshift('Fake browser window asking for a password (a common way to steal logins)');
  } else if (sig.fake_browser_chrome) {
    add(40, 'The page draws a fake browser window');
  }

  const fakeWindow = !!sig.fake_browser_chrome && pw;
  out.score = Math.min(fakeWindow ? FAKE_WINDOW_SCORE : PAGE_RISK_CAP, score);
  return out;
}


/**
 * Folds a page-structure score into a domain assessment (never lowers it,
 * never touches an allowlisted or saved site).
 */
export function applyPageRisk<T extends {
  riskScore: number;
  riskLevel: string;
  decision: string;
  reasons: string[];
  matchedTarget: string | null;
  isAllowlisted: boolean;
  signals: { isSameRegistrableDomain: boolean };
}>(risk: T, page: PageRisk, thresholds: { warnScore?: number; blockScore?: number } = {}): T {
  if (risk.isAllowlisted || risk.signals.isSameRegistrableDomain || page.score <= risk.riskScore) return risk;
  const warn = thresholds.warnScore ?? 40;
  const block = thresholds.blockScore ?? 75;
  const decision = page.score >= block ? 'block' : page.score >= warn ? 'warn' : risk.decision;
  const riskLevel = page.score >= 90 ? 'critical' : page.score >= block ? 'high' : page.score >= warn ? 'medium' : 'low';
  return {
    ...risk,
    riskScore: page.score,
    riskLevel,
    decision,
    matchedTarget: risk.matchedTarget || page.impersonatedDomain || null,
    reasons: Array.from(new Set([...page.reasons, ...risk.reasons])),
  };
}
