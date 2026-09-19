// Regression suite for the LOCAL checks (no network): known phishing
// patterns must be caught with an EMPTY vault (locked / new user), and
// popular real sites — including ones that contain brand words — must not be.
import { describe, it, expect } from 'vitest';
import { assessWithCatalog, normalizeLookalike } from './domainRisk';
import { scorePageSignals, applyPageRisk, PAGE_RISK_CAP } from './pageRisk';
import { isFreeHostingHost } from './siteTrust';
import { mergeExtraBrands } from './brandCatalog';

const check = (host: string, vault: string[] = []) => assessWithCatalog(host, vault, [], `https://${host}/`);

const PHISHING: [string, 'warn' | 'block'][] = [
  ['paypal-secure-login.xyz', 'block'],
  ['microsoft-login-verify.com', 'block'],
  ['rnicrosoft.com', 'block'],
  ['pay-pal.com', 'block'],
  ['paypal.com.account-review.io', 'block'],
  ['login.microsoftonline.com.evil.top', 'block'],
  ['netflix-account-verify.xyz', 'block'],
  ['coinbase-wallet-login.com', 'block'],
  ['xn--pypal-4ve.com', 'block'],
  ['paypa1.com', 'warn'],
  ['metamsk.io', 'warn'],
  ['dropboxx.com', 'warn'],
  ['instagrarn.com', 'block'],
];

const LEGIT = [
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'amazon.ca', 'google.de', 'paypal.me', 'wikipedia.org',
  'reddit.com', 'stackoverflow.com', 'github.com', 'gitlab.com', 'microsoftonline.com', 'login.microsoftonline.com',
  'office.com', 'outlook.live.com', 'accounts.google.com', 'netflix.com', 'dropbox.com', 'linkedin.com', 'x.com',
  'twitter.com', 'instagram.com', 'whatsapp.com', 'apple.com', 'icloud.com', 'chase.com', 'wellsfargo.com',
  'bankofamerica.com', 'coinbase.com', 'binance.com', 'ups.com', 'usps.com', 'fedex.com', 'dhl.de', 'zoom.us',
  'slack.com', 'stripe.com', 'adobe.com', 'docusign.net', 'spotify.com', 'discord.com', 'roblox.com', 'steamcommunity.com',
  // brand words inside ordinary names
  'stream.com', 'finance.yahoo.com', 'applebees.com', 'purchase.com', 'sign-ups.io', 'pop-ups.net', 'wise-owl.com',
  'zoom-lens.com', 'apple-pie-recipes.com', 'steamdb.info', 'chaseamerica.org', 'googleblog.com', 'amazonaws.com',
  'booking-tips.net', 'slackline.com', 'dhl-tracking-help.org', 'ups-store-locator.com', 'kraken-rum.com',
  'shopify.com', 'walmart.com', 'ebay.com', 'bestbuy.com', 'target.com', 'twitch.tv', 'epicgames.com', 'notion.so',
];

describe('local checks catch phishing with an empty vault (built-in brand catalog)', () => {
  it.each(PHISHING)('%s → %s', (host, want) => {
    const r = check(host);
    if (want === 'block') expect(r.decision).toBe('block');
    else expect(['warn', 'block']).toContain(r.decision);
  });
});

describe('local checks leave real sites alone', () => {
  it.each(LEGIT)('%s → allow', (host) => {
    const r = check(host);
    expect(r.decision, `${host}: ${r.reasons.join(' | ')}`).toBe('allow');
  });
});

describe('catalog never overrides the user', () => {
  it('a saved site is trusted even if it resembles a brand', () => {
    expect(check('paypa1.com', ['paypa1.com']).decision).toBe('allow');
  });
  it('extra brands from the server extend the catalog', () => {
    const brands = mergeExtraBrands([{ token: 'acmebank', name: 'Acme Bank', domains: ['acmebank.com'] }]);
    expect(assessWithCatalog('acmebank-login-verify.com', [], [], '', {}, brands).decision).toBe('block');
    expect(assessWithCatalog('acmebank.com', [], [], '', {}, brands).decision).toBe('allow');
  });
});

describe('lookalike normalisation', () => {
  it('folds multi-character lookalikes and hyphens', () => {
    expect(normalizeLookalike('rnicrosoft')).toBe('microsoft');
    expect(normalizeLookalike('pay-pal')).toBe('paypal');
    expect(normalizeLookalike('vvise')).toBe('wise');
  });
});

describe('page-structure scoring', () => {
  it('brand login on free hosting warns (never blocks by itself)', () => {
    const r = scorePageSignals({ title_brand_tokens: ['office365'], password_field_count: 1 }, 'secure-docs.pages.dev');
    expect(r.score).toBe(PAGE_RISK_CAP);
    expect(r.impersonated).toBe('Microsoft 365');
    expect(isFreeHostingHost('secure-docs.pages.dev')).toBe(true);
  });
  it('a real brand site is not flagged', () => {
    expect(scorePageSignals({ title_brand_tokens: ['paypal'], password_field_count: 1 }, 'www.paypal.com').score).toBe(0);
    expect(scorePageSignals({ title_brand_tokens: ['microsoft'], password_field_count: 1 }, 'login.microsoftonline.com').score).toBe(0);
  });
  it('"Sign in with Google" buttons are not impersonation', () => {
    expect(scorePageSignals({ visible_brand_tokens: ['google', 'apple'], password_field_count: 1 }, 'example.com').score).toBe(0);
  });
  it('brand claim without a password field is ignored', () => {
    expect(scorePageSignals({ title_brand_tokens: ['paypal'] }, 'news.example.com').score).toBe(0);
  });
  it('a shared document impersonating a brand is caught', () => {
    expect(scorePageSignals({ title_brand_tokens: ['microsoft'], password_field_count: 1 }, 'sites.google.com').score).toBeGreaterThanOrEqual(40);
  });
  it('fake browser window asking for a password blocks', () => {
    const r = scorePageSignals({ fake_browser_chrome: true, password_field_count: 1 }, 'example.com');
    expect(r.score).toBeGreaterThanOrEqual(75);
  });
  it('page risk merges into an assessment without lowering it or touching saved sites', () => {
    const base = check('secure-docs.pages.dev');
    const merged = applyPageRisk(base, scorePageSignals({ title_brand_tokens: ['office365'], password_field_count: 1 }, 'secure-docs.pages.dev'));
    expect(merged.decision).toBe('warn');
    const saved = check('secure-docs.pages.dev', ['secure-docs.pages.dev']);
    expect(applyPageRisk(saved, { score: 70, reasons: ['x'] }).decision).toBe('allow');
  });
});
