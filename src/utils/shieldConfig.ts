// XoraPass Shield remote configuration (kill switch + tuning).
//
// Mirrors ShieldRemoteConfig in the backend
// (apps/core-api/modules/domainrisk/shield_config.go). The server can change
// any of this at runtime, so a misbehaving rule is switched off in minutes
// rather than after a store review. Every value received is validated and
// clamped here; anything missing or malformed falls back to the defaults
// below, so a broken config degrades to "normal protection", never to "off"
// (turning Shield off requires an explicit shield_enabled: false).
//
// Pure and dependency-free: used by the background worker and by tests.

export type LocalRule = 'homograph' | 'brand_abuse' | 'tld_change' | 'typosquat' | 'keyword_tld';

export const LOCAL_RULES: readonly LocalRule[] = ['homograph', 'brand_abuse', 'tld_change', 'typosquat', 'keyword_tld'];

export interface ShieldRedirectorRule {
  host_pattern: string;
  path_prefix?: string;
  query_param: string;
  type?: string;
}

export interface ShieldConfig {
  version: number;
  shield_enabled: boolean;
  nav_guard: { enabled: boolean; block_score: number; typing_guard_ms: number };
  blocklist: { enabled: boolean; refresh_minutes: number };
  remote: { enabled: boolean; min_local_score: number; on_credential_forms: boolean };
  heuristics: { disabled_rules: LocalRule[]; warn_score: number; block_score: number };
  config_refresh_minutes: number;
  ai_scan: { enabled: boolean };
  // "Is it Safe" tools (server-side quotas; these only hide/show the UI).
  image_scan: { enabled: boolean };
  file_scan: { enabled: boolean };
  file_upload: { enabled: boolean };
  email_scan: { enabled: boolean };
  trusted_domains: string[];
  /** Brands added to the built-in catalog without an extension release. */
  extra_brands: { token: string; name: string; domains: string[] }[];
  /** Dynamic redirector rules for unwrapping links without store releases. */
  redirector_rules: ShieldRedirectorRule[];
  /** ICANN brand TLDs (e.g. microsoft, google, apple). */
  brand_tlds: string[];
  /** Cloud & enterprise infrastructure domains to treat as verified platforms. */
  verified_platforms: string[];
  /** Email service provider click tracking and redirector domains. */
  esp_tracking_domains: string[];
  /** Standard external platforms routinely linked in corporate email footers (reviews, social, app stores). */
  standard_email_external_domains: string[];
  /** First-party authentic sender domains whose transactional messages are never flagged. */
  safe_sender_domains: string[];
}

export const DEFAULT_REDIRECTOR_RULES: readonly ShieldRedirectorRule[] = Object.freeze([
  { host_pattern: '*.static.microsoft', path_prefix: '/evergreen-assets/safelinks', query_param: 'url' },
  { host_pattern: '*.teams.cdn.office.net', query_param: 'url' },
  { host_pattern: 'teams.microsoft.com', path_prefix: '/l/message', query_param: 'url' },
  { host_pattern: '*.safelinks.protection.outlook.com', query_param: 'url' },
  { host_pattern: 'urldefense.proofpoint.com', type: 'proofpoint', query_param: 'u' },
  { host_pattern: 'urldefense.com', type: 'proofpoint', query_param: 'u' },
  { host_pattern: 'l.facebook.com', path_prefix: '/l.php', query_param: 'u' },
  { host_pattern: 'lm.facebook.com', path_prefix: '/l.php', query_param: 'u' },
  { host_pattern: 'l.instagram.com', query_param: 'u' },
  { host_pattern: 'out.reddit.com', query_param: 'url' },
  { host_pattern: 'slack-redir.net', query_param: 'url' },
  { host_pattern: 'youtube.com', path_prefix: '/redirect', query_param: 'q' },
  { host_pattern: 'linkedin.com', path_prefix: '/redir/', query_param: 'url' },
  { host_pattern: 'steamcommunity.com', path_prefix: '/linkfilter', query_param: 'url' },
  { host_pattern: 'href.li', type: 'raw_query', query_param: '' },
]);

export const DEFAULT_BRAND_TLDS: readonly string[] = Object.freeze([
  'microsoft', 'google', 'apple', 'amazon', 'cisco', 'sony', 'canon', 'barclays', 'kpmg',
]);

export const DEFAULT_VERIFIED_PLATFORMS: readonly string[] = Object.freeze([
  'static.microsoft', 'office.net', 'azure.com', 'windows.net', 'sharepoint.com',
  'gstatic.com', 'googleusercontent.com', 'googleapis.com',
  'apple.com', 'icloud.com', 'cdn-apple.com',
  'cloudfront.net', 'awsapps.com',
]);

export const DEFAULT_ESP_TRACKING_DOMAINS: readonly string[] = Object.freeze([
  'brevo.com', 'sendinblue.com', 'sendibt3.com', 'sendibt1.com', 'sendibt2.com',
  'sendib1.com', 'sendib2.com', 'sendib3.com', 'awstrack.me', 'mjt.lu',
  'mailjet.com', 'resend-links.com', 'sendgrid.net', 'mailgun.org', 'pstmrk.it',
  'postmarkapp.com', 'mandrillapp.com', 'mailchimp.com', 'hubspotlinks.com',
  'klaviyomail.com', 'constantcontact.com', 'campaign-monitor.com', 'customeriomail.com',
  'sparkpostmail.com', 'intercom-mail.com', 'intercom-clicks.com', 'sailthru.com',
  'acems1.com', 'activehosted.com',
]);

export const DEFAULT_STANDARD_EMAIL_EXTERNAL_DOMAINS: readonly string[] = Object.freeze([
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
  'youtube.com', 'tiktok.com', 'threads.net', 'pinterest.com', 'apple.com',
  'google.com', 'adobe.com', 'trustpilot.com', 'feefo.com', 'bazaarvoice.com',
  'yotpo.com', 'google.co.uk',
]);

export const DEFAULT_SAFE_SENDER_DOMAINS: readonly string[] = Object.freeze([
  'xorapass.com', 'xorapass.net',
]);

export const DEFAULT_SHIELD_CONFIG: ShieldConfig = Object.freeze({
  version: 1,
  shield_enabled: true,
  nav_guard: { enabled: true, block_score: 90, typing_guard_ms: 1500 },
  blocklist: { enabled: true, refresh_minutes: 30 },
  remote: { enabled: true, min_local_score: 25, on_credential_forms: true },
  heuristics: { disabled_rules: [], warn_score: 40, block_score: 75 },
  config_refresh_minutes: 15,
  ai_scan: { enabled: true },
  image_scan: { enabled: true },
  file_scan: { enabled: true },
  file_upload: { enabled: true },
  email_scan: { enabled: true },
  trusted_domains: [],
  extra_brands: [],
  redirector_rules: [...DEFAULT_REDIRECTOR_RULES],
  brand_tlds: [...DEFAULT_BRAND_TLDS],
  verified_platforms: [...DEFAULT_VERIFIED_PLATFORMS],
  esp_tracking_domains: [...DEFAULT_ESP_TRACKING_DOMAINS],
  standard_email_external_domains: [...DEFAULT_STANDARD_EMAIL_EXTERNAL_DOMAINS],
  safe_sender_domains: [...DEFAULT_SAFE_SENDER_DOMAINS],
}) as ShieldConfig;

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function bool(v: unknown, def: boolean): boolean {
  return typeof v === 'boolean' ? v : def;
}

function int(v: unknown, lo: number, hi: number, def: number): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) return def;
  return Math.min(hi, Math.max(lo, Math.round(v)));
}

const HOST_RE = /^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

/** Validates and clamps an untrusted config payload. */
export function coerceShieldConfig(input: unknown): ShieldConfig {
  const d = DEFAULT_SHIELD_CONFIG;
  const o = obj(input);
  const nav = obj(o.nav_guard);
  const bl = obj(o.blocklist);
  const rem = obj(o.remote);
  const heur = obj(o.heuristics);
  const ai = obj(o.ai_scan);

  const rules = Array.isArray(heur.disabled_rules)
    ? Array.from(
        new Set(
          heur.disabled_rules
            .filter((r): r is string => typeof r === 'string')
            .map((r) => r.trim().toLowerCase())
            .filter((r): r is LocalRule => (LOCAL_RULES as readonly string[]).includes(r))
        )
      )
    : [];

  const warn = int(heur.warn_score, 10, 90, d.heuristics.warn_score);
  let block = int(heur.block_score, 50, 100, d.heuristics.block_score);
  if (block <= warn) block = Math.min(100, warn + 10);

  const trusted = Array.isArray(o.trusted_domains)
    ? Array.from(
        new Set(
          o.trusted_domains
            .filter((h): h is string => typeof h === 'string')
            .map((h) => h.trim().toLowerCase().replace(/^www\./, ''))
            .filter((h) => HOST_RE.test(h))
        )
      ).slice(0, 5000)
    : [];

  return {
    version: int(o.version, 1, Number.MAX_SAFE_INTEGER, d.version),
    shield_enabled: bool(o.shield_enabled, d.shield_enabled),
    nav_guard: {
      enabled: bool(nav.enabled, d.nav_guard.enabled),
      block_score: int(nav.block_score, 50, 100, d.nav_guard.block_score),
      typing_guard_ms: int(nav.typing_guard_ms, 0, 5000, d.nav_guard.typing_guard_ms),
    },
    blocklist: {
      enabled: bool(bl.enabled, d.blocklist.enabled),
      refresh_minutes: int(bl.refresh_minutes, 15, 1440, d.blocklist.refresh_minutes),
    },
    remote: {
      enabled: bool(rem.enabled, d.remote.enabled),
      min_local_score: int(rem.min_local_score, 0, 100, d.remote.min_local_score),
      on_credential_forms: bool(rem.on_credential_forms, d.remote.on_credential_forms),
    },
    heuristics: { disabled_rules: rules, warn_score: warn, block_score: block },
    config_refresh_minutes: int(o.config_refresh_minutes, 5, 1440, d.config_refresh_minutes),
    ai_scan: { enabled: bool(ai.enabled, d.ai_scan.enabled) },
    image_scan: { enabled: bool(obj(o.image_scan).enabled, d.image_scan.enabled) },
    file_scan: { enabled: bool(obj(o.file_scan).enabled, d.file_scan.enabled) },
    file_upload: { enabled: bool(obj(o.file_upload).enabled, d.file_upload.enabled) },
    email_scan: { enabled: bool(obj(o.email_scan).enabled, d.email_scan.enabled) },
    trusted_domains: trusted,
    extra_brands: Array.isArray(o.extra_brands)
      ? (o.extra_brands as unknown[])
          .map((b) => obj(b))
          .filter((b) => typeof b.token === 'string' && Array.isArray(b.domains))
          .slice(0, 200)
          .map((b) => ({
            token: String(b.token).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 40),
            name: typeof b.name === 'string' ? b.name.slice(0, 60) : String(b.token),
            domains: (b.domains as unknown[])
              .filter((d): d is string => typeof d === 'string')
              .map((d) => d.trim().toLowerCase().replace(/^www\./, ''))
              .filter((d) => HOST_RE.test(d))
              .slice(0, 30),
          }))
          .filter((b) => b.token.length >= 3 && b.domains.length > 0)
      : [],
    redirector_rules: Array.isArray(o.redirector_rules) && o.redirector_rules.length > 0
      ? (o.redirector_rules as unknown[])
          .map((r) => obj(r))
          .filter((r) => typeof r.host_pattern === 'string' && typeof r.query_param === 'string')
          .slice(0, 100)
          .map((r) => ({
            host_pattern: String(r.host_pattern).trim().toLowerCase(),
            path_prefix: typeof r.path_prefix === 'string' ? String(r.path_prefix).trim() : undefined,
            query_param: String(r.query_param).trim(),
            type: typeof r.type === 'string' ? String(r.type).trim().toLowerCase() : undefined,
          }))
          .filter((r) => r.host_pattern.length > 0)
      : [...d.redirector_rules],
    brand_tlds: Array.isArray(o.brand_tlds) && o.brand_tlds.length > 0
      ? Array.from(
          new Set(
            (o.brand_tlds as unknown[])
              .filter((t): t is string => typeof t === 'string')
              .map((t) => t.trim().toLowerCase().replace(/^\./, ''))
              .filter((t) => /^[a-z0-9-]+$/.test(t))
          )
        ).slice(0, 100)
      : [...d.brand_tlds],
    verified_platforms: Array.isArray(o.verified_platforms) && o.verified_platforms.length > 0
      ? Array.from(
          new Set(
            (o.verified_platforms as unknown[])
              .filter((p): p is string => typeof p === 'string')
              .map((p) => p.trim().toLowerCase().replace(/^www\./, ''))
              .filter((p) => HOST_RE.test(p))
          )
        ).slice(0, 300)
      : [...d.verified_platforms],
    esp_tracking_domains: Array.isArray(o.esp_tracking_domains) && o.esp_tracking_domains.length > 0
      ? Array.from(
          new Set(
            (o.esp_tracking_domains as unknown[])
              .filter((p): p is string => typeof p === 'string')
              .map((p) => p.trim().toLowerCase().replace(/^www\./, ''))
              .filter((p) => HOST_RE.test(p))
          )
        ).slice(0, 300)
      : [...d.esp_tracking_domains],
    standard_email_external_domains: Array.isArray(o.standard_email_external_domains) && o.standard_email_external_domains.length > 0
      ? Array.from(
          new Set(
            (o.standard_email_external_domains as unknown[])
              .filter((p): p is string => typeof p === 'string')
              .map((p) => p.trim().toLowerCase().replace(/^www\./, ''))
              .filter((p) => HOST_RE.test(p))
          )
        ).slice(0, 300)
      : [...d.standard_email_external_domains],
    safe_sender_domains: Array.isArray(o.safe_sender_domains) && o.safe_sender_domains.length > 0
      ? Array.from(
          new Set(
            (o.safe_sender_domains as unknown[])
              .filter((p): p is string => typeof p === 'string')
              .map((p) => p.trim().toLowerCase().replace(/^www\./, ''))
              .filter((p) => HOST_RE.test(p))
          )
        ).slice(0, 100)
      : [...d.safe_sender_domains],
  };
}
