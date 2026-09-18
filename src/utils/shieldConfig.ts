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

export interface ShieldConfig {
  version: number;
  shield_enabled: boolean;
  nav_guard: { enabled: boolean; block_score: number; typing_guard_ms: number };
  blocklist: { enabled: boolean; refresh_minutes: number };
  remote: { enabled: boolean; min_local_score: number; on_credential_forms: boolean };
  heuristics: { disabled_rules: LocalRule[]; warn_score: number; block_score: number };
  config_refresh_minutes: number;
  trusted_domains: string[];
}

export const DEFAULT_SHIELD_CONFIG: ShieldConfig = Object.freeze({
  version: 1,
  shield_enabled: true,
  nav_guard: { enabled: true, block_score: 90, typing_guard_ms: 1500 },
  blocklist: { enabled: true, refresh_minutes: 30 },
  remote: { enabled: true, min_local_score: 25, on_credential_forms: true },
  heuristics: { disabled_rules: [], warn_score: 40, block_score: 75 },
  config_refresh_minutes: 15,
  trusted_domains: [],
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
    trusted_domains: trusted,
  };
}
