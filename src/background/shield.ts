// XoraPass Shield runtime (background service worker).
//
// Owns everything that makes Shield ALWAYS-ON rather than "on while the vault
// is unlocked":
//
//   • Entitlement — always-on Shield is a paid feature. It is active only for
//     a signed-in account whose plan includes Domain Risk (and whose own
//     setting is on), checked against GET /api/shield/status and cached with
//     a 24 h offline grace.
//   • Locked-mode credential — locking clears the session JWT, so on unlock
//     the extension obtains a narrowly-scoped device token
//     (POST /api/shield/device-token). It authenticates ONLY the Shield /
//     Domain Risk read paths (blocklist, hash lookups, risk checks, status) —
//     it cannot read or change the vault — and is revoked on sign-out.
//   • Remote config / kill switch — GET /api/shield/config, polled on an alarm.
//   • Blocklist — hash-prefix set synced from GET /api/shield/blocklist and
//     kept in IndexedDB; prefix hits are confirmed with /api/shield/hash-lookup
//     (only the 4-byte prefix leaves the device).

import browser from 'webextension-polyfill';
import { API_BASE_URL } from '../utils/config';
import { DEFAULT_SHIELD_CONFIG, coerceShieldConfig, type ShieldConfig } from '../utils/shieldConfig';
import { PrefixSet, prefixHex, loadStoredBlocklist, saveStoredBlocklist } from '../utils/shieldBlocklist';
import { hashUrlExpressions } from '../utils/urlHashing';
import type { BlocklistHit } from '../utils/shieldEngine';

const TOKEN_KEY = 'shieldDeviceToken';
const ENTITLEMENT_KEY = 'shieldEntitlement';
const CONFIG_KEY = 'shieldConfig';
const CONFIG_META_KEY = 'shieldConfigMeta';

export const SHIELD_CONFIG_ALARM = 'xorapass-shield-config';
export const SHIELD_BLOCKLIST_ALARM = 'xorapass-shield-blocklist';

const ENTITLEMENT_GRACE_MS = 24 * 60 * 60 * 1000;
const TOKEN_ROTATE_BEFORE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_LOOKUP_PREFIXES = 20;

interface StoredToken {
  token: string;
  expiresAt: number;
  email: string;
}

export type ShieldFeature =
  | 'always_on'
  | 'page_hooks'
  | 'email_guard'
  | 'insecure_forms'
  | 'tracker_blocking'
  | 'download_guard'
  | 'ai_scan'
  | 'image_scan'
  | 'file_scan';

export interface ShieldEntitlement {
  active: boolean;
  planAllows: boolean;
  userEnabled: boolean;
  email: string;
  checkedAt: number;
  /** Gradual rollout, decided per user by the server (GET /api/shield/status). */
  features?: Partial<Record<ShieldFeature, boolean>>;
}

let getSessionJwt: () => Promise<string> = async () => '';

async function localGet<T>(key: string): Promise<T | undefined> {
  try {
    const res = (await browser.storage.local.get([key])) as Record<string, unknown>;
    return res[key] as T | undefined;
  } catch {
    return undefined;
  }
}

async function localSet(values: Record<string, unknown>): Promise<void> {
  try {
    await browser.storage.local.set(values);
  } catch {
    /* storage full / unavailable — Shield keeps running from memory */
  }
}

// ── Config ──────────────────────────────────────────────────────────────────

let configMem: ShieldConfig | null = null;

export async function getShieldConfig(): Promise<ShieldConfig> {
  if (configMem) return configMem;
  const stored = await localGet<unknown>(CONFIG_KEY);
  configMem = stored ? coerceShieldConfig(stored) : DEFAULT_SHIELD_CONFIG;
  return configMem;
}

/** Fetches the remote config (ETag-aware). Never throws. */
export async function refreshShieldConfig(): Promise<ShieldConfig> {
  const meta = (await localGet<{ etag?: string; fetchedAt?: number }>(CONFIG_META_KEY)) || {};
  const before = await getShieldConfig();
  try {
    const headers: Record<string, string> = {};
    if (meta.etag && configMem) headers['If-None-Match'] = meta.etag;
    const res = await fetch(`${API_BASE_URL}/api/shield/config`, { headers, cache: 'no-store' });
    if (res.status === 304) {
      await localSet({ [CONFIG_META_KEY]: { ...meta, fetchedAt: Date.now() } });
      return before;
    }
    if (!res.ok) return before;
    const cfg = coerceShieldConfig(await res.json());
    configMem = cfg;
    await localSet({
      [CONFIG_KEY]: cfg,
      [CONFIG_META_KEY]: { etag: res.headers.get('ETag') || undefined, fetchedAt: Date.now() },
    });
    if (
      cfg.config_refresh_minutes !== before.config_refresh_minutes ||
      cfg.blocklist.refresh_minutes !== before.blocklist.refresh_minutes
    ) {
      await scheduleShieldAlarms(cfg);
    }
    if (!cfg.shield_enabled || !cfg.blocklist.enabled) {
      // Kill switch: drop the in-memory list immediately.
      prefixSet = null;
    }
    return cfg;
  } catch {
    return before;
  }
}

// ── Credential & entitlement ────────────────────────────────────────────────

async function getStoredToken(): Promise<StoredToken | null> {
  const t = await localGet<StoredToken>(TOKEN_KEY);
  if (!t || typeof t.token !== 'string' || typeof t.expiresAt !== 'number') return null;
  if (t.expiresAt <= Date.now()) return null;
  return t;
}

/**
 * Credential for Shield / Domain Risk calls: the session JWT when unlocked,
 * otherwise "Shield <device-token>", otherwise ''.
 */
export async function getShieldCredential(): Promise<string> {
  const jwt = await getSessionJwt();
  if (jwt) return jwt;
  const t = await getStoredToken();
  return t ? `Shield ${t.token}` : '';
}

function authHeader(cred: string): string {
  return /^(Bearer|Shield) /.test(cred) ? cred : `Bearer ${cred}`;
}

async function setEntitlement(e: ShieldEntitlement): Promise<void> {
  entitlementMem = e;
  await localSet({ [ENTITLEMENT_KEY]: e });
}

let entitlementMem: ShieldEntitlement | null = null;

async function getEntitlement(): Promise<ShieldEntitlement | null> {
  if (entitlementMem) return entitlementMem;
  const e = await localGet<ShieldEntitlement>(ENTITLEMENT_KEY);
  entitlementMem = e && typeof e.active === 'boolean' ? e : null;
  return entitlementMem;
}

const INACTIVE = (email = ''): ShieldEntitlement => ({
  active: false,
  planAllows: false,
  userEnabled: false,
  email,
  checkedAt: Date.now(),
});

/** Re-checks the entitlement with the server. Keeps the old value offline. */
export async function refreshShieldEntitlement(): Promise<ShieldEntitlement | null> {
  const cred = await getShieldCredential();
  if (!cred) {
    await setEntitlement(INACTIVE());
    return entitlementMem;
  }
  try {
    const res = await fetch(`${API_BASE_URL}/api/shield/status`, {
      headers: { Authorization: authHeader(cred) },
      cache: 'no-store',
    });
    if (res.status === 401) {
      if (cred.startsWith('Shield ')) await browser.storage.local.remove(TOKEN_KEY).catch(() => undefined);
      await setEntitlement(INACTIVE());
      return entitlementMem;
    }
    if (!res.ok) return getEntitlement();
    const data = (await res.json()) as {
      active?: boolean;
      plan_allows?: boolean;
      user_enabled?: boolean;
      features?: Record<string, unknown>;
    };
    const features: Partial<Record<ShieldFeature, boolean>> = {};
    for (const [k, v] of Object.entries(data.features || {})) if (v === true) features[k as ShieldFeature] = true;
    const tok = await getStoredToken();
    await setEntitlement({
      active: data.active === true,
      planAllows: data.plan_allows === true,
      userEnabled: data.user_enabled === true,
      email: tok?.email || (await getEntitlement())?.email || '',
      checkedAt: Date.now(),
      features,
    });
    return entitlementMem;
  } catch {
    return getEntitlement();
  }
}

/**
 * Called after every unlock / bridged sign-in: makes sure this browser has a
 * valid device token for the signed-in account so Shield keeps working after
 * the vault locks. Rotates tokens within a week of expiry.
 */
export async function ensureShieldDeviceToken(jwt: string, email: string): Promise<void> {
  if (!jwt) return;
  const existing = await getStoredToken();
  const sameAccount = existing && existing.email === email;
  if (sameAccount && existing!.expiresAt - Date.now() > TOKEN_ROTATE_BEFORE_MS) {
    void refreshShieldEntitlement();
    return;
  }
  try {
    const res = await fetch(`${API_BASE_URL}/api/shield/device-token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (res.status === 403) {
      // Plan doesn't include Shield: no locked-mode credential.
      await revokeStoredToken(existing);
      await setEntitlement({ ...INACTIVE(email), userEnabled: true });
      return;
    }
    if (!res.ok) return;
    const data = (await res.json()) as { token?: string; expires_at?: string };
    const expiresAt = data.expires_at ? Date.parse(data.expires_at) : NaN;
    if (typeof data.token !== 'string' || !Number.isFinite(expiresAt)) return;
    // Replacing another account's (or an old) token: revoke it server-side.
    if (existing && existing.token !== data.token) await revokeStoredToken(existing);
    await localSet({ [TOKEN_KEY]: { token: data.token, expiresAt, email } satisfies StoredToken });
    await refreshShieldEntitlement();
    void refreshBlocklist();
  } catch {
    /* offline — retried on next unlock */
  }
}

async function revokeStoredToken(t: StoredToken | null): Promise<void> {
  if (!t) return;
  try {
    await fetch(`${API_BASE_URL}/api/shield/device-token`, {
      method: 'DELETE',
      headers: { Authorization: `Shield ${t.token}` },
    });
  } catch {
    /* best effort; token also expires on its own */
  }
  await browser.storage.local.remove(TOKEN_KEY).catch(() => undefined);
}

/** Sign-out: revoke the device token and forget everything account-bound. */
export async function shieldSignOut(): Promise<void> {
  await revokeStoredToken(await getStoredToken());
  await setEntitlement(INACTIVE());
  prefixSet = null;
  blocklistVersion = '';
  fullHashCache.clear();
  await saveStoredBlocklist(null);
}

/**
 * Always-on Shield is active: kill switch on, entitlement fresh and true,
 * and the "always_on" rollout includes this user.
 */
export async function isShieldActive(): Promise<boolean> {
  return shieldFeature('always_on');
}

/** A rollout-controlled Shield feature is on for this user (implies always_on). */
export async function shieldFeature(feature: ShieldFeature): Promise<boolean> {
  const cfg = await getShieldConfig();
  if (!cfg.shield_enabled) return false;
  const e = await getEntitlement();
  if (!e || !e.active) return false;
  if (Date.now() - e.checkedAt > ENTITLEMENT_GRACE_MS) {
    void refreshShieldEntitlement();
    return false;
  }
  return e.features?.always_on === true && e.features?.[feature] === true;
}

export async function getShieldState(): Promise<{
  active: boolean;
  entitlement: ShieldEntitlement | null;
  hasDeviceToken: boolean;
  blocklistVersion: string;
  blocklistSize: number;
  configVersion: number;
  killSwitch: boolean;
}> {
  const cfg = await getShieldConfig();
  await ensureBlocklistLoaded();
  return {
    active: await isShieldActive(),
    entitlement: await getEntitlement(),
    hasDeviceToken: !!(await getStoredToken()),
    blocklistVersion,
    blocklistSize: prefixSet?.size ?? 0,
    configVersion: cfg.version,
    killSwitch: !cfg.shield_enabled,
  };
}

// ── Blocklist ───────────────────────────────────────────────────────────────

let prefixSet: PrefixSet | null = null;
let blocklistVersion = '';
let loading: Promise<void> | null = null;

async function ensureBlocklistLoaded(): Promise<void> {
  if (prefixSet) return;
  if (!loading) {
    loading = (async () => {
      const stored = await loadStoredBlocklist();
      if (stored && !prefixSet) {
        try {
          prefixSet = PrefixSet.fromBigEndianBytes(stored.bytes);
          blocklistVersion = stored.version;
        } catch {
          await saveStoredBlocklist(null);
        }
      }
    })().finally(() => {
      loading = null;
    });
  }
  await loading;
}

/** Downloads a newer blocklist if there is one. Never throws. */
export async function refreshBlocklist(): Promise<void> {
  const cfg = await getShieldConfig();
  if (!cfg.blocklist.enabled || !(await isShieldActive())) return;
  const cred = await getShieldCredential();
  if (!cred) return;
  await ensureBlocklistLoaded();
  try {
    const url = `${API_BASE_URL}/api/shield/blocklist${blocklistVersion ? `?have=${encodeURIComponent(blocklistVersion)}` : ''}`;
    const res = await fetch(url, { headers: { Authorization: authHeader(cred) }, cache: 'no-store' });
    if (res.status === 304) return;
    if (res.status === 401 || res.status === 403) {
      await refreshShieldEntitlement();
      return;
    }
    if (!res.ok) return;
    const version = res.headers.get('X-Shield-Blocklist-Version') || '';
    const bytes = await res.arrayBuffer();
    const set = PrefixSet.fromBigEndianBytes(bytes); // validates
    prefixSet = set;
    blocklistVersion = version;
    fullHashCache.clear();
    await saveStoredBlocklist({ version, bytes, savedAt: Date.now() });
  } catch {
    /* keep the list we have */
  }
}

interface FullHashCacheEntry {
  matches: Map<string, { threatType: string; source: string }>;
  expires: number;
}

const fullHashCache = new Map<string, FullHashCacheEntry>();

async function lookupFullHashes(prefixes: string[]): Promise<boolean> {
  const cred = await getShieldCredential();
  if (!cred) return false;
  try {
    const res = await fetch(`${API_BASE_URL}/api/shield/hash-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: authHeader(cred) },
      body: JSON.stringify({ prefixes }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as {
      matches?: { prefix: string; full_hash: string; threat_type: string; source: string }[];
      cache_seconds?: number;
    };
    const ttl = Math.min(Math.max(Number(data.cache_seconds) || 300, 30), 86_400) * 1000;
    const expires = Date.now() + ttl;
    for (const p of prefixes) fullHashCache.set(p, { matches: new Map(), expires });
    for (const m of data.matches || []) {
      const entry = fullHashCache.get(String(m.prefix).toLowerCase());
      if (entry && typeof m.full_hash === 'string') {
        entry.matches.set(m.full_hash.toLowerCase(), { threatType: String(m.threat_type), source: String(m.source) });
      }
    }
    if (fullHashCache.size > 5000) {
      const now = Date.now();
      for (const [k, v] of fullHashCache) if (v.expires < now) fullHashCache.delete(k);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * L1: is this URL on the blocklist? Hashes the URL's lookup expressions
 * locally; only prefixes that hit the local set are confirmed with the
 * server. Fails OPEN (null) when the confirmation can't be obtained.
 */
export async function checkBlocklist(url: string): Promise<BlocklistHit | null> {
  const cfg = await getShieldConfig();
  if (!cfg.shield_enabled || !cfg.blocklist.enabled) return null;
  await ensureBlocklistLoaded();
  const set = prefixSet;
  if (!set || set.size === 0) return null;

  const hashes = await hashUrlExpressions(url);
  const hits = hashes.filter((h) => set.has(h.prefix));
  if (hits.length === 0) return null;

  const now = Date.now();
  const needed = Array.from(
    new Set(hits.map((h) => prefixHex(h.prefix)).filter((p) => !((fullHashCache.get(p)?.expires ?? 0) > now)))
  ).slice(0, MAX_LOOKUP_PREFIXES);
  if (needed.length > 0) await lookupFullHashes(needed);

  for (const h of hits) {
    const entry = fullHashCache.get(prefixHex(h.prefix));
    const m = entry?.matches.get(h.fullHashHex);
    if (m) return { threatType: m.threatType, source: m.source };
  }
  return null;
}

// ── Alarms / lifecycle ──────────────────────────────────────────────────────

async function scheduleShieldAlarms(cfg: ShieldConfig): Promise<void> {
  try {
    await browser.alarms.create(SHIELD_CONFIG_ALARM, { delayInMinutes: 1, periodInMinutes: cfg.config_refresh_minutes });
    await browser.alarms.create(SHIELD_BLOCKLIST_ALARM, { delayInMinutes: 2, periodInMinutes: cfg.blocklist.refresh_minutes });
  } catch {
    /* alarms unavailable in tests */
  }
}

/** Returns true when the alarm belonged to Shield (and was handled). */
export function handleShieldAlarm(name: string): boolean {
  if (name === SHIELD_CONFIG_ALARM) {
    void refreshShieldConfig().then(() => refreshShieldEntitlement());
    return true;
  }
  if (name === SHIELD_BLOCKLIST_ALARM) {
    void refreshBlocklist();
    return true;
  }
  return false;
}

export function initShield(deps: { getJwt: () => Promise<string> }): void {
  getSessionJwt = deps.getJwt;
  void (async () => {
    const cfg = await getShieldConfig();
    const existing = await browser.alarms.get(SHIELD_CONFIG_ALARM).catch(() => undefined);
    if (!existing) await scheduleShieldAlarms(cfg);
    const meta = (await localGet<{ fetchedAt?: number }>(CONFIG_META_KEY)) || {};
    if (!meta.fetchedAt || Date.now() - meta.fetchedAt > cfg.config_refresh_minutes * 60_000) {
      await refreshShieldConfig();
      await refreshShieldEntitlement();
    }
  })();
}
