// Persistent encrypted vault cache.
//
// Everything here is ciphertext exactly as the server stores it — the same
// blobs the API hands back, never decrypted items. That is what makes it safe
// to put on disk in `storage.local`: an attacker with the file gets no more
// than an attacker with the database.
//
// The cache exists so that locking stops meaning logging out. Lock drops the
// key from memory and leaves this behind; unlocking re-derives the key from the
// master password and reopens the cache without a round trip, which is also
// what makes the vault readable with no connection at all.

import browser from 'webextension-polyfill';

export const CACHE_KEY = 'vaultCache';

/** Bump when the cached shape changes; older caches are discarded, not migrated. */
export const CACHE_VERSION = 1;

/** A vault row as the API returns it. Opaque to us without the key. */
export interface RawVaultEntry {
  id: string;
  encrypted_payload: { ciphertext: string; tag: string; keyVersion: number };
  nonce: string;
}

export interface VaultCache {
  version: number;
  /** Whose vault this is — a cache for another account must never be opened. */
  email: string;
  /**
   * The account's Argon2id salt. Not a secret (the server hands it to anyone
   * who asks for the address), and caching it is what lets unlock skip the
   * /auth/discover call and therefore work offline.
   */
  masterSalt: string;
  entries: RawVaultEntry[];
  cachedAt: number;
}

function isRawEntry(v: unknown): v is RawVaultEntry {
  if (typeof v !== 'object' || v === null) return false;
  const e = v as Record<string, unknown>;
  const payload = e.encrypted_payload as Record<string, unknown> | undefined;
  return (
    typeof e.id === 'string' &&
    typeof e.nonce === 'string' &&
    typeof payload === 'object' &&
    payload !== null &&
    typeof payload.ciphertext === 'string' &&
    typeof payload.tag === 'string'
  );
}

/**
 * Whether a stored value is a cache we are willing to open for `email`.
 *
 * Pure so the rules are testable without a browser. The email check is the
 * important one: switching accounts must not surface the previous account's
 * entries, and a cache whose owner we cannot confirm is treated as absent.
 */
export function isUsableCache(value: unknown, email: string): value is VaultCache {
  if (typeof value !== 'object' || value === null) return false;
  const c = value as Record<string, unknown>;
  if (c.version !== CACHE_VERSION) return false;
  if (typeof c.email !== 'string' || typeof c.masterSalt !== 'string' || !c.masterSalt) {
    return false;
  }
  if (c.email.toLowerCase() !== email.trim().toLowerCase()) return false;
  if (!Array.isArray(c.entries)) return false;
  return c.entries.every(isRawEntry);
}

/**
 * Whether an offline unlock can be attempted at all.
 *
 * An empty vault has nothing to decrypt, so there is no way to tell a correct
 * master password from a wrong one without the server — those accounts must go
 * online to unlock rather than be let in unverified.
 */
export function canVerifyOffline(cache: VaultCache): boolean {
  return cache.entries.length > 0;
}

/**
 * Confirms a derived key really opens this cache.
 *
 * `tryDecrypt` is injected so this stays testable and so the caller decides
 * which decrypt implementation to use. XChaCha20-Poly1305 is authenticated, so
 * a wrong key fails the tag check rather than returning garbage — that makes a
 * successful decrypt a sound password check with no server involved.
 */
export function verifiesAgainstCache(
  cache: VaultCache,
  tryDecrypt: (entry: RawVaultEntry) => boolean
): boolean {
  if (!canVerifyOffline(cache)) return false;
  return tryDecrypt(cache.entries[0]);
}

export async function readVaultCache(email: string): Promise<VaultCache | null> {
  try {
    const res = await browser.storage.local.get([CACHE_KEY]);
    const value = (res as Record<string, unknown>)[CACHE_KEY];
    return isUsableCache(value, email) ? value : null;
  } catch {
    return null;
  }
}

/** Replaces the cache wholesale. Callers pass raw API rows, never decrypted items. */
export async function writeVaultCache(
  email: string,
  masterSalt: string,
  entries: RawVaultEntry[]
): Promise<void> {
  const cache: VaultCache = {
    version: CACHE_VERSION,
    email,
    masterSalt,
    entries,
    cachedAt: Date.now(),
  };
  await browser.storage.local.set({ [CACHE_KEY]: cache });
}

/**
 * Refreshes the entries of an existing cache, keeping its salt and owner.
 * A sync has no reason to know the salt, so it must not have to supply one —
 * and must not silently create a cache for a different account.
 */
export async function updateCachedEntries(
  email: string,
  entries: RawVaultEntry[]
): Promise<void> {
  const existing = await readVaultCache(email);
  if (!existing) return;
  await writeVaultCache(existing.email, existing.masterSalt, entries);
}

/** Logging out — as opposed to locking — takes the vault off the disk. */
export async function clearVaultCache(): Promise<void> {
  await browser.storage.local.remove(CACHE_KEY);
}
