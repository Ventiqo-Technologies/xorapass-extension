import { describe, it, expect, vi } from 'vitest';

// vaultCache imports the webextension-polyfill default export, which throws when
// loaded outside a real extension. Only the storage helpers touch it; the rules
// under test here are pure.
vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } } },
}));

import {
  CACHE_VERSION,
  canVerifyOffline,
  isUsableCache,
  verifiesAgainstCache,
  type VaultCache,
} from './vaultCache';

const entry = (id: string) => ({
  id,
  nonce: 'bm9uY2U=',
  encrypted_payload: { ciphertext: 'Y3Q=', tag: 'dGFn', keyVersion: 1 },
});

const cache = (over: Partial<VaultCache> = {}): VaultCache => ({
  version: CACHE_VERSION,
  email: 'user@example.com',
  masterSalt: 'a1b2c3',
  entries: [entry('1'), entry('2')],
  cachedAt: 1_700_000_000_000,
  ...over,
});

describe('isUsableCache', () => {
  it('accepts a well-formed cache for its own account', () => {
    expect(isUsableCache(cache(), 'user@example.com')).toBe(true);
  });

  it('ignores case and surrounding space in the email', () => {
    expect(isUsableCache(cache(), '  USER@example.com ')).toBe(true);
  });

  it('refuses a cache belonging to another account', () => {
    // Signing in as someone else must never surface the previous user's vault.
    expect(isUsableCache(cache(), 'someone@else.com')).toBe(false);
  });

  it('refuses a cache written by a different version', () => {
    expect(isUsableCache(cache({ version: CACHE_VERSION + 1 }), 'user@example.com')).toBe(false);
  });

  it('refuses a cache with no salt, since nothing could be derived from it', () => {
    expect(isUsableCache(cache({ masterSalt: '' }), 'user@example.com')).toBe(false);
  });

  it('accepts an empty vault', () => {
    expect(isUsableCache(cache({ entries: [] }), 'user@example.com')).toBe(true);
  });

  it('refuses malformed entries', () => {
    const bad = cache({ entries: [{ id: '1' } as any] });
    expect(isUsableCache(bad, 'user@example.com')).toBe(false);
  });

  it('refuses entries carrying plaintext instead of ciphertext', () => {
    // A guard against the cache ever being fed decrypted items by mistake.
    const leaked = cache({ entries: [{ id: '1', username: 'a', value: 'hunter2' } as any] });
    expect(isUsableCache(leaked, 'user@example.com')).toBe(false);
  });

  it('refuses non-objects', () => {
    for (const bad of [null, undefined, 'cache', 42, []]) {
      expect(isUsableCache(bad, 'user@example.com')).toBe(false);
    }
  });
});

describe('canVerifyOffline', () => {
  it('is true when there is something to decrypt', () => {
    expect(canVerifyOffline(cache())).toBe(true);
  });

  it('is false for an empty vault', () => {
    // With nothing to decrypt there is no way to tell a right master password
    // from a wrong one, so those accounts have to go online.
    expect(canVerifyOffline(cache({ entries: [] }))).toBe(false);
  });
});

describe('verifiesAgainstCache', () => {
  it('passes when an entry opens', () => {
    expect(verifiesAgainstCache(cache(), () => true)).toBe(true);
  });

  it('fails when the key does not open the entry', () => {
    expect(verifiesAgainstCache(cache(), () => false)).toBe(false);
  });

  it('fails an empty vault without consulting the decryptor', () => {
    let called = false;
    const result = verifiesAgainstCache(cache({ entries: [] }), () => {
      called = true;
      return true;
    });
    expect(result).toBe(false);
    expect(called).toBe(false);
  });
});
