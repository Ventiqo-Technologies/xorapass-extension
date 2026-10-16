import { describe, expect, it } from 'vitest';
import { VaultSession } from './vaultSession';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(r => { resolve = r; });
  return { promise, resolve };
}

describe('vault session generations and serialized transitions', () => {
  it('supports a stored unlocked session after a worker restart', () => {
    const session = new VaultSession();
    expect(session.isCurrent(session.capture()!)).toBe(true);
  });

  it('blocks old and new requests synchronously when invalidated', () => {
    const session = new VaultSession();
    const request = session.capture()!;
    session.invalidate();
    expect(session.isCurrent(request)).toBe(false);
    expect(session.capture()).toBeNull();
  });

  it('never revives an old request on a same-account re-unlock', async () => {
    const session = new VaultSession();
    const oldRequest = session.capture()!;
    session.invalidate();
    const next = session.invalidate();
    expect(await session.commit(next, async () => {}, true)).toBe(true);
    expect(session.isCurrent(oldRequest)).toBe(false);
    expect(session.isCurrent(session.capture()!)).toBe(true);
  });

  it('finishes a pending unlock write before clearing it for a newer lock', async () => {
    const session = new VaultSession();
    const pending = deferred();
    const entered = deferred();
    let stored = 'locked';
    const unlock = session.commit(session.invalidate(), async () => {
      entered.resolve(); await pending.promise; stored = 'unlocked';
    }, true);
    await entered.promise;
    const lock = session.commit(session.invalidate(), async () => { stored = 'locked'; }, false);
    pending.resolve();
    expect(await unlock).toBe(false);
    expect(await lock).toBe(true);
    expect(stored).toBe('locked');
    expect(session.capture()).toBeNull();
  });

  it('keeps account replacements ordered when an older write is pending', async () => {
    const session = new VaultSession();
    const pending = deferred();
    const entered = deferred();
    let account = '';
    const first = session.commit(session.invalidate(), async () => {
      entered.resolve(); await pending.promise; account = 'old';
    }, true);
    await entered.promise;
    const second = session.commit(session.invalidate(), async () => { account = 'new'; }, true);
    pending.resolve();
    expect(await first).toBe(false);
    expect(await second).toBe(true);
    expect(account).toBe('new');
  });

  it('skips an obsolete queued write', async () => {
    const session = new VaultSession();
    const old = session.invalidate();
    session.invalidate();
    let written = false;
    expect(await session.commit(old, async () => { written = true; }, true)).toBe(false);
    expect(written).toBe(false);
  });

  it('stays blocked after a failed write and allows a later clean unlock', async () => {
    const session = new VaultSession();
    await expect(session.commit(session.invalidate(), async () => { throw new Error('storage unavailable'); }, true)).rejects.toThrow();
    expect(session.capture()).toBeNull();
    expect(await session.commit(session.invalidate(), async () => {}, true)).toBe(true);
    expect(session.capture()).not.toBeNull();
  });
});
