import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => ({ state: {} as Record<string, any>, loadBlocklist: vi.fn(async () => null) }));
vi.mock('webextension-polyfill', () => ({ default: {
  runtime: { id: 'fixture', getURL: (p: string) => 'chrome-extension://fixture/' + p },
  storage: { local: {
    get: async () => fixture.state,
    set: async (values: Record<string, unknown>) => { Object.assign(fixture.state, values); },
    remove: async (key: string) => { delete fixture.state[key]; },
  } },
} }));
vi.mock('../utils/shieldBlocklist', () => ({ PrefixSet: class {}, prefixHex: vi.fn(), loadStoredBlocklist: fixture.loadBlocklist, saveStoredBlocklist: vi.fn() }));

const enabled = (on: boolean) => ({ active: on, plan_allows: true, user_enabled: on, features: { always_on: on, page_hooks: on } });
const response = (on: boolean) => new Response(JSON.stringify(enabled(on)), { headers: { 'Content-Type': 'application/json' } });
beforeEach(() => {
  vi.resetModules(); fixture.loadBlocklist.mockClear();
  fixture.state = { shieldDeviceToken: { token: 'synthetic', expiresAt: Date.now() + 3600000 }, shieldEntitlement: { active: true, planAllows: true, userEnabled: true, checkedAt: Date.now(), features: { always_on: true, page_hooks: true } } };
});
afterEach(() => vi.unstubAllGlobals());

describe('Shield preference is shared by enforcement and status', () => {
  it('replaces a cached active state with the server off preference', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response(false)));
    const shield = await import('./shield'); await shield.refreshShieldEntitlement();
    expect(await shield.isShieldActive()).toBe(false);
    expect(await shield.getShieldState()).toMatchObject({ active: false, entitlement: { userEnabled: false } });
  });
  it('never enables automatic protection when the response contradicts user/plan permission', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ...enabled(false), active: true }))));
    const shield = await import('./shield'); await shield.refreshShieldEntitlement(); expect(await shield.isShieldActive()).toBe(false);
  });
  it('applies a saved off preference immediately and retains off through a failed refresh', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 503 })));
    const shield = await import('./shield'); await shield.applyShieldPreference(false);
    expect(await shield.isShieldActive()).toBe(false);
    await shield.refreshShieldEntitlement(true); expect(await shield.isShieldActive()).toBe(false);
  });
  it('discards a pre-toggle active response after a newer off response', async () => {
    const deferred: Array<(response: Response) => void> = [];
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(resolve => deferred.push(resolve))));
    const shield = await import('./shield'); const old = shield.refreshShieldEntitlement();
    await vi.waitFor(() => expect(deferred).toHaveLength(1));
    const fresh = shield.refreshShieldEntitlement(true); await vi.waitFor(() => expect(deferred).toHaveLength(2));
    deferred[1](response(false)); await fresh; deferred[0](response(true)); await old;
    expect(await shield.isShieldActive()).toBe(false); expect(fixture.state.shieldEntitlement.userEnabled).toBe(false);
  });
  it('does not restore a saved off preference from an older response', async () => {
    let resolve!: (value: Response) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(r => { resolve = r; })));
    const shield = await import('./shield'); const pending = shield.refreshShieldEntitlement();
    await vi.waitFor(() => expect(resolve).toBeTypeOf('function'));
    await shield.applyShieldPreference(false); resolve(response(true)); await pending;
    expect(await shield.isShieldActive()).toBe(false);
  });
  it('shares a refresh across concurrent popup/status callers', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response(true)));
    const shield = await import('./shield'); const a = shield.refreshShieldEntitlement(); const b = shield.refreshShieldEntitlement();
    expect(a).toBe(b); await Promise.all([a, b]); expect(fetch).toHaveBeenCalledOnce();
  });
  it('requires fresh entitlement before enabling again', async () => {
    const shield = await import('./shield'); await shield.applyShieldPreference(true); expect(await shield.isShieldActive()).toBe(false);
    vi.stubGlobal('fetch', vi.fn(async () => response(true))); await shield.refreshShieldEntitlement(true); expect(await shield.isShieldActive()).toBe(true);
  });
  it('skips even a cached blocklist lookup when the user preference is off', async () => {
    fixture.state.shieldEntitlement.userEnabled = false;
    const shield = await import('./shield'); expect(await shield.checkBlocklist('https://fixture.invalid')).toBeNull();
    expect(fixture.loadBlocklist).not.toHaveBeenCalled();
  });
});
