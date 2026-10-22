import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { VaultSession } from '../utils/vaultSession';
import { credentialRequestUrl } from '../utils/credentialOrigin';
import { extractHostname, isDomainMatch } from '../utils/siteTrust';
import { isFillableCategory } from '../utils/fillPolicy';

// Execute the actual handler/function source, with deterministic browser and
// provider dependencies. Importing the entire worker would register unrelated
// alarms, UI integrations and network initialization in the unit-test process.
const source = readFileSync(new URL('./background.ts', import.meta.url), 'utf8');
function between(start: string, end: string) {
  const offset = source.indexOf(start);
  const finish = source.indexOf(end, offset + start.length);
  if (offset < 0 || finish < 0) throw new Error(`Handler source not found: ${start}`);
  return source.slice(offset, finish);
}
const functions = between('async function lockVaultNow()', '// "locked" fires') +
  between('async function credentialReleaseError(', 'interface EmailAliasSummary');
const lifecycleListeners = between('browser.alarms.onAlarm.addListener((alarm) => {', 'interface VaultItem') +
  between('browser.idle.onStateChanged.addListener((state) => {', '// (Re)arm');
const handlers = [
  ['UNLOCK_VAULT', 'LOCK_VAULT'], ['LOCK_VAULT', 'REFRESH_TOKEN'],
  ['GET_CREDENTIAL_SECRET', 'REMEMBER_USERNAME'],
  ['SHIELD_SIGN_OUT', 'SHIELD_EMAIL_SCAN'],
].map(([start, end]) => between(`  if (type === '${start}') {`, `  if (type === '${end}') {`)).join('\n');

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}

function fixture() {
  const vaultSession = new VaultSession();
  const item = { id: 'entry', category: 'login', url: 'https://victim.example.com/login',
    username: 'synthetic-user', value: 'SYNTHETIC-PASSWORD', accountId: 'synthetic-account', totpSecret: 'SYNTHETIC-TOTP-KEY' };
  let state: Record<string, any> = { unlocked: true, email: 'first@example.invalid', encKey: 'synthetic-key', vaultItems: [item] };
  const sender = { id: 'own-extension', frameId: 0, origin: 'https://victim.example.com',
    url: 'https://victim.example.com/login', tab: { id: 1, url: 'https://victim.example.com/login' } };
  const browser = {
    storage: { session: {
      get: vi.fn(async () => structuredClone(state)),
      set: vi.fn(async (data: Record<string, unknown>) => { Object.assign(state, structuredClone(data)); }),
      clear: vi.fn(async () => { state = {}; }),
    } },
    tabs: { get: vi.fn(async () => ({ ...sender.tab })) },
    alarms: { clear: vi.fn(async () => true), onAlarm: { addListener: vi.fn() } },
    idle: { onStateChanged: { addListener: vi.fn() } },
  };
  const dependencies = {
    browser, vaultSession, credentialRequestUrl, extractHostname, isDomainMatch, isFillableCategory,
    isSiteDisabled: vi.fn(async () => false), getDomainAllowlist: vi.fn(async () => []),
    evaluateDomainRisk: vi.fn(async () => ({ decision: 'allow' })),
    sensitivityForItems: () => 'standard', isFillWithheld: () => false,
    parseTotpSecret: () => ({ secret: 'SYNTHETIC-TOTP-KEY' }),
    generateTotp: vi.fn(async () => ({ code: '123456' })),
    scheduleAutoLock: vi.fn(async () => {}), scheduleAiHeartbeat: vi.fn(), scheduleTokenRefresh: vi.fn(),
    clearAiHeartbeat: vi.fn(async () => {}), clearTokenRefresh: vi.fn(async () => {}),
    clearRiskApprovals: vi.fn(), clearClipboard: vi.fn(async () => {}), dismissedByTab: new Map(),
    shieldSignOut: vi.fn(async () => {}), ensureShieldDeviceToken: vi.fn(), AUTO_LOCK_ALARM: 'auto-lock',
    handleShieldAlarm: () => false, getLockOnScreenLock: vi.fn(async () => true),
    apiJwt: vi.fn(async () => ({ ok: true, data: [{ id: 'ai-session', status: 'active', granted_scopes: ['autofill'], vault_entry_id: 'entry' }] })),
  };
  const compiled = transformSync(`${functions}\n${lifecycleListeners}\nfunction handle(msg, sender) { const type = msg.type; ${handlers} }`, { loader: 'ts', target: 'esnext' }).code;
  const factory = new Function(...Object.keys(dependencies), `${compiled}\nreturn { handle, lockVaultNow };`);
  const actual = factory(...Object.values(dependencies));
  const request = (type = 'GET_CREDENTIAL_SECRET') => actual.handle({ type, payload: { id: 'entry', sessionId: 'ai-session' } }, sender);
  const unlock = async (email = 'first@example.invalid') => actual.handle({ type: 'UNLOCK_VAULT', payload: {
    decryptedItems: [item], email, encKey: 'synthetic-key', token: '',
  } }, sender);
  const lock = () => actual.handle({ type: 'LOCK_VAULT' }, sender);
  return { ...dependencies, ...actual, request, unlock, lock, sender, item,
    state: () => state, update: (data: Record<string, unknown>) => Object.assign(state, structuredClone(data)) };
}

type Fixture = ReturnType<typeof fixture>;
type Boundary = 'initial session' | 'site settings' | 'allowlist' | 'risk' | 'TOTP' | 'final session' | 'tab';
function pause(f: Fixture, boundary: Boundary) {
  const entered = deferred<void>();
  const resume = deferred<void>();
  const hold = async <T,>(value: T) => { entered.resolve(); await resume.promise; return value; };
  switch (boundary) {
    case 'initial session': f.browser.storage.session.get.mockImplementationOnce(() => hold(structuredClone(f.state()))); break;
    case 'site settings': f.isSiteDisabled.mockImplementationOnce(() => hold(false)); break;
    case 'allowlist': f.getDomainAllowlist.mockImplementationOnce(() => hold([])); break;
    case 'risk': f.evaluateDomainRisk.mockImplementationOnce(() => hold({ decision: 'allow' })); break;
    case 'TOTP': f.generateTotp.mockImplementationOnce(() => hold({ code: '123456' })); break;
    case 'final session':
      f.browser.storage.session.get.mockImplementationOnce(async () => structuredClone(f.state()))
        .mockImplementationOnce(() => hold(structuredClone(f.state()))); break;
    case 'tab': f.browser.tabs.get.mockImplementationOnce(() => hold({ ...f.sender.tab })); break;
  }
  return { entered: entered.promise, resume: () => resume.resolve() };
}

describe('SHIELD-005 actual credential release handler', () => {
  it('releases username/password/account/TOTP when the same session remains authorized', async () => {
    const f = fixture();
    expect(await f.request()).toEqual({ username: f.item.username, value: f.item.value, accountId: f.item.accountId, totpCode: '123456' });
  });

  for (const boundary of ['initial session', 'site settings', 'allowlist', 'risk', 'TOTP', 'final session', 'tab'] as Boundary[]) {
    for (const event of ['manual lock', 'sign-out', 'account switch', 'same-account re-unlock']) {
      it(`denies ${event} during ${boundary}`, async () => {
        const f = fixture();
        const pending = pause(f, boundary);
        const response = f.request();
        await pending.entered;
        if (event === 'manual lock') await f.lock();
        else if (event === 'sign-out') await f.handle({ type: 'SHIELD_SIGN_OUT' }, f.sender);
        else if (event === 'account switch') await f.unlock('second@example.invalid');
        else { await f.lock(); await f.unlock(); }
        pending.resume();
        expect(await response).toEqual({ error: 'locked' });
        expect(f.scheduleAutoLock).toHaveBeenCalledTimes(event.includes('unlock') || event === 'account switch' ? 1 : 0);
      });
    }
  }

  it('denies pending and new releases while clipboard cleanup is still waiting', async () => {
    const f = fixture();
    const pending = pause(f, 'risk');
    const cleanup = deferred<void>();
    const cleanupEntered = deferred<void>();
    f.clearClipboard.mockImplementation(() => { cleanupEntered.resolve(); return cleanup.promise; });
    const response = f.request();
    await pending.entered;
    const lock = f.lock();
    pending.resume();
    expect(await response).toEqual({ error: 'locked' });
    expect(await f.request()).toEqual({ error: 'locked' });
    await cleanupEntered.promise;
    expect(f.state().unlocked).toBe(false); // Safe if the worker restarts here.
    cleanup.resolve(); await lock;
  });

  it('still clears storage if alarm cleanup fails', async () => {
    const f = fixture();
    f.browser.alarms.clear.mockRejectedValueOnce(new Error('alarm unavailable'));
    await f.lock();
    expect(f.state()).toEqual({});
  });

  it('releases normally after a fresh unlock following a lock', async () => {
    const f = fixture();
    await f.lock(); await f.unlock();
    expect((await f.request()).value).toBe(f.item.value);
  });

  it.each(['auto-lock', 'screen lock'])('cancels a pending risk check through the actual %s event listener', async (event) => {
    const f = fixture(); const pending = pause(f, 'risk');
    const response = f.request(); await pending.entered;
    if (event === 'auto-lock') f.browser.alarms.onAlarm.addListener.mock.calls[0][0]({ name: 'auto-lock' });
    else {
      await f.browser.idle.onStateChanged.addListener.mock.calls[0][0]('locked');
      // The listener waits for the opt-in setting before calling lockVaultNow.
      await Promise.resolve();
    }
    pending.resume(); expect(await response).toEqual({ error: 'locked' });
  });

  for (const field of ['username', 'value', 'url', 'category', 'accountId', 'totpSecret']) {
    it(`denies a credential whose ${field} changed while risk was pending`, async () => {
      const f = fixture();
      const pending = pause(f, 'risk');
      const response = f.request(); await pending.entered;
      f.update({ vaultItems: [{ ...f.item, [field]: 'changed' }] });
      pending.resume();
      expect(await response).toEqual({ error: 'credential_changed' });
    });
  }

  it('denies a removed credential', async () => {
    const f = fixture(); const pending = pause(f, 'risk');
    const response = f.request(); await pending.entered; f.update({ vaultItems: [] }); pending.resume();
    expect(await response).toEqual({ error: 'credential_changed' });
  });

  it.each(['email', 'encKey', 'unlocked'])('checks live session %s even without a lifecycle event', async (key) => {
    const f = fixture(); const pending = pause(f, 'risk');
    const response = f.request(); await pending.entered;
    f.update({ [key]: key === 'unlocked' ? false : 'changed' }); pending.resume();
    expect(await response).toEqual({ error: 'locked' });
  });

  it('denies top-page navigation during risk evaluation', async () => {
    const f = fixture(); const pending = pause(f, 'risk');
    const response = f.request(); await pending.entered;
    f.browser.tabs.get.mockResolvedValue({ id: 1, url: 'https://victim.example.com/different-page' });
    pending.resume(); expect(await response).toEqual({ error: 'navigation_changed' });
  });

  it('denies a tab that closed during risk evaluation', async () => {
    const f = fixture(); const pending = pause(f, 'risk');
    const response = f.request(); await pending.entered;
    f.browser.tabs.get.mockRejectedValue(new Error('tab missing'));
    pending.resume(); expect(await response).toEqual({ error: 'navigation_changed' });
  });

  it('locks before waiting for remote sign-out', async () => {
    const f = fixture(); const revoke = deferred<void>();
    f.shieldSignOut.mockImplementation(() => revoke.promise);
    const signOut = f.handle({ type: 'SHIELD_SIGN_OUT' }, f.sender);
    expect(await f.request()).toEqual({ error: 'locked' });
    revoke.resolve(); await signOut;
  });
});

describe('retired AI credential access', () => {
  it('has no approval, session or AI fill handlers', () => {
    expect(source).not.toContain('/ai/access-requests');
    expect(source).not.toContain('/ai/sessions');
    expect(source).not.toContain("type === 'AI_FILL_CONFIRM'");
    expect(source).toContain("type === 'SHIELD_EMAIL_SCAN'");
    expect(source).toContain("type === 'AI_PASTE_EVENT'");
  });
});
