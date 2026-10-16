import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { classifyWalletRequest } from '../utils/scamBehavior';

const source = readFileSync(new URL('./pageHooks.ts', import.meta.url), 'utf8');
const section = source.slice(source.indexOf('  // ── Wallet observations'), source.indexOf('  // ── Lock-in'));
function fixture(request: (...args: any[]) => any, post = vi.fn(), hooksEnabled = true) {
  const w = { ethereum: { request } };
  const window = { addEventListener: vi.fn() };
  const compiled = transformSync(section, { loader: 'ts', target: 'esnext' }).code;
  new Function('w', 'window', 'classifyWalletRequest', 'post', 'hooksEnabled', compiled)(w, window, classifyWalletRequest, post, hooksEnabled);
  return { provider: w.ethereum, post, window };
}
describe('wallet observation preserves native wallet authority', () => {
  it('does not report wallet activity when Shield is off', async () => {
    const request = vi.fn(async () => 'native'); const post = vi.fn(); const f = fixture(request, post, false);
    expect(await f.provider.request({ method: 'eth_sign' })).toBe('native'); expect(post).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledOnce();
  });
  it('warns while invoking the native provider exactly once, without waiting for page approval', async () => {
    const args = { method: 'eth_sign', params: ['account', 'payload'] };
    const request = vi.fn(async () => 'native-wallet-result'); const f = fixture(request);
    expect(await f.provider.request(args)).toBe('native-wallet-result');
    expect(request).toHaveBeenCalledExactlyOnceWith(args); expect(f.post).toHaveBeenCalledWith('wallet_check', expect.any(Object));
    expect(f.window.addEventListener.mock.calls.some(([name]) => name === 'message')).toBe(false);
    expect(section).not.toContain('setTimeout'); expect(section).not.toContain('__xoraShieldReply');
  });
  it('does not change a normal request or invent an approval', async () => {
    const request = vi.fn(async () => ['account']); const f = fixture(request);
    expect(await f.provider.request({ method: 'eth_accounts' })).toEqual(['account']); expect(f.post).not.toHaveBeenCalled();
  });
  it('preserves native wallet rejection', async () => {
    const rejection = Object.assign(new Error('native rejection'), { code: 4001 });
    const f = fixture(async () => { throw rejection; });
    await expect(f.provider.request({ method: 'eth_sign' })).rejects.toBe(rejection);
  });
  it('still reaches native confirmation when advisory reporting fails', async () => {
    const f = fixture(async () => 'native', () => { throw new Error('report unavailable'); });
    expect(await f.provider.request({ method: 'eth_sign' })).toBe('native');
  });
});
