import { describe, expect, it, vi } from 'vitest';
import { TokenRevocations, PENDING_REVOCATIONS_KEY } from './tokenRevocations';
describe('device-token revocation retry', () => {
  it('retains failed revocation durably and retries it without making it active', async () => {
    const state: Record<string, unknown> = {};
    const storage = { get: async () => state, set: async (v: Record<string, unknown>) => { Object.assign(state, v); } };
    const revoke = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
    expect(await new TokenRevocations(storage, revoke, () => 1).retry({ token: 'synthetic', expiresAt: 100 })).toBe(false);
    expect(state[PENDING_REVOCATIONS_KEY]).toEqual([{ token: 'synthetic', expiresAt: 100 }]);
    expect(await new TokenRevocations(storage, revoke, () => 2).retry()).toBe(true);
    expect(state[PENDING_REVOCATIONS_KEY]).toEqual([]);
    expect(state).not.toHaveProperty('shieldDeviceToken');
  });
  it('retains network failures and drops expired credentials without dispatch', async () => {
    const state: Record<string, unknown> = { [PENDING_REVOCATIONS_KEY]: [{ token: 'expired', expiresAt: 0 }] };
    const revoke = vi.fn().mockRejectedValue(new Error('offline'));
    const storage = { get: async () => state, set: async (v: Record<string, unknown>) => { Object.assign(state, v); } };
    expect(await new TokenRevocations(storage, revoke, () => 1).retry({ token: 'pending', expiresAt: 100 })).toBe(false);
    expect(revoke).toHaveBeenCalledExactlyOnceWith('pending');
  });
});
