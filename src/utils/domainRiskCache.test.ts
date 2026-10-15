import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkDomainRiskRemote, clearRemoteRiskCache, clearRemoteRiskCacheForHost, checkDomainRiskEnabled, getCachedRemoteRisk, type FormThreatContext } from './domainRiskService';

const allow = { decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [] };
const block = { ...allow, decision: 'block', risk_score: 95, risk_level: 'critical' };
const page = 'https://portal.example.com/clean';
const form: FormThreatContext = { actionUrl: 'https://portal.example.com/submit', hasPasswordField: true };
afterEach(() => clearRemoteRiskCache());

describe('complete risk cache identity', () => {
  it.each([
    ['path', 'https://portal.example.com/phish', form],
    ['scheme', 'http://portal.example.com/clean', form],
    ['port', 'https://portal.example.com:8443/clean', form],
    ['action path', page, { ...form, actionUrl: 'https://portal.example.com/steal' }],
    ['action scheme', page, { ...form, actionUrl: 'http://portal.example.com/submit' }],
    ['action port', page, { ...form, actionUrl: 'https://portal.example.com:8443/submit' }],
    ['password', page, { ...form, hasPasswordField: false }],
    ['login', page, { ...form, isLoginForm: true }],
    ['MFA', page, { ...form, hasMfaField: true }],
    ['lead capture', page, { ...form, hasLeadCaptureForm: true }],
    ['frame', page, { ...form, isIframe: true }],
    ['input count', page, { ...form, numInputs: 10 }],
  ])('does not reuse an allow after changing %s', async (_name, nextPage, nextForm) => {
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => allow }).mockResolvedValue({ ok: true, json: async () => block });
    await checkDomainRiskRemote(page, '', form, undefined, 'standard', fetchFn, async () => '', undefined, false);
    const result = await checkDomainRiskRemote(nextPage, '', nextForm, undefined, 'standard', fetchFn, async () => '', undefined, false);
    expect(result?.decision).toBe('block'); expect(fetchFn).toHaveBeenCalledTimes(2);
  });
  it('reuses identical redacted metadata with explicit cache opt-in', async () => {
    const fetchFn = vi.fn().mockResolvedValue({ ok: true, json: async () => allow });
    await checkDomainRiskRemote(page+'?token=first#one', '', form, undefined, 'standard', fetchFn, async () => '', { has_favicon: true, password_field_count: 1 }, false);
    const result = await checkDomainRiskRemote(page+'?token=second#two', '', form, undefined, 'standard', fetchFn, async () => '', { password_field_count: 1, has_favicon: true }, false);
    expect(result?.cached).toBe(true); expect(fetchFn).toHaveBeenCalledTimes(1);
  });
  it.each(['agentId', 'toolName'] as const)('distinguishes AI %s', async key => {
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => allow }).mockResolvedValue({ ok: true, json: async () => block });
    const ai = { isAISession: true, agentId: 'agent', toolName: 'fill' };
    await checkDomainRiskRemote(page, '', form, ai, 'standard', fetchFn, async () => '', undefined, false);
    const result = await checkDomainRiskRemote(page, '', form, { ...ai, [key]: 'changed' }, 'standard', fetchFn, async () => '', undefined, false);
    expect(result?.decision).toBe('block'); expect(fetchFn).toHaveBeenCalledTimes(2);
  });
  it('separates authenticated sessions and anonymous callers', async () => {
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => allow }).mockResolvedValue({ ok: true, json: async () => block });
    for (const token of ['synthetic-account-a', 'synthetic-account-b', '']) {
      const result = await checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => token, undefined, false);
      expect(result?.decision).toBe(token === 'synthetic-account-a' ? 'allow' : 'block');
    }
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });
  it('checks fresh server policy by default after a cached allow', async () => {
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => allow }).mockResolvedValue({ ok: true, json: async () => ({ ...block, policy_enforced: true }) });
    await checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => '');
    expect((await checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => ''))?.decision).toBe('block');
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
  it.each(['global', 'host'])('does not refill invalidated cache from a late %s response', async kind => {
    let complete!: (value: unknown) => void;
    const fetchFn = vi.fn().mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    const pending = checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => '', undefined, false);
    await vi.waitFor(() => expect(fetchFn).toHaveBeenCalledTimes(1));
    if (kind === 'global') clearRemoteRiskCache(); else clearRemoteRiskCacheForHost('portal.example.com');
    complete({ ok: true, json: async () => allow }); await pending;
    expect(getCachedRemoteRisk(page)).toBeNull();
  });
  it('scopes the feature-status cache to the current credential', async () => {
    const fetchFn = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ enabled: false }) }).mockResolvedValue({ ok: true, json: async () => ({ enabled: true }) });
    expect(await checkDomainRiskEnabled(fetchFn, async () => 'synthetic-account-a')).toBe(false);
    expect(await checkDomainRiskEnabled(fetchFn, async () => 'synthetic-account-b')).toBe(true);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});
