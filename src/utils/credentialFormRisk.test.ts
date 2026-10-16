import { describe, expect, it } from 'vitest';
import { assessDomainRisk } from './domainRisk';
import { applyCredentialFormRisk, credentialFormReason } from './credentialFormRisk';
import { checkDomainRiskRemote, clearRemoteRiskCache, mergeLocalAndRemoteRisk } from './domainRiskService';
import { decideNavigation } from './shieldEngine';
import { DEFAULT_SHIELD_CONFIG } from './shieldConfig';

describe('credential form checks independent of saved-site trust', () => {
  const page = 'https://portal.example.com/login';
  const form = { hasPasswordField: true, isLoginForm: true };
  it.each(['/submit', '../submit', 'https://portal.example.com:443/submit'])('preserves a same-origin HTTPS action %s', actionUrl => {
    expect(credentialFormReason(page, { ...form, actionUrl })).toBeNull();
  });
  it.each(['https://collector.invalid/submit', 'https://auth.example.com/submit', 'https://portal.example.com:8443/submit',
    'http://portal.example.com/submit', 'javascript:submit()', 'data:text/plain,password', 'https://['])
  ('requires approval for unsafe action %s on an allowlisted saved site', actionUrl => {
    const base = assessDomainRisk('portal.example.com', ['portal.example.com'], ['portal.example.com']);
    const risk = applyCredentialFormRisk(base, page, { ...form, actionUrl });
    expect(risk.decision).toBe('require_approval');
    expect(risk.riskScore).toBeGreaterThanOrEqual(70);
  });
  it('checks structural form signals even without a form action', () => {
    expect(credentialFormReason(page, undefined, { password_field_count: 1, form_action_insecure: true })).toBeTruthy();
    expect(credentialFormReason(page, undefined, { password_field_count: 1, form_action_cross_origin: true })).toBeTruthy();
  });
  it('checks passwords on an HTTP page even with an implicit form action', () => {
    expect(credentialFormReason('http://portal.example.com/login', form)).toBeTruthy();
  });
  it('does not flag a non-credential form', () => {
    expect(credentialFormReason(page, { actionUrl: 'https://collector.invalid/search' })).toBeNull();
  });
  it('preserves a stricter block', () => {
    const base = { ...assessDomainRisk('portal.example.com', []), decision: 'block' as const };
    expect(applyCredentialFormRisk(base, page, { ...form, actionUrl: 'https://collector.invalid' })).toBe(base);
  });
  it('does not let a personal allowlist erase a confirmed remote threat', () => {
    const base = assessDomainRisk('portal.example.com', [], ['portal.example.com']);
    const risk = mergeLocalAndRemoteRisk(base, { decision: 'block', risk_score: 95, risk_level: 'critical', reasons: ['Confirmed hit'], reason_codes: ['THREAT_INTEL_PHISHING_HIT'] });
    expect(risk.decision).toBe('block'); expect(risk.confirmedThreat).toBe(true);
  });
  it('enforces a low-score policy block during navigation on a trusted/allowlisted site', () => {
    const local = { ...assessDomainRisk('portal.example.com', ['portal.example.com']), policyEnforced: true, decision: 'block' as const };
    expect(decideNavigation({ url: page, config: DEFAULT_SHIELD_CONFIG, active: true, userAllowlist: ['portal.example.com'], knownHosts: ['portal.example.com'], blocklistHit: null, local }).action).toBe('block');
  });
  it('refreshes mandatory checks even when a client allow verdict is cached', async () => {
    clearRemoteRiskCache();
    let count = 0;
    const fetchFn = (async () => ({ ok: true, json: async () => (++count === 1
      ? { decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [] }
      : { decision: 'block', risk_score: 0, risk_level: 'critical', reasons: [], reason_codes: ['ORG_POLICY_BLOCKLISTED'], policy_enforced: true }) })) as unknown as typeof fetch;
    await checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => 'synthetic');
    const changed = await checkDomainRiskRemote(page, '', undefined, undefined, 'standard', fetchFn, async () => 'synthetic', undefined, true);
    expect(count).toBe(2); expect(changed?.decision).toBe('block');
    clearRemoteRiskCache();
  });
  it.each([
    ['/submit?private_token=synthetic#fragment', 'https://portal.example.com/submit'],
    ['javascript:submit()', 'invalid:'],
    ['https://[', 'invalid:'],
  ])('sends an accurate redacted destination for %s', async (actionUrl, expected) => {
    let transmitted = '';
    const fetchFn = (async (_url: unknown, init: RequestInit) => {
      transmitted = JSON.parse(init.body as string).form_context.action_url;
      return { ok: true, json: async () => ({ decision: 'allow', risk_score: 0, reasons: [] }) };
    }) as unknown as typeof fetch;
    await checkDomainRiskRemote(page, '', { ...form, actionUrl }, undefined, 'standard', fetchFn, async () => '', undefined, true);
    expect(transmitted).toBe(expected);
    clearRemoteRiskCache();
  });
});
