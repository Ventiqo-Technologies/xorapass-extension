import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { assessWithCatalog, disabledDomainRiskAssessment } from '../utils/domainRisk';
import { mergeLocalAndRemoteRisk } from '../utils/domainRiskService';
import { isTrustedHost, threatReason } from '../utils/shieldEngine';
import { applyCredentialFormRisk } from '../utils/credentialFormRisk';
import { applyPageRisk, scorePageSignals } from '../utils/pageRisk';
import { mergeExtraBrands } from '../utils/brandCatalog';
import { DEFAULT_SHIELD_CONFIG } from '../utils/shieldConfig';
import { isLocalOrPrivateHost } from '../utils/localHosts';
import { registrableDomain } from '../utils/siteTrust';

const source = readFileSync(new URL('./background.ts', import.meta.url), 'utf8');
const evaluate = source.slice(source.indexOf('async function evaluateDomainRisk('), source.indexOf('/**\n * Proactive navigation check'));
const blocklist = source.slice(source.indexOf('function blocklistAssessment('), source.indexOf('/**\n * Navigation guard'));
function fixture(trust: 'saved' | 'personal' | 'global' | 'platform' = 'saved') {
  const hostname = trust === 'platform' ? 'accounts.google.com' : 'portal.example.com';
  const cfg = { ...DEFAULT_SHIELD_CONFIG, trusted_domains: trust === 'global' ? [hostname] : [] };
  const dependencies = {
    getShieldConfig: vi.fn(async () => cfg), checkDomainRiskEnabled: vi.fn(async () => true), registrableDomain,
    isShieldActive: vi.fn(async () => true), isLocalOrPrivateHost, isTrustedHost,
    assessWithCatalog, disabledDomainRiskAssessment, mergeExtraBrands, applyPageRisk, scorePageSignals,
    applyCredentialFormRisk, mergeLocalAndRemoteRisk, threatReason,
    shieldAssessOptions: () => ({}), getShieldCredential: vi.fn(async () => 'synthetic-token'),
    checkBlocklist: vi.fn(async (): Promise<any> => null),
    checkDomainRiskRemote: vi.fn(async (): Promise<any> => ({ decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [] })),
  };
  const compiled = transformSync(blocklist + evaluate, { loader: 'ts', target: 'esnext' }).code;
  const run = new Function(...Object.keys(dependencies), compiled + '\nreturn evaluateDomainRisk;')(...Object.values(dependencies));
  const options = { hostname, currentUrl: `https://${hostname}/login`, knownHosts: trust === 'saved' ? [hostname] : [],
    allowlist: trust === 'personal' ? [hostname] : [], savedDomain: hostname, sensitivity: 'standard',
    remoteGate: () => false, formContext: { hasPasswordField: true, isLoginForm: true, actionUrl: `https://${hostname}/submit` } };
  return { ...dependencies, run, options, cfg };
}

describe('SHIELD-003 actual trusted-site risk pipeline', () => {
  for (const trust of ['saved', 'personal', 'global', 'platform'] as const) {
    it(`checks policies for a benign ${trust} site despite a false listing gate`, async () => {
      const f = fixture(trust);
      expect((await f.run(f.options)).decision).toBe('allow');
      expect(f.checkDomainRiskRemote).toHaveBeenCalledTimes(1);
      expect(f.checkDomainRiskRemote.mock.calls[0].at(-1)).toBe(true);
    });
    it(`enforces a remote block on a ${trust} site`, async () => {
      const f = fixture(trust);
      f.checkDomainRiskRemote.mockResolvedValue({ decision: 'block', risk_score: 0, risk_level: 'critical', reasons: ['Mandatory policy'], reason_codes: ['ORG_POLICY_BLOCKLISTED'], policy_enforced: true });
      const risk = await f.run(f.options);
      expect(risk.decision).toBe('block'); expect(risk.policyEnforced).toBe(true);
    });
    it(`enforces unsafe form checks offline on a ${trust} site`, async () => {
      const f = fixture(trust); f.cfg.remote = { ...f.cfg.remote, enabled: false };
      expect((await f.run({ ...f.options, formContext: { ...f.options.formContext, actionUrl: 'https://collector.invalid/' } })).decision).toBe('require_approval');
    });
    it(`keeps a confirmed blocklist hit above ${trust} trust`, async () => {
      const f = fixture(trust);
      f.checkBlocklist.mockResolvedValue({ threatType: 'MALWARE' });
      expect((await f.run(f.options)).decision).toBe('block');
    });
  }
  it('does not let an administrator domain allow erase an unsafe form destination', async () => {
    const f = fixture();
    f.checkDomainRiskRemote.mockResolvedValue({ decision: 'allow', policy_enforced: true, risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: ['ORG_POLICY_ALLOWLISTED'] });
    expect((await f.run({ ...f.options, formContext: { ...f.options.formContext, actionUrl: 'http://portal.example.com/submit' } })).decision).toBe('require_approval');
  });
  it('preserves the account feature-off gate', async () => {
    const f = fixture(); f.checkDomainRiskEnabled.mockResolvedValue(false);
    expect((await f.run(f.options)).decision).toBe('allow');
    expect(f.checkDomainRiskRemote).not.toHaveBeenCalled();
  });
});
