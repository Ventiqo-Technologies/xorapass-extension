import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';
import { describe, expect, it, vi } from 'vitest';
import { buildSiteSafetyReport } from '../utils/siteScanner';
import { assessWithCatalog } from '../utils/domainRisk';
import { extractHostname, findLookalikeTarget, isDomainMatch } from '../utils/siteTrust';
import { mergeExtraBrands } from '../utils/brandCatalog';
import { isFillableCategory } from '../utils/fillPolicy';
import { DEFAULT_SHIELD_CONFIG } from '../utils/shieldConfig';

const source = readFileSync(new URL('./background.ts', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const scanner = source.slice(source.indexOf("  if (type === 'SCAN_SITE')"), source.indexOf("  if (type === 'RISK_APPROVE_DOMAIN')"));
describe('opening Shield/scanning never replaces page protection with raw API data', () => {
  it.each([false, true])('scanner report is independent (provider hit=%s)', async hit => {
    const url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
    const remote = { decision:hit?'block':'warn',risk_score:hit?100:15,risk_level:hit?'critical':'safe',
      reasons:['Synthetic scanner finding'],reason_codes:[hit?'THREAT_INTEL_PHISHING_HIT':'BRAND_IN_URL_PATH'] };
    const publishTabRisk = vi.fn();
    const browser = {storage:{session:{get:vi.fn(async()=>({unlocked:true,vaultItems:[]}))}},tabs:{query:vi.fn(async()=>[{id:7,url}]),sendMessage:vi.fn(async()=>({pageSignals:{}}))}};
    const dependencies = {browser,buildSiteSafetyReport,extractHostname,findLookalikeTarget,isDomainMatch,isFillableCategory,assessWithCatalog,mergeExtraBrands,
      getDomainAllowlist:async()=>[],checkDomainRiskEnabled:async()=>true,getShieldCredential:async()=> 'synthetic-only',
      getShieldConfig:async()=>DEFAULT_SHIELD_CONFIG,shieldAssessOptions:()=>({}),sensitivityForItems:()=> 'standard',
      checkDomainRiskRemote:vi.fn(async()=>remote),publishTabRisk};
    const compiled = transformSync(scanner,{loader:'ts'}).code;
    const run = new Function(...Object.keys(dependencies), `return async function(type,msg){${compiled}};`)(...Object.values(dependencies));
    const result = await run('SCAN_SITE',{payload:{url,title:'Synthetic Microsoft login',pageSignals:{}}});
    expect(result.report.verdict).toBe(hit?'danger':'safe');
    expect(dependencies.checkDomainRiskRemote).toHaveBeenCalledOnce();
    expect(publishTabRisk).not.toHaveBeenCalled();
    expect(browser.tabs.sendMessage.mock.calls).toEqual([]);
  });
});
