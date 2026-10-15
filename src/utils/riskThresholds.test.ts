import { expect, it } from 'vitest';
import { heuristicDecision, numericRiskLevel } from './riskThresholds';
import { assessDomainRisk } from './domainRisk';
import { coerceShieldConfig } from './shieldConfig';
import { decideNavigation } from './shieldEngine';
it.each([[39,40,75,'allow'],[40,40,75,'warn'],[74,40,75,'warn'],[75,40,75,'block'],[89,90,100,'allow'],[90,90,100,'warn'],[99,90,100,'warn'],[100,90,100,'block']] as const)('uses configured boundary %s/%s/%s', (score,warn,block,want) => {
  expect(heuristicDecision(score,warn,block)).toBe(want);
});
it('keeps severity independent from configured actions', () => {
  expect(numericRiskLevel(75)).toBe('medium'); expect(numericRiskLevel(90)).toBe('critical');
  expect(heuristicDecision(75,40,75)).toBe('block'); expect(heuristicDecision(75,90,100)).toBe('allow');
});
it.each([[89,90,'warn'],[90,90,'block'],[91,90,'block']] as const)('honors the navigation boundary %s/%s', (score,threshold,action) => {
  const local = { ...assessDomainRisk('strpie.com', ['stripe.com']), riskScore: score, decision: 'block' as const };
  expect(decideNavigation({ url: 'https://strpie.com', config: coerceShieldConfig({ nav_guard: { enabled: true, block_score: threshold } }), active: true, userAllowlist: [], knownHosts: [], blocklistHit: null, local }).action).toBe(action);
});
