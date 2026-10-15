import type { Decision, RiskLevel } from './domainRisk';
export function numericRiskLevel(score: number): RiskLevel {
  return score >= 90 ? 'critical' : score >= 80 ? 'high' : score >= 60 ? 'medium' : score >= 30 ? 'low' : 'safe';
}
export function heuristicDecision(score: number, warn: number, block: number): Decision {
  return score >= block ? 'block' : score >= warn ? 'warn' : 'allow';
}
