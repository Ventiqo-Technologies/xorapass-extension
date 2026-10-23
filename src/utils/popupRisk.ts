import type { DomainRiskAssessment } from './domainRisk';
import { isCurrentRiskContext, sameRiskDocument, validTabRiskWarning, type RiskTabs, type TabRiskContext, type TabRiskWarning } from './tabRiskContext';

export interface PopupRiskState {
  assessment: DomainRiskAssessment | null;
  warning: TabRiskWarning | null;
  available: boolean;
  enabled: boolean | null;
}
export const EMPTY_POPUP_RISK: PopupRiskState = { assessment: null, warning: null, available: false, enabled: null };

function validAssessment(value: unknown, host: string): value is DomainRiskAssessment {
  if (!value || typeof value !== 'object') return false;
  const risk = value as DomainRiskAssessment;
  return risk.pageHostname === host && ['allow', 'warn', 'require_approval', 'block'].includes(risk.decision) &&
    ['safe', 'low', 'medium', 'high', 'critical'].includes(risk.riskLevel) &&
    Number.isFinite(risk.riskScore) && risk.riskScore >= 0 && risk.riskScore <= 100 &&
    Array.isArray(risk.reasons) && risk.reasons.every(reason => typeof reason === 'string') &&
    !!risk.signals && typeof risk.signals === 'object';
}

// Read the page's final background-enforced verdict, not a new URL-only API
// assessment. The two responses can legitimately differ after trust/form checks.
export async function readPopupRiskState(tabs: RiskTabs, context: TabRiskContext): Promise<PopupRiskState> {
  try {
    const response = await tabs.sendMessage(context.tabId, { type: 'GET_TAB_RISK_STATE', pageContext: context }, { frameId: 0 }) as any;
    if (!sameRiskDocument(response?.pageContext, context) || typeof response?.enabled !== 'boolean' ||
      (response.assessment !== null && !validAssessment(response.assessment, new URL(context.url).hostname)) ||
      !await isCurrentRiskContext(tabs, context)) return { ...EMPTY_POPUP_RISK };
    return { available: true, enabled: response.enabled, assessment: response.enabled ? response.assessment : null,
      warning: response.enabled && validTabRiskWarning(response.warning, context) ? response.warning : null };
  } catch { return { ...EMPTY_POPUP_RISK }; }
}

function warningLevel(level: string | undefined, severity: string): string {
  // A real policy may warn/block with a zero numeric score. Preserve the
  // action, but never put a "safe" badge on an actionable warning.
  return level && ['low','medium','high','critical'].includes(level) ? level : severity === 'block' ? 'high' : 'low';
}

export function popupThreat(assessment: DomainRiskAssessment | null, warning: TabRiskWarning | null, host: string, disabled = false): TabRiskWarning | null {
  if (disabled || !host) return null;
  const risk = assessment?.pageHostname === host ? assessment : null;
  const surface = warning?.currentDomain === host ? warning : null;
  if (surface?.pageBlocked) return { ...surface, severity: 'block', riskLevel: warningLevel(surface.riskLevel, 'block') };
  // Independent AI/behaviour warnings remain meaningful on a safe domain.
  const independent = surface?.source === 'ai' || surface?.source === 'behavior';
  const actionable = risk && risk.decision !== 'allow';
  if (actionable && (risk.decision !== 'warn' || !independent)) {
    const severity = risk.decision;
    return { source: 'domain', severity, title: severity === 'block' ? 'Threat detected' : 'Security warning',
      message: risk.safeWarningMessage || risk.reasons[0] || 'Review this page before entering sensitive information.',
      currentDomain: host, expectedDomain: risk.matchedTarget, riskLevel: warningLevel(risk.riskLevel, severity),
      allowlistRequestStatus: surface?.allowlistRequestStatus };
  }
  if (independent && surface) return { ...surface, riskLevel: warningLevel(surface.riskLevel, surface.severity) };
  // No action follows from explanation strings, low scores or retained domain
  // warning metadata after the current verdict has become allow.
  return null;
}
