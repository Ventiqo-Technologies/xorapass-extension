import type { DomainRiskAssessment } from './domainRisk';
import type { FormThreatContext } from './domainRiskService';
import type { PageSignals } from './pageSignals';

/** A saved/trusted page does not authorize sending a password elsewhere. */
export function credentialFormReason(currentUrl: string, form?: FormThreatContext, signals?: PageSignals): string | null {
  if (!(form?.hasPasswordField || form?.isLoginForm || (signals?.password_field_count ?? 0) > 0)) return null;
  try {
    const page = new URL(currentUrl);
    const action = new URL(form?.actionUrl || currentUrl, page);
    if (!/^https?:$/.test(action.protocol)) return 'This login form has an unsupported credential destination.';
    if (action.protocol === 'http:' || signals?.form_action_insecure) return 'This login form sends your password over an unencrypted connection.';
    if (action.origin !== page.origin || signals?.form_action_cross_origin) return 'This login form sends your password to a different origin.';
  } catch {
    return 'The destination of this login form could not be verified.';
  }
  return null;
}

export function applyCredentialFormRisk(risk: DomainRiskAssessment, currentUrl: string, form?: FormThreatContext, signals?: PageSignals): DomainRiskAssessment {
  const reason = credentialFormReason(currentUrl, form, signals);
  if (!reason || risk.decision === 'block') return risk;
  return {
    ...risk,
    riskScore: Math.max(risk.riskScore, 70),
    riskLevel: 'high',
    decision: 'require_approval',
    reasons: Array.from(new Set([reason, ...risk.reasons])),
    safeWarningMessage: reason,
  };
}
