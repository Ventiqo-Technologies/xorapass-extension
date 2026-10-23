export const HISTORY_ASSESSMENT_LABELS: Record<string, string> = {
  domain_risk_block: 'Block recommended',
  domain_risk_require_approval: 'Approval recommended',
  domain_risk_warn: 'Risk indicators',
  domain_risk_allow: 'Check recorded',
};

// Never replay legacy banner copy: the server logs its recommendation before
// the extension applies local trust and form checks. It is not an action receipt.
export function historyAssessmentSummary(eventType: string): string {
  switch (eventType) {
    case 'domain_risk_block': return 'Security checks recommended blocking this site.';
    case 'domain_risk_require_approval': return 'Security checks recommended asking for approval before autofill.';
    case 'domain_risk_warn': return 'Security checks recorded potential risk indicators. These are not proof of a malicious site.';
    case 'domain_risk_allow': return 'Security checks did not recommend a warning for this check. This is not a guarantee of safety.';
    default: return 'A security assessment was recorded; its recommendation is unavailable.';
  }
}

export const HISTORY_ASSESSMENT_NOTICE = 'These are security assessments, not confirmed warnings or blocks. Your extension may handle a site differently using local trust and form checks. Credential sharing is not tracked here.';
