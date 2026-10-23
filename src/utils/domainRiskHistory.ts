// Only actions reported after rendering/refusal are user-facing history.
export const HISTORY_ASSESSMENT_LABELS: Record<string, string> = {
  shield_page_blocked: 'Blocked',
  shield_warning_shown: 'Warning shown',
  shield_autofill_blocked: 'Autofill blocked',
};

export function isReportedShieldAction(eventType: unknown): eventType is string {
  return typeof eventType === 'string' && Object.prototype.hasOwnProperty.call(HISTORY_ASSESSMENT_LABELS, eventType);
}

export function visibleShieldHistory<T extends { event_type: string }>(events: T[]): T[] {
  return Array.isArray(events) ? events.filter(event => event && isReportedShieldAction(event.event_type)) : [];
}

export function historyAssessmentSummary(eventType: string): string {
  switch (eventType) {
    case 'shield_page_blocked': return 'Your extension reported showing a full-screen Shield block on this page.';
    case 'shield_warning_shown': return 'Your extension reported displaying a warning on this page.';
    case 'shield_autofill_blocked': return 'Your extension reported refusing an autofill request. This does not mean the page itself was blocked.';
    default: return 'This assessment does not confirm that the extension took an action.';
  }
}

export const HISTORY_ASSESSMENT_NOTICE = 'Activity reported by your extension. “Blocked” means a full-screen Shield warning was displayed; “Autofill blocked” means a fill request was refused. Reports may take a moment to sync.';
