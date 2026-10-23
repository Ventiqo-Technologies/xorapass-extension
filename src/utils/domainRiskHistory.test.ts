import { describe, expect, it } from 'vitest';
import { HISTORY_ASSESSMENT_LABELS, HISTORY_ASSESSMENT_NOTICE, historyAssessmentSummary, visibleShieldHistory } from './domainRiskHistory';

describe('history reflects assessments, not browser action receipts', () => {
  it('labels server recommendations without claiming an action occurred', () => {
    expect(HISTORY_ASSESSMENT_LABELS.shield_page_blocked).toBe('Blocked');
    expect(HISTORY_ASSESSMENT_LABELS.shield_warning_shown).toBe('Warning shown');
    expect(HISTORY_ASSESSMENT_LABELS.shield_autofill_blocked).toBe('Autofill blocked');
    expect(historyAssessmentSummary('shield_page_blocked')).toContain('full-screen');
    expect(historyAssessmentSummary('shield_autofill_blocked')).toContain('does not mean the page itself was blocked');
    expect(visibleShieldHistory([{event_type:'domain_risk_warn'},{event_type:'domain_risk_block'},{event_type:'shield_page_blocked'},{event_type:'constructor'}])).toEqual([{event_type:'shield_page_blocked'}]);
  });
  it('qualifies weak indicators and credential outcome', () => {
    expect(historyAssessmentSummary('domain_risk_warn')).toContain('does not confirm');
    expect(HISTORY_ASSESSMENT_NOTICE).toContain('full-screen Shield warning');
    expect(historyAssessmentSummary('shield_page_blocked')).not.toContain('No credential');
  });
});
