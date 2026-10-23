import { describe, expect, it } from 'vitest';
import { HISTORY_ASSESSMENT_LABELS, HISTORY_ASSESSMENT_NOTICE, historyAssessmentSummary } from './domainRiskHistory';

describe('history reflects assessments, not browser action receipts', () => {
  it('labels server recommendations without claiming an action occurred', () => {
    expect(HISTORY_ASSESSMENT_LABELS.domain_risk_block).toBe('Block recommended');
    expect(HISTORY_ASSESSMENT_LABELS.domain_risk_require_approval).toBe('Approval recommended');
    expect(HISTORY_ASSESSMENT_LABELS.domain_risk_warn).toBe('Risk indicators');
    for (const eventType of Object.keys(HISTORY_ASSESSMENT_LABELS)) {
      expect(historyAssessmentSummary(eventType)).not.toMatch(/was blocked|were blocked|was refused|were released|was released|is safe/);
    }
    expect(historyAssessmentSummary('domain_risk_future')).toContain('unavailable');
  });
  it('qualifies weak indicators and credential outcome', () => {
    expect(historyAssessmentSummary('domain_risk_warn')).toContain('not proof');
    expect(HISTORY_ASSESSMENT_NOTICE).toContain('not confirmed warnings or blocks');
    expect(HISTORY_ASSESSMENT_NOTICE).toContain('Credential sharing is not tracked');
  });
});
