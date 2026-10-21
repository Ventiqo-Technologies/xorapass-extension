import type { EmailLocalSummary } from './emailGuard';
import { senderDomainMatchesBrand } from './webmailGuard';
import { registrableDomain } from './siteTrust';

export interface EmailScanResult {
  verdict: 'phishing' | 'scam' | 'suspicious' | 'legit' | 'inconclusive' | 'unavailable';
  risk_score?: number;
  title?: string;
  message?: string;
  impersonated_brand?: string;
  sender_domain?: string;
  /** Domain/name association only; this is not sender authentication. */
  sender_matches_brand?: boolean;
  red_flags?: string[];
  links?: { index: number; host: string; reason: string }[];
  reason?: string;
  confirmed_threat?: boolean;
  /** Fixed diagnostic code only; never raw model text or email content. */
  validation_issue?: string;
}

const invalid = (): EmailScanResult => ({ verdict: 'unavailable', reason: 'invalid_response' });
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

const VALIDATION_ISSUES: Readonly<Record<string, string>> = {
  model_output_shape: 'AI returned a result in an invalid format.',
  model_low_confidence: 'AI did not reach a confident assessment.',
  sender_brand_contradiction: 'AI made a sender-domain claim that conflicts with the domain catalog.',
  sender_metadata_mismatch: 'The result describes a different sender domain than the opened email.',
  sender_mismatch_unproven: 'AI could not support its sender-impersonation claim.',
  link_mismatch_unproven: 'AI could not establish that the displayed link and its destination are deceptive.',
  evidence_quote_length: 'AI did not supply a usable supporting quote.',
  evidence_quote_not_found: 'AI cited text that was not in the supplied email excerpt.',
  link_without_evidence: 'AI flagged a link without a supporting finding.',
  weak_indicators_only: 'AI relied only on weak cues, which are not enough to justify a scam warning.',
  warning_without_evidence: 'AI proposed a warning without supporting findings.',
  unknown_indicator: 'AI returned a finding this scanner does not recognize.',
  evidence_source_mismatch: 'AI cited evidence from the wrong email field.',
  insufficient_content: 'Too little email content was available for a reliable assessment.',
};

/** Completed uncertainty is neutral, not a service failure or an assurance. */
export function emailInconclusiveText(ai: EmailScanResult): string {
  const explanations: Record<string, string> = {
    weak_indicators: 'Only nonspecific cues were found. Discounts, generic greetings or urgency alone do not establish fraud.',
    insufficient_evidence: 'The supplied evidence did not support a reliable fraud verdict.',
    low_confidence: 'AI did not reach a confident assessment of the supplied evidence.',
  };
  const reason = Object.prototype.hasOwnProperty.call(explanations, ai.reason || '') ? explanations[ai.reason!] : explanations.insufficient_evidence;
  return `${reason} This is not a safe-email verdict. On-device warnings still apply; sender authentication and unresolved link destinations were not verified.`;
}

const validationIssue = (value: unknown): string | undefined =>
  typeof value === 'string' && Object.prototype.hasOwnProperty.call(VALIDATION_ISSUES, value) ? value : undefined;

/** Render only locally authored explanations and allowlisted support codes. */
export function emailScanFailureText(ai: EmailScanResult): string {
  const issue = validationIssue(ai.validation_issue);
  if (issue && ai.verdict === 'unavailable') {
    return `${VALIDATION_ISSUES[issue]} The AI verdict was withheld, not classified as safe or malicious. On-device warnings are unchanged. Retry once; if this persists, share diagnostic code ${issue} with XoraPass support.`;
  }
  return Object.prototype.hasOwnProperty.call(EMAIL_SCAN_FAILURE_TEXT, ai.reason || '')
    ? EMAIL_SCAN_FAILURE_TEXT[ai.reason!] : EMAIL_SCAN_FAILURE_TEXT.invalid_response;
}

/** Fixed copy only: never render raw server errors or provider responses. */
export const EMAIL_SCAN_FAILURE_TEXT: Record<string, string> = {
  quota: 'You have used this month\'s AI checks. Add more from the XoraPass popup, or wait for the monthly reset. On-device checks still run.',
  daily_limit: 'Daily AI check limit reached. It resets at midnight UTC. On-device checks still run.',
  auto_limit: 'Automatic AI check limit reached. You can request a manual analysis. On-device checks still run.',
  budget: 'AI checks are paused for today. On-device checks still run.',
  metering_unavailable: 'The AI usage service is unavailable. Your email was not analyzed. On-device checks still run; retry later.',
  auth_required: 'Your AI session needs reconnecting. Open XoraPass and sign in again. On-device checks still run.',
  consent_required: 'Confirm the text-sharing notice before requesting AI analysis. On-device checks still run.',
  not_available: 'AI email analysis is not enabled for this account. On-device checks still run.',
  disabled: 'AI email analysis is disabled. On-device checks still run.',
  no_model: 'The server has no AI model configured. On-device checks still run; contact XoraPass support.',
  network_error: 'Could not reach the AI analysis service. On-device checks still run; check your connection and retry.',
  rate_limited: 'Too many AI requests. Wait a moment and retry. On-device checks still run.',
  service_unavailable: 'The AI analysis service is temporarily unavailable. On-device checks still run; retry later.',
  invalid_response: 'AI returned an invalid result. On-device warnings are unchanged; you can retry the analysis.',
  inconsistent_evidence: 'AI returned contradictory or unsupported findings. No reliable AI verdict is available. On-device warnings are unchanged; you can retry.',
  low_confidence: 'AI could not reach a confident result. On-device warnings are unchanged.',
  error: 'The server could not complete AI analysis. On-device warnings are unchanged; you can retry.',
};

export function emailScanHttpFailure(status: number): EmailScanResult {
  return { verdict: 'unavailable', reason: status === 401 ? 'auth_required' : status === 403 ? 'not_available'
    : status === 429 ? 'rate_limited' : status >= 500 ? 'service_unavailable' : 'error' };
}

/** Validate API data before it is cached or allowed to affect the email panel. */
export function normalizeEmailScanResult(value: unknown, senderEmail?: string): EmailScanResult {
  if (!record(value)) return invalid();
  if (value.verdict === 'unavailable') {
    const result: EmailScanResult = { verdict: 'unavailable', reason: typeof value.reason === 'string' ? value.reason.slice(0, 80) : undefined };
    const issue = validationIssue(value.validation_issue);
    if (issue) result.validation_issue = issue;
    return result;
  }
  if (!['phishing', 'scam', 'suspicious', 'legit', 'inconclusive'].includes(value.verdict as string)) return invalid();
  const score = value.risk_score;
  if (typeof score !== 'number' || !Number.isInteger(score) || score < 0 || score > 100) return invalid();
  const neutral = value.verdict === 'legit' || value.verdict === 'inconclusive';
  if ((neutral && score !== 0) || (!neutral && score === 0)) return invalid();
  for (const key of ['title', 'message', 'impersonated_brand', 'sender_domain', 'reason']) {
    if (value[key] !== undefined && (typeof value[key] !== 'string' || (value[key] as string).length > 2000)) return invalid();
  }
  if (value.sender_matches_brand !== undefined && typeof value.sender_matches_brand !== 'boolean') return invalid();
  if (value.confirmed_threat !== undefined && typeof value.confirmed_threat !== 'boolean') return invalid();
  if (senderEmail) {
    const host = senderEmail.split('@').at(-1)?.toLowerCase().trim() || '';
    const actualDomain = registrableDomain(host);
    const contradiction = (value.sender_domain && value.sender_domain !== actualDomain) ||
      (typeof value.impersonated_brand === 'string' && value.sender_matches_brand === false && senderDomainMatchesBrand(value.impersonated_brand, host));
    if (!value.confirmed_threat && contradiction) {
      return { verdict: 'unavailable', reason: 'inconsistent_evidence', validation_issue:
        value.sender_domain && value.sender_domain !== actualDomain ? 'sender_metadata_mismatch' : 'sender_brand_contradiction' };
    }
  }
  if (value.red_flags !== undefined && (!Array.isArray(value.red_flags) || value.red_flags.length > 5 ||
      !value.red_flags.every(f => typeof f === 'string' && f.length <= 300))) return invalid();
  if (value.links !== undefined && (!Array.isArray(value.links) || value.links.length > 20 || !value.links.every(l =>
    record(l) && typeof l.index === 'number' && Number.isInteger(l.index) && l.index >= 0 && l.index < 20 &&
    typeof l.host === 'string' && l.host.length <= 253 && typeof l.reason === 'string' && l.reason.length <= 300))) return invalid();
  if (neutral && ((value.red_flags as unknown[] | undefined)?.length || (value.links as unknown[] | undefined)?.length)) return invalid();
  if (value.confirmed_threat && (score < 75 || !['phishing', 'scam'].includes(value.verdict as string) || !(value.links as unknown[] | undefined)?.length)) return invalid();
  const weakLabels = new Set(['Pressure to act immediately', 'Generic greeting instead of your name', 'Contains a suspicious link', 'Offer that is too good to be true']);
  const flags = value.red_flags as string[] | undefined;
  if (!value.confirmed_threat && ['scam', 'phishing'].includes(value.verdict as string) &&
      flags?.length && flags.every(flag => weakLabels.has(flag))) {
    return { verdict: 'inconclusive', risk_score: 0, reason: 'weak_indicators' };
  }
  return value as unknown as EmailScanResult;
}

export function emailAIWarningCopy(verdict: EmailScanResult['verdict'], confirmedThreat = false) {
  if (confirmedThreat) return { title: 'Known dangerous link', message: 'Threat intelligence identified phishing or malware in an email link. Do not follow it. Sender authentication was not verified.' };
  return {
    title: verdict === 'phishing' ? 'AI assessment: possible phishing' : verdict === 'scam' ? 'AI assessment: possible scam' : 'AI assessment: review this email',
    message: 'AI reported warning signs in the supplied email excerpt. This assessment is not proof of fraud and does not authenticate the sender. Review the findings before following links or sharing information.',
  };
}

/** AI can add a warning; it cannot remove deterministic findings or authenticate a sender. */
export function emailInsightSummary(local: Pick<EmailLocalSummary, 'danger' | 'cautions' | 'findings'>, ai: EmailScanResult | null) {
  const n = local.findings.length;
  const aiBad = ai?.verdict === 'phishing' || ai?.verdict === 'scam';
  const level = aiBad || local.danger ? 'danger'
    : ai?.verdict === 'suspicious' || local.cautions > 0 ? 'caution'
    : ai?.verdict === 'unavailable' || ai?.verdict === 'inconclusive' ? 'neutral' : 'ok';
  const summary = ai?.confirmed_threat ? "Known dangerous link — don't open it" : aiBad
    ? ai.verdict === 'phishing' ? "AI flagged possible phishing — check carefully" : "AI flagged a possible scam — check carefully"
    : local.danger ? `XoraPass found ${n} warning${n === 1 ? '' : 's'} on this email`
    : ai?.verdict === 'suspicious' ? 'AI found concerns to review — not confirmed fraud'
    : n ? `${n} thing${n === 1 ? '' : 's'} to check on this email`
    : ai?.verdict === 'legit' ? 'AI found no scam indicators — sender not authenticated'
    : ai?.verdict === 'inconclusive' ? 'AI assessment uncertain — no fraud verdict'
    : ai?.verdict === 'unavailable' ? 'AI check inconclusive — on-device checks still apply'
    : 'On-device checks found no warning signs';
  return { level, summary };
}
