import type { EmailLocalSummary } from './emailGuard';

export interface EmailScanResult {
  verdict: 'phishing' | 'scam' | 'suspicious' | 'legit' | 'unavailable';
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
}

const invalid = (): EmailScanResult => ({ verdict: 'unavailable', reason: 'invalid_response' });
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

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
  low_confidence: 'AI could not reach a confident result. On-device warnings are unchanged.',
  error: 'The server could not complete AI analysis. On-device warnings are unchanged; you can retry.',
};

export function emailScanHttpFailure(status: number): EmailScanResult {
  return { verdict: 'unavailable', reason: status === 401 ? 'auth_required' : status === 403 ? 'not_available'
    : status === 429 ? 'rate_limited' : status >= 500 ? 'service_unavailable' : 'error' };
}

/** Validate API data before it is cached or allowed to affect the email panel. */
export function normalizeEmailScanResult(value: unknown): EmailScanResult {
  if (!record(value)) return invalid();
  if (value.verdict === 'unavailable') {
    return { verdict: 'unavailable', reason: typeof value.reason === 'string' ? value.reason.slice(0, 80) : undefined };
  }
  if (!['phishing', 'scam', 'suspicious', 'legit'].includes(value.verdict as string)) return invalid();
  const score = value.risk_score;
  if (typeof score !== 'number' || !Number.isInteger(score) || score < 0 || score > 100) return invalid();
  if ((value.verdict === 'legit' && score !== 0) || (value.verdict !== 'legit' && score === 0)) return invalid();
  for (const key of ['title', 'message', 'impersonated_brand', 'sender_domain', 'reason']) {
    if (value[key] !== undefined && (typeof value[key] !== 'string' || (value[key] as string).length > 2000)) return invalid();
  }
  if (value.sender_matches_brand !== undefined && typeof value.sender_matches_brand !== 'boolean') return invalid();
  if (value.red_flags !== undefined && (!Array.isArray(value.red_flags) || value.red_flags.length > 5 ||
      !value.red_flags.every(f => typeof f === 'string' && f.length <= 300))) return invalid();
  if (value.links !== undefined && (!Array.isArray(value.links) || value.links.length > 20 || !value.links.every(l =>
    record(l) && typeof l.index === 'number' && Number.isInteger(l.index) && l.index >= 0 && l.index < 20 &&
    typeof l.host === 'string' && l.host.length <= 253 && typeof l.reason === 'string' && l.reason.length <= 300))) return invalid();
  if (value.verdict === 'legit' && ((value.red_flags as unknown[] | undefined)?.length || (value.links as unknown[] | undefined)?.length)) return invalid();
  return value as unknown as EmailScanResult;
}

/** AI can add a warning; it cannot remove deterministic findings or authenticate a sender. */
export function emailInsightSummary(local: Pick<EmailLocalSummary, 'danger' | 'cautions' | 'findings'>, ai: EmailScanResult | null) {
  const n = local.findings.length;
  const aiBad = ai?.verdict === 'phishing' || ai?.verdict === 'scam';
  const level = aiBad || local.danger ? 'danger'
    : ai?.verdict === 'suspicious' || local.cautions > 0 ? 'caution'
    : ai?.verdict === 'unavailable' ? 'neutral' : 'ok';
  const summary = aiBad
    ? ai.verdict === 'phishing' ? "Likely phishing email — don't click its links" : "Likely scam email — don't reply or pay"
    : local.danger ? `XoraPass found ${n} warning${n === 1 ? '' : 's'} on this email`
    : ai?.verdict === 'suspicious' ? 'Suspicious email — check carefully'
    : n ? `${n} thing${n === 1 ? '' : 's'} to check on this email`
    : ai?.verdict === 'legit' ? 'AI found no scam indicators — sender not authenticated'
    : ai?.verdict === 'unavailable' ? 'AI check inconclusive — on-device checks still apply'
    : 'On-device checks found no warning signs';
  return { level, summary };
}
