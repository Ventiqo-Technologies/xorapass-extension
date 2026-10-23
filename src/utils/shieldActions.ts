import { API_BASE_URL } from './config';
import { authHeaderValue } from './domainRiskService';
import { extractHostname } from './siteTrust';
import { isLocalOrPrivateHost } from './localHosts';

export type ShieldAction = 'page_blocked' | 'warning_shown' | 'autofill_blocked';
export type ShieldActionReason = 'phishing' | 'malware' | 'policy' | 'unsafe_form' | 'risk';
export function shieldActionReason(risk?: { confirmedThreat?: boolean; policyEnforced?: boolean; threatIntelSignals?: Record<string,string> } | null): ShieldActionReason {
  const signals = Object.values(risk?.threatIntelSignals || {});
  if (signals.includes('phishing_hit')) return 'phishing';
  if (signals.includes('malware_hit')) return 'malware';
  return risk?.policyEnforced ? 'policy' : 'risk';
}

// Capture one credential for all retries: a later login must never attribute an
// earlier user's browsing event to a different account. No full URLs leave here.
export async function reportShieldAction(url: string, action: ShieldAction, reason: ShieldActionReason,
  getCredential: () => Promise<string>, fetcher: typeof fetch = globalThis.fetch,
  pause: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms))): Promise<boolean> {
  const host = extractHostname(url);
  if (!host || isLocalOrPrivateHost(host)) return false;
  let credential: string;
  try { credential = await getCredential(); } catch { return false; }
  if (!credential) return false;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetcher(`${API_BASE_URL}/api/domain-risk/action`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: authHeaderValue(credential) },
        body: JSON.stringify({ hostname: host, action, reason }), signal: AbortSignal.timeout(5000),
      });
      if (response.ok) return true;
      // Missing backend support, revoked auth, disabled plans and invalid data
      // aren't transient. A failed report never changes protection itself.
      if (response.status < 500 && response.status !== 429) return false;
    } catch { /* bounded retry; no page data or credential is logged */ }
    if (attempt < 2) await pause(500 * (attempt + 1));
  }
  return false;
}
