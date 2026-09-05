// Domain Risk API Client and Threat-Intel Integration Service.
//
// Communicates with backend POST /api/domain-risk/check when necessary
// while strictly maintaining zero-knowledge guarantees:
// NO passwords, usernames, TOTP secrets, tokens, or vault keys are ever sent.
//
// Includes in-memory & session caching with TTL to minimize API latency and overhead.

import { API_BASE_URL } from './config';
import type { Decision, RiskLevel, DomainRiskAssessment } from './domainRisk';
import { extractHostname } from './siteTrust';

export interface FormThreatContext {
  isLoginForm?: boolean;
  hasPasswordField?: boolean;
  hasMfaField?: boolean;
  isIframe?: boolean;
  actionUrl?: string;
  numInputs?: number;
}

export interface AISessionThreatContext {
  isAISession?: boolean;
  agentId?: string;
  toolName?: string;
}

export interface RemoteDomainRiskCheckRequest {
  current_url: string;
  current_domain: string;
  saved_domain?: string;
  form_context?: {
    is_login_form?: boolean;
    has_password_field?: boolean;
    has_mfa_field?: boolean;
    is_iframe?: boolean;
    action_url?: string;
    num_inputs?: number;
  };
  ai_session_context?: {
    is_ai_session?: boolean;
    agent_id?: string;
    tool_name?: string;
  };
  credential_sensitivity?: 'standard' | 'high' | 'critical';
}

export interface RemoteDomainRiskResponse {
  decision: Decision;
  risk_score: number;
  risk_level: RiskLevel;
  reasons: string[];
  reason_codes: string[];
  safe_warning_message?: string;
  matched_target?: string;
  cached?: boolean;
  timestamp?: number;
  // Threat-intel provider signals returned by the backend enrichment layer.
  // Keys are provider name constants (e.g. "google_web_risk"); values are
  // ThreatSignal strings (e.g. "phishing_hit", "clean", "provider_unavailable").
  threat_intel_signals?: Record<string, string>;
  // True when a business admin's DomainRiskPolicy determined or overrode this
  // decision. A local user-level allowlist toggle is exactly the "weaker
  // setting" business policy is meant to override, so mergeLocalAndRemoteRisk
  // must not let isAllowlisted bypass a policy-enforced remote decision.
  policy_enforced?: boolean;
}

// In-memory cache for fast sync lookups (10 min TTL)
const MEMORY_CACHE = new Map<string, { data: RemoteDomainRiskResponse; expiresAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000;

// Cached separately from MEMORY_CACHE (which is keyed per-domain): this is a
// single account-wide flag, refreshed on its own short TTL so a plan change
// takes effect quickly without a status call on every single domain check.
let statusCache: { enabled: boolean; expiresAt: number } | null = null;
const STATUS_CACHE_TTL_MS = 5 * 60 * 1000;

function buildCacheKey(
  currentDomain: string,
  savedDomain: string,
  actionHost: string,
  isAI: boolean,
  sensitivity: string
): string {
  return [
    extractHostname(currentDomain),
    extractHostname(savedDomain),
    extractHostname(actionHost),
    isAI ? 'ai' : 'user',
    sensitivity,
  ].join('|');
}

/**
 * Drops every cached remote verdict (and the cached plan/user status flag).
 *
 * Must be called whenever something that FEEDS a verdict changes rather than
 * the domain itself: allowlisting or un-allowlisting a host, or toggling the
 * user's Domain Risk preference. Without this, un-allowlisting a domain left
 * the stale `allow` in place for up to CACHE_TTL_MS, so protection stayed off
 * for ten minutes after the user turned it back on.
 */
export function clearRemoteRiskCache(): void {
  MEMORY_CACHE.clear();
  statusCache = null;
}

/**
 * Checks cached remote risk evaluation if available and fresh.
 */
export function getCachedRemoteRisk(
  currentDomain: string,
  savedDomain: string = '',
  actionUrl: string = '',
  isAI: boolean = false,
  sensitivity: 'standard' | 'high' | 'critical' = 'standard'
): RemoteDomainRiskResponse | null {
  const key = buildCacheKey(currentDomain, savedDomain, actionUrl, isAI, sensitivity);
  const entry = MEMORY_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    MEMORY_CACHE.delete(key);
    return null;
  }
  return { ...entry.data, cached: true };
}

// Resolves the current session JWT, or '' if locked/unavailable/lookup fails.
// Shared by every function in this file that attaches auth to a backend call.
// Dynamically imports the polyfill so this module stays loadable outside an
// extension context (e.g. unit tests under Node) — the package throws at
// import time when no browser/chrome runtime is present.
async function getJwtOrEmpty(getJwtFn?: () => Promise<string>): Promise<string> {
  try {
    if (getJwtFn) return await getJwtFn();
    const { default: browser } = await import('webextension-polyfill');
    if (browser.storage?.session) {
      const res = await browser.storage.session.get(['jwt']);
      const token = (res as Record<string, unknown>).jwt;
      return typeof token === 'string' ? token : '';
    }
    return '';
  } catch {
    return '';
  }
}

/**
 * Calls POST /api/domain-risk/check with metadata only (NO SECRETS).
 * Attaches the user JWT when available so the backend can associate the
 * telemetry event with the authenticated session — critical for the admin
 * Domain Risk panel to receive events from the extension.
 * Falls back safely to null if offline or on network error.
 *
 * @param getJwtFn - Injectable JWT getter (defaults to browser.storage.session lookup).
 *                   Overridden in unit tests to avoid browser API dependency.
 */
export async function checkDomainRiskRemote(
  currentUrl: string,
  savedDomain: string = '',
  formContext?: FormThreatContext,
  aiContext?: AISessionThreatContext,
  sensitivity: 'standard' | 'high' | 'critical' = 'standard',
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<RemoteDomainRiskResponse | null> {
  const currHost = extractHostname(currentUrl);
  if (!currHost) return null;

  // Ensure current_url is always a full URL — providers like Google Web Risk
  // require scheme + host. If the caller passed a bare hostname, reconstruct it.
  const normalizedUrl =
    currentUrl.includes('://') ? currentUrl : `https://${currHost}`;

  const actionHost = formContext?.actionUrl ? extractHostname(formContext.actionUrl) : '';
  const isAI = !!aiContext?.isAISession;

  // 1. Check client cache first
  const cached = getCachedRemoteRisk(currHost, savedDomain, actionHost, isAI, sensitivity);
  if (cached) {
    return cached;
  }

  // 2. Prepare safe zero-knowledge request payload
  const payload: RemoteDomainRiskCheckRequest = {
    current_url: normalizedUrl,
    current_domain: currHost,
    saved_domain: extractHostname(savedDomain),
    credential_sensitivity: sensitivity,
  };

  if (formContext) {
    payload.form_context = {
      is_login_form: formContext.isLoginForm,
      has_password_field: formContext.hasPasswordField,
      has_mfa_field: formContext.hasMfaField,
      is_iframe: formContext.isIframe,
      action_url: formContext.actionUrl,
      num_inputs: formContext.numInputs,
    };
  }

  if (aiContext && aiContext.isAISession) {
    payload.ai_session_context = {
      is_ai_session: true,
      agent_id: aiContext.agentId || '',
      tool_name: aiContext.toolName || '',
    };
  }

  // 3. Attach JWT if available — the backend records an anonymized telemetry
  //    event on every call, but the admin panel receives these events in the
  //    Domain Risk feed. Without auth the call still works (the route is
  //    public), but attaching the token ensures proper session tracking and
  //    makes the event visible immediately in the admin panel refresh.
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (jwt) {
    headers['Authorization'] = `Bearer ${jwt}`;
  }

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/check`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      return null;
    }

    const data = (await res.json()) as RemoteDomainRiskResponse;
    if (data && typeof data.risk_score === 'number' && data.decision) {
      // Store in memory cache
      const key = buildCacheKey(currHost, savedDomain, actionHost, isAI, sensitivity);
      MEMORY_CACHE.set(key, {
        data,
        expiresAt: Date.now() + CACHE_TTL_MS,
      });
      return data;
    }
    return null;
  } catch {
    // Network offline / backend unreachable -> safely return null so extension uses local engine
    return null;
  }
}

/**
 * Combines local on-device domain risk assessment with backend threat intel if available.
 */
export function mergeLocalAndRemoteRisk(
  local: DomainRiskAssessment,
  remote: RemoteDomainRiskResponse | null
): DomainRiskAssessment {
  if (!remote) {
    return local;
  }

  // A local, user-level allowlist toggle can suppress ordinary heuristic/
  // threat-intel noise for a domain the user has personally vetted — but it
  // must NOT be able to override a business admin's DomainRiskPolicy. That's
  // precisely the "weaker user-level setting" business policy exists to
  // override; letting isAllowlisted bypass it here would silently defeat the
  // whole org-blocklist / stricter-credential-category feature.
  if (local.isAllowlisted && !remote.policy_enforced) {
    return local;
  }

  // Choose stricter decision & higher score
  const score = Math.max(local.riskScore, remote.risk_score);
  let decision: Decision = local.decision;

  const rank = (d: Decision): number => {
    switch (d) {
      case 'block':
        return 3;
      case 'require_approval':
        return 2;
      case 'warn':
        return 1;
      case 'allow':
      default:
        return 0;
    }
  };

  if (rank(remote.decision) > rank(local.decision)) {
    decision = remote.decision;
  }

  let riskLevel: RiskLevel = local.riskLevel;
  if (score >= 90) riskLevel = 'critical';
  else if (score >= 80) riskLevel = 'high';
  else if (score >= 60) riskLevel = 'medium';
  else if (score >= 30) riskLevel = 'low';
  else riskLevel = 'safe';

  // Merge unique reason strings. Defensively coerced to [] — a backend
  // response with reasons serialized as null (a real bug that shipped
  // once already: a Go nil slice marshals to JSON null, not []) would
  // otherwise crash this entire function on `...null`, taking down
  // whatever UI called it.
  const combinedReasons = Array.from(new Set([...(local.reasons || []), ...(remote.reasons || [])]));

  return {
    ...local,
    riskScore: score,
    riskLevel,
    decision,
    reasons: combinedReasons,
    matchedTarget: local.matchedTarget || remote.matched_target || null,
    safeWarningMessage: remote.safe_warning_message || local.safeWarningMessage,
  };
}

/**
 * Calls POST /api/domain-risk/report — records a user-initiated "Report
 * phishing" click. Public endpoint (works even signed out), but attaches the
 * JWT when available for attribution. Never throws; a network failure just
 * resolves false so the UI can show "Try again".
 */
export async function reportPhishing(
  hostname: string,
  decision?: string,
  riskLevel?: string,
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<boolean> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/report`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ hostname, decision, risk_level: riskLevel }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { success?: boolean };
    return !!data.success;
  } catch {
    return false;
  }
}

/**
 * Calls GET /api/domain-risk/status — asks once whether Domain Risk (the
 * whole feature: detection, warnings/blocking, reporting, allowlisting) is
 * enabled for the caller's plan. Callers should check this BEFORE running
 * the on-device heuristic engine (assessDomainRisk in siteTrust.ts) as well
 * as before calling checkDomainRiskRemote — gating only the remote call
 * would leave local detection running regardless, since it needs no network
 * access at all. Fails open (true) on any network/parse error: a transient
 * backend hiccup must not silently disable phishing protection.
 */
export async function checkDomainRiskEnabled(
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<boolean> {
  if (statusCache && Date.now() < statusCache.expiresAt) {
    return statusCache.enabled;
  }

  const headers: Record<string, string> = {};
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/status`, { headers });
    if (!res.ok) return statusCache?.enabled ?? true;
    const data = (await res.json()) as { enabled?: boolean };
    const enabled = data.enabled !== false;
    statusCache = { enabled, expiresAt: Date.now() + STATUS_CACHE_TTL_MS };
    return enabled;
  } catch {
    return statusCache?.enabled ?? true;
  }
}

export interface DomainRiskSettings {
  enabled: boolean;
  planAllows: boolean;
  userEnabled: boolean;
}

/**
 * Calls GET /api/domain-risk/status fresh — bypassing checkDomainRiskEnabled's
 * short-lived cache — and returns the full plan/user breakdown, not just the
 * combined value. Used to render the Settings toggle, which needs to show the
 * true current state immediately (and distinguish "off because your plan
 * doesn't include this" from "off because you turned it off") rather than a
 * value that might be up to 5 minutes stale.
 */
export async function getDomainRiskSettings(
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<DomainRiskSettings | null> {
  const headers: Record<string, string> = {};
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/status`, { headers });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      enabled?: boolean;
      plan_allows?: boolean;
      user_enabled?: boolean;
    };
    return {
      enabled: data.enabled !== false,
      planAllows: data.plan_allows !== false,
      userEnabled: data.user_enabled !== false,
    };
  } catch {
    return null;
  }
}

/**
 * Calls PATCH /api/domain-risk/my-settings to turn Domain Risk detection on
 * or off for the signed-in user personally — the same preference the web app
 * reads/writes, so toggling it here is reflected there on its next fetch,
 * and vice versa. Requires auth (inherently account-bound); resolves false
 * without a request if no JWT is available. Clears the short-lived
 * checkDomainRiskEnabled cache on success so the very next autofill-time
 * check reflects the change immediately instead of waiting out its TTL.
 */
export async function updateDomainRiskSettings(
  enabled: boolean,
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<boolean> {
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (!jwt) return false;

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/my-settings`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) return false;
    statusCache = null;
    return true;
  } catch {
    return false;
  }
}

export interface DomainRiskHistoryEvent {
  id: number;
  event_type: string; // "domain_risk_block" | "domain_risk_warn" | "domain_risk_require_approval"
  timestamp: string;
  secret_exposed: boolean;
  detail?: string;
  domain?: string;
  reason_codes?: string; // JSON-encoded string[]
}

/**
 * Calls GET /api/domain-risk/my-history — the same personal history the web
 * app's Domain Risk panel shows, so the extension popup can surface a small
 * "recently blocked/warned" summary without duplicating any backend logic.
 * Requires auth; resolves an empty array without a request if no JWT is
 * available, and on any network/parse failure (fails empty, not throwing,
 * since this is a nice-to-have summary, not something autofill depends on).
 */
export async function getDomainRiskHistory(
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<DomainRiskHistoryEvent[]> {
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (!jwt) return [];

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/my-history`, {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { events?: DomainRiskHistoryEvent[] };
    return Array.isArray(data.events) ? data.events : [];
  } catch {
    return [];
  }
}

export interface DomainRiskReportRecord {
  id: string;
  hostname: string;
  decision: string;
  risk_level: string;
  reported_at: string;
}

/** Calls GET /api/domain-risk/my-reports — same fail-empty contract as getDomainRiskHistory. */
export async function getMyPhishingReports(
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<DomainRiskReportRecord[]> {
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (!jwt) return [];
  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/my-reports`, {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { reports?: DomainRiskReportRecord[] };
    return Array.isArray(data.reports) ? data.reports : [];
  } catch {
    return [];
  }
}

export interface DomainRiskAllowlistRequestRecord {
  id: string;
  hostname: string;
  status: 'pending' | 'approved' | 'denied';
  requested_at: string;
}

/** Calls GET /api/domain-risk/my-allowlist-requests — same fail-empty contract as getDomainRiskHistory. */
export async function getMyDomainAllowlistRequests(
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<DomainRiskAllowlistRequestRecord[]> {
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (!jwt) return [];
  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/my-allowlist-requests`, {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { requests?: DomainRiskAllowlistRequestRecord[] };
    return Array.isArray(data.requests) ? data.requests : [];
  } catch {
    return [];
  }
}

export interface AllowlistRequestResult {
  success: boolean;
  /** Set on failure so the caller can show something more useful than a dead-end "Try again". */
  reason?: 'not_authenticated' | 'network';
}

/**
 * Calls POST /api/domain-risk/allowlist-request — submits a pending
 * admin-review request for the current domain. Requires auth: unlike
 * reportPhishing, a request with no JWT is rejected server-side (401), since
 * a request is meaningless without an account to eventually grant it to.
 */
export async function requestDomainAllowlist(
  hostname: string,
  fetchFn: typeof fetch = globalThis.fetch,
  getJwtFn?: () => Promise<string>
): Promise<AllowlistRequestResult> {
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (!jwt) return { success: false, reason: 'not_authenticated' };

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/allowlist-request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
      body: JSON.stringify({ hostname }),
    });
    if (res.status === 401) return { success: false, reason: 'not_authenticated' };
    if (!res.ok) return { success: false, reason: 'network' };
    const data = (await res.json()) as { success?: boolean };
    return data.success ? { success: true } : { success: false, reason: 'network' };
  } catch {
    return { success: false, reason: 'network' };
  }
}
