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
import type { PageSignals } from './pageSignals';

export interface FormThreatContext {
  isLoginForm?: boolean;
  hasPasswordField?: boolean;
  hasMfaField?: boolean;
  hasLeadCaptureForm?: boolean;
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
    has_lead_capture_form?: boolean;
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
  // Structural page features (see pageSignals.ts). Counts, booleans and
  // fixed-lexicon brand names only - never page text or user input.
  page_signals?: PageSignals;
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
  // True when the server wants a full-page block rather than a banner: a
  // critical verdict on a page actively asking for a password.
  show_interstitial?: boolean;
}

// In-memory cache for fast sync lookups (10 min TTL)
const MEMORY_CACHE = new Map<string, { data: RemoteDomainRiskResponse; expiresAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000;

// Cached separately from MEMORY_CACHE (which is keyed per-domain): this is a
// single account-wide flag, refreshed on its own short TTL so a plan change
// takes effect quickly without a status call on every single domain check.
let statusCache: { enabled: boolean; expiresAt: number; scope: string } | null = null;
const STATUS_CACHE_TTL_MS = 5 * 60 * 1000;

// Canonical full metadata prevents property order and delimiter collisions.
function canonicalMetadata(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonicalMetadata).join(',') + ']';
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return '{' + Object.keys(object).filter(k => object[k] !== undefined).sort()
      .map(k => JSON.stringify(k) + ':' + canonicalMetadata(object[k])).join(',') + '}';
  }
  return JSON.stringify(value) ?? 'null';
}

let cacheGeneration = 0;
let activeCredentialScope = 'anonymous';
async function credentialScope(credential: string): Promise<string> {
  if (!credential) return 'anonymous';
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credential));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

function buildCacheKey(payload: RemoteDomainRiskCheckRequest, scope: string): string {
  return payload.current_domain + '|' + scope + '|' + canonicalMetadata(payload);
}

function riskPayload(currentUrl: string, savedDomain: string, formContext?: FormThreatContext,
  aiContext?: AISessionThreatContext, sensitivity = 'standard', pageSignals?: PageSignals): RemoteDomainRiskCheckRequest {
  const normalizedUrl = sanitizeUrlForRiskCheck(currentUrl) || `https://${extractHostname(currentUrl)}/`;
  const payload: RemoteDomainRiskCheckRequest = {
    current_url: normalizedUrl, current_domain: extractHostname(currentUrl), saved_domain: extractHostname(savedDomain),
    credential_sensitivity: sensitivity as RemoteDomainRiskCheckRequest['credential_sensitivity'],
  };
  if (pageSignals) payload.page_signals = pageSignals;
  if (formContext) {
    let actionUrl: string | undefined;
    if (formContext.actionUrl) {
      try {
        const resolved = new URL(formContext.actionUrl, normalizedUrl);
        actionUrl = /^https?:$/.test(resolved.protocol) ? sanitizeUrlForRiskCheck(resolved.href) : 'invalid:';
      } catch { actionUrl = 'invalid:'; }
    }
    payload.form_context = {
      is_login_form: !!formContext.isLoginForm, has_password_field: !!formContext.hasPasswordField,
      has_mfa_field: !!formContext.hasMfaField, has_lead_capture_form: !!formContext.hasLeadCaptureForm,
      is_iframe: !!formContext.isIframe, action_url: actionUrl, num_inputs: formContext.numInputs ?? 0,
    };
  }
  if (aiContext?.isAISession) payload.ai_session_context = {
    is_ai_session: true, agent_id: aiContext.agentId || '', tool_name: aiContext.toolName || '',
  };
  return payload;
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
  cacheGeneration++;
  MEMORY_CACHE.clear();
  statusCache = null;
}

/**
 * Drops cached remote verdicts for a specific hostname.
 */
export function clearRemoteRiskCacheForHost(hostname: string): void {
  const norm = extractHostname(hostname);
  cacheGeneration++;
  for (const key of MEMORY_CACHE.keys()) {
    if (key.startsWith(norm + '|')) {
      MEMORY_CACHE.delete(key);
    }
  }
}

/**
 * Builds the Authorization header value for a risk call. The credential is a
 * session JWT, or — while the vault is locked — a ready-made
 * "Shield <device-token>" value (see background/shield.ts), which the backend
 * accepts on the Shield / Domain Risk read paths only.
 */
export function authHeaderValue(credential: string): string {
  return /^(Bearer|Shield) /.test(credential) ? credential : `Bearer ${credential}`;
}

/**
 * Reduces a URL to scheme://host/path — no userinfo, query or fragment — so
 * nothing token-like ever leaves the device in a risk check. Returns '' for
 * anything without an http(s) host.
 */
export function sanitizeUrlForRiskCheck(raw: string): string {
  const s = (raw || '').trim();
  if (!s) return '';
  let u: URL;
  try {
    u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
  } catch {
    return '';
  }
  if ((u.protocol !== 'http:' && u.protocol !== 'https:') || !u.hostname) return '';
  return `${u.protocol}//${u.host.toLowerCase()}${u.pathname || '/'}`;
}

/**
 * Checks cached remote risk evaluation if available and fresh.
 */
export function getCachedRemoteRisk(
  currentDomain: string,
  savedDomain: string = '',
  actionUrl: string = '',
  isAI: boolean = false,
  sensitivity: 'standard' | 'high' | 'critical' = 'standard',
  signals?: PageSignals,
  context?: { formContext?: FormThreatContext; aiContext?: AISessionThreatContext }
): RemoteDomainRiskResponse | null {
  const payload = riskPayload(currentDomain, savedDomain, context?.formContext ?? (actionUrl ? { actionUrl } : undefined),
    context?.aiContext ?? (isAI ? { isAISession: true } : undefined), sensitivity, signals);
  const key = buildCacheKey(payload, activeCredentialScope);
  const entry = MEMORY_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    MEMORY_CACHE.delete(key);
    return null;
  }
  return { ...structuredClone(entry.data), cached: true };
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
  getJwtFn?: () => Promise<string>,
  pageSignals?: PageSignals,
  forceRefresh = true
): Promise<RemoteDomainRiskResponse | null> {
  const currHost = extractHostname(currentUrl);
  if (!currHost) return null;

  const generation = cacheGeneration;
  const jwt = await getJwtOrEmpty(getJwtFn);
  const scope = await credentialScope(jwt);
  activeCredentialScope = scope;
  const payload = riskPayload(currentUrl, savedDomain, formContext, aiContext, sensitivity, pageSignals);
  const key = buildCacheKey(payload, scope);
  // Default calls always reach the backend for fresh policy/user approvals.
  // Explicit opt-in reuse is for metadata-only callers; credential checks
  // already pass forceRefresh=true. Never reuse a policy-enforced response.
  const cached = MEMORY_CACHE.get(key);
  if (!forceRefresh && generation === cacheGeneration && cached && Date.now() < cached.expiresAt && !cached.data.policy_enforced) {
    return { ...structuredClone(cached.data), cached: true };
  }

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (jwt) {
    headers['Authorization'] = authHeaderValue(jwt);
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
      if (generation === cacheGeneration) MEMORY_CACHE.set(key, {
        data: structuredClone(data), expiresAt: Date.now() + CACHE_TTL_MS,
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

  const hasThreatIntelHit =
    (remote.reason_codes || []).some((rc) => rc === 'THREAT_INTEL_PHISHING_HIT' || rc === 'THREAT_INTEL_MALWARE_HIT') ||
    Object.values(remote.threat_intel_signals || {}).some((sig) => sig === 'phishing_hit' || sig === 'malware_hit');
  const hasFormRisk = (remote.reason_codes || []).some((rc) =>
    ['CROSS_ORIGIN_FORM_ACTION', 'INSECURE_FORM_ACTION', 'INVALID_FORM_ACTION'].includes(rc));

  // A local, user-level allowlist toggle can suppress ordinary heuristic/
  // threat-intel noise for a domain the user has personally vetted — but it
  // must NOT be able to override a business admin's DomainRiskPolicy. That's
  // precisely the "weaker user-level setting" business policy exists to
  // override; letting isAllowlisted bypass it here would silently defeat the
  // whole org-blocklist / stricter-credential-category feature.
  if (local.isAllowlisted && !remote.policy_enforced && !hasThreatIntelHit && !hasFormRisk) {
    return local;
  }

  // An admin approved this site for this user (server-side, per account):
  // the server already refused to apply it over policies or threat-intel
  // hits, so honour it over local heuristics too.
  if (remote.decision === 'allow' && (remote.reason_codes || []).includes('USER_ALLOWLIST_APPROVED')) {
    return {
      ...local,
      riskScore: Math.min(local.riskScore, remote.risk_score),
      riskLevel: 'safe',
      decision: 'allow',
      reasons: Array.from(new Set([...(remote.reasons || [])])),
      isAllowlisted: true,
      showInterstitial: false,
      threatIntelSignals: remote.threat_intel_signals,
    };
  }

  // Check whether threat intelligence (Google Web Risk, VirusTotal, Cloudflare, etc.) flagged
  // this domain as suspected phishing or malware. A confirmed threat intel hit must NEVER
  // be softened or presented as merely a low/medium warning.

  // Choose stricter decision & higher score
  let score = Math.max(local.riskScore, remote.risk_score);
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

  const isPolicyAllowed = !!remote.policy_enforced && remote.decision === 'allow';
  const isUnblockedOverride = (remote.reason_codes || []).some(
    (rc) => rc === 'THREAT_INTEL_UNBLOCKED_WARNING'
  );

  if (isPolicyAllowed) {
    decision = 'allow';
    score = remote.risk_score || 0;
  } else if (hasThreatIntelHit && !isUnblockedOverride) {
    if (score < 85) score = 85;
    decision = 'block';
  } else if (hasThreatIntelHit && isUnblockedOverride) {
    decision = 'warn';
    if (score < 65) score = 65;
  } else if (rank(remote.decision) > rank(local.decision)) {
    decision = remote.decision;
  }

  let riskLevel: RiskLevel = local.riskLevel;
  if (isPolicyAllowed) {
    riskLevel = 'safe';
  } else {
    if (score >= 90) riskLevel = 'critical';
    else if (score >= 80) riskLevel = 'high';
    else if (score >= 60) riskLevel = 'medium';
    else if (score >= 30) riskLevel = 'low';
    else riskLevel = 'safe';

    if (hasThreatIntelHit && riskLevel !== 'critical' && !isUnblockedOverride) {
      riskLevel = 'high';
    }
  }

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
    showInterstitial:
      !isPolicyAllowed &&
      (!!remote.show_interstitial ||
        (hasThreatIntelHit && !isUnblockedOverride) ||
        (decision === 'block' && (!!remote.policy_enforced || score >= 85))),
    threatIntelSignals: remote.threat_intel_signals,
    policyEnforced: !!remote.policy_enforced,
    confirmedThreat: hasThreatIntelHit && !isUnblockedOverride && !isPolicyAllowed,
  };
}

export interface ReportPhishingResponse {
  success: boolean;
  alreadyBlocked?: boolean;
  duplicate?: boolean;
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
): Promise<ReportPhishingResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = await getJwtOrEmpty(getJwtFn);
  if (jwt) headers['Authorization'] = authHeaderValue(jwt);

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/report`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ hostname, decision, risk_level: riskLevel }),
    });
    if (!res.ok) return { success: false };
    clearRemoteRiskCacheForHost(hostname);
    const data = (await res.json()) as { success?: boolean; already_blocked?: boolean; duplicate?: boolean };
    return {
      success: !!data.success,
      alreadyBlocked: !!data.already_blocked,
      duplicate: !!data.duplicate,
    };
  } catch {
    return { success: false };
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
  const generation = cacheGeneration;
  const jwt = await getJwtOrEmpty(getJwtFn);
  const scope = await credentialScope(jwt);
  if (statusCache?.scope === scope && Date.now() < statusCache.expiresAt) return statusCache.enabled;
  const headers: Record<string, string> = {};
  if (jwt) headers['Authorization'] = authHeaderValue(jwt);

  try {
    const res = await fetchFn(`${API_BASE_URL}/api/domain-risk/status`, { headers });
    if (!res.ok) return statusCache?.scope === scope ? statusCache.enabled : true;
    const data = (await res.json()) as { enabled?: boolean };
    const enabled = data.enabled !== false;
    if (generation === cacheGeneration) statusCache = { enabled, scope, expiresAt: Date.now() + STATUS_CACHE_TTL_MS };
    return enabled;
  } catch {
    return statusCache?.scope === scope ? statusCache.enabled : true;
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
    clearRemoteRiskCache();
    return true;
  } catch {
    return false;
  }
}

export interface DomainRiskHistoryEvent {
  id: number;
  event_type: string; // "domain_risk_block" | "domain_risk_warn" | "domain_risk_require_approval"
  timestamp: string;
  // Old false values are defaults, not proof of a credential outcome.
  secret_exposed?: boolean | null;
  record_type?: 'assessment';
  credential_outcome?: 'not_observed';
  detail?: string;
  domain?: string;
  reason_codes?: string; // JSON-encoded string[]
}

/**
 * Calls GET /api/domain-risk/my-history — the same personal history the web
 * app's Domain Risk panel shows, so the extension popup can surface a small
 * recent-assessment summary. These are not client action receipts.
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
  /** Who an approval applies to: the requester, their workspace, or everyone. */
  scope?: 'user' | 'workspace' | 'global' | '';
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
