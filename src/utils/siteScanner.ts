// Site Scanner utility for XoraPass Shield.
//
// Gathers comprehensive on-device security signals from the active tab and
// combines them with local domain risk heuristics and remote threat intelligence
// to generate an actionable, user-friendly security report.
//
// Zero-knowledge contract: NEVER accesses form input values, passwords,
// session cookies, or vault secrets. Only structural metrics and hostnames
// are inspected.

import { extractHostname, isDomainMatch, findLookalikeTarget } from './siteTrust';
import { assessDomainRisk, disabledDomainRiskAssessment } from './domainRisk';
import type { PageSignals } from './pageSignals';
import type { RemoteDomainRiskResponse } from './domainRiskService';

export interface SiteSafetyReport {
  url: string;
  hostname: string;
  title?: string;
  favIconUrl?: string;
  timestamp: number;

  // Primary Shield metrics
  riskScore: number; // 0 - 100
  riskLevel: 'safe' | 'low' | 'suspicious' | 'high' | 'critical';
  verdict: 'safe' | 'caution' | 'danger';
  headline: string;
  summary: string;

  // Breakdown indicators
  encryption: {
    isHttps: boolean;
    label: string;
    detail: string;
  };
  domainAuthenticity: {
    status: 'match' | 'neutral' | 'lookalike' | 'untrusted';
    label: string;
    detail: string;
    matchedTarget?: string;
  };
  threatIntel: {
    clean: boolean;
    label: string;
    detail: string;
    signals: string[];
  };
  credentialGuard: {
    status: 'protected' | 'autofill_allowed' | 'autofill_blocked';
    label: string;
    detail: string;
  };
  trackersAndScripts: {
    scriptCount: number;
    externalOriginsCount: number;
    hasCrossDomainForm: boolean;
    label: string;
  };

  // Detailed reasons
  reasons: string[];
}

/**
 * Builds a structured SiteSafetyReport from raw tab details, vault context,
 * and domain risk assessments.
 */
export function buildSiteSafetyReport(params: {
  url: string;
  title?: string;
  favIconUrl?: string;
  savedDomains: string[];
  riskAssessment?: RemoteDomainRiskResponse | null;
  scriptCount?: number;
  externalOriginsCount?: number;
  hasCrossDomainForm?: boolean;
  /** The user's domain allowlist — must be honoured exactly as on the autofill path. */
  allowlist?: string[];
  /**
   * false when Domain Risk is off for this account (plan or user setting):
   * no lookalike/threat-intel verdict is produced, only transport security.
   */
  domainRiskEnabled?: boolean;
  /** Structural page features from the content script (pageSignals.ts). */
  pageSignals?: PageSignals;
}): SiteSafetyReport {
  const {
    url,
    title,
    favIconUrl,
    savedDomains,
    scriptCount = 0,
    allowlist = [],
    domainRiskEnabled = true,
    pageSignals,
  } = params;
  const externalOriginsCount = params.externalOriginsCount ?? pageSignals?.external_script_origins ?? 0;
  const hasCrossDomainForm = params.hasCrossDomainForm ?? !!pageSignals?.form_action_cross_origin;

  const hostname = extractHostname(url);
  const isHttps = url.toLowerCase().startsWith('https://');

  // 1. Vault domain matching & lookalike detection
  const hasSavedCredential = savedDomains.some((d) => isDomainMatch(hostname, d));
  const localRisk = domainRiskEnabled
    ? assessDomainRisk(hostname, savedDomains, allowlist, url)
    : disabledDomainRiskAssessment(hostname);
  const lookalike =
    domainRiskEnabled && !hasSavedCredential ? findLookalikeTarget(hostname, savedDomains, allowlist) : null;
  // Same rule as mergeLocalAndRemoteRisk: a user allowlist suppresses the
  // remote verdict unless a business policy enforced it.
  const riskAssessment =
    !domainRiskEnabled || (localRisk.isAllowlisted && !params.riskAssessment?.policy_enforced)
      ? null
      : params.riskAssessment;

  // 2. Risk scoring (use max of local heuristic assessment, remote assessment, and structural flags)
  let score = Math.max(localRisk.riskScore, riskAssessment?.risk_score ?? 0);
  if (!isHttps && score < 30) score = Math.max(score, 30);
  if (lookalike && score < 70) score = Math.max(score, 70);

  // Normalize risk level
  let riskLevel: 'safe' | 'low' | 'suspicious' | 'high' | 'critical' = 'safe';
  if (score >= 85) riskLevel = 'critical';
  else if (score >= 70) riskLevel = 'high';
  else if (score >= 50) riskLevel = 'suspicious';
  else if (score >= 25) riskLevel = 'low';

  // 3. Verdict & Headlines
  let verdict: 'safe' | 'caution' | 'danger' = 'safe';
  let headline = 'Site Appears Safe';
  let summary = 'No threat indicators, domain spoofing, or credential mismatches detected.';

  if (riskLevel === 'critical' || riskLevel === 'high') {
    verdict = 'danger';
    headline = 'High Risk Detected';
    summary =
      riskAssessment?.safe_warning_message ||
      (lookalike
        ? `This website resembles ${lookalike.target} for which you have saved credentials.`
        : 'Potential phishing, brand impersonation, or malicious threat detected.');
  } else if (riskLevel === 'suspicious') {
    verdict = 'caution';
    headline = 'Exercise Caution';
    summary =
      riskAssessment?.safe_warning_message ||
      'This website exhibits unusual characteristics or unverified security indicators.';
  } else if (!isHttps) {
    verdict = 'caution';
    headline = 'Unencrypted Connection';
    summary = 'This website does not use secure HTTPS. Data sent to this site can be intercepted.';
  }
  if (!domainRiskEnabled && verdict === 'safe') {
    headline = 'Connection Checked';
    summary =
      'Phishing & Lookalike Shield is off for this account, so only connection security was checked.';
  }

  // 4. Detailed indicators
  const encryption = {
    isHttps,
    label: isHttps ? 'Secure Connection (HTTPS)' : 'Insecure Connection (HTTP)',
    detail: isHttps
      ? 'Traffic is encrypted using standard TLS.'
      : 'Traffic is unencrypted. Do not enter passwords or sensitive information.',
  };

  let domainAuthStatus: 'match' | 'neutral' | 'lookalike' | 'untrusted' = 'neutral';
  let domainAuthLabel = 'Known Web Domain';
  let domainAuthDetail = 'Domain has no detected typosquatting or brand spoofing flags.';

  const isLookalike = !!lookalike || !!localRisk.signals.brandAbuse || !!localRisk.signals.typosquatTarget || !!localRisk.signals.isHomograph;
  const targetBrand = lookalike?.target || localRisk.matchedTarget || 'known service';

  if (hasSavedCredential) {
    domainAuthStatus = 'match';
    domainAuthLabel = 'Verified Credential Domain';
    domainAuthDetail = 'Matches your saved vault credentials for this website.';
  } else if (isLookalike) {
    domainAuthStatus = 'lookalike';
    domainAuthLabel = 'Deceptive Lookalike Domain';
    domainAuthDetail = `Resembles ${targetBrand} (possible typosquatting or brand impersonation).`;
  } else if (score >= 70) {
    domainAuthStatus = 'untrusted';
    domainAuthLabel = 'Untrusted Hostname';
    domainAuthDetail = 'Identified by threat intelligence or security heuristics as suspicious.';
  }

  const threatIntelSignals = Object.entries(riskAssessment?.threat_intel_signals || {}).map(
    ([k, v]) => `${k}: ${v}`
  );
  const isThreatIntelClean =
    threatIntelSignals.length === 0 ||
    threatIntelSignals.every((s) => s.includes('clean') || s.includes('unavailable'));

  const threatIntel = {
    clean: isThreatIntelClean,
    label: isThreatIntelClean ? 'Threat Feeds Clean' : 'Threat Intelligence Alert',
    detail: isThreatIntelClean
      ? 'No known phishing, malware, or abuse reports found on global security databases.'
      : 'Flagged on active security intelligence feeds.',
    signals: threatIntelSignals,
  };

  // Credential Guard
  let credGuardStatus: 'protected' | 'autofill_allowed' | 'autofill_blocked' = 'protected';
  let credGuardLabel = 'Credential Guard Active';
  let credGuardDetail = 'Monitoring for unauthorized credential capture.';

  if (verdict === 'danger') {
    credGuardStatus = 'autofill_blocked';
    credGuardLabel = 'Autofill Blocked by Shield';
    credGuardDetail = 'Credential autofill, passkeys, and auto-copy are strictly blocked for your safety.';
  } else if (hasSavedCredential) {
    credGuardStatus = 'autofill_allowed';
    credGuardLabel = 'Safe for Autofill';
    credGuardDetail = 'Verified domain matches your saved login. Autofill is permitted.';
  }

  const trackersAndScripts = {
    scriptCount,
    externalOriginsCount,
    hasCrossDomainForm,
    label:
      scriptCount > 0
        ? `${scriptCount} script${scriptCount === 1 ? '' : 's'}${
            externalOriginsCount > 0 ? ` across ${externalOriginsCount} origin${externalOriginsCount === 1 ? '' : 's'}` : ''
          }`
        : `${externalOriginsCount} external script origin${externalOriginsCount === 1 ? '' : 's'}`,
  };

  return {
    url,
    hostname,
    title,
    favIconUrl,
    timestamp: Date.now(),
    riskScore: score,
    riskLevel,
    verdict,
    headline,
    summary,
    encryption,
    domainAuthenticity: {
      status: domainAuthStatus,
      label: domainAuthLabel,
      detail: domainAuthDetail,
      matchedTarget: lookalike?.target || localRisk.matchedTarget || undefined,
    },
    threatIntel,
    credentialGuard: {
      status: credGuardStatus,
      label: credGuardLabel,
      detail: credGuardDetail,
    },
    trackersAndScripts,
    reasons: Array.from(
      new Set([
        ...(riskAssessment?.reasons || []),
        ...(localRisk.reasons || []),
        ...(lookalike ? [lookalike.reason] : []),
      ])
    ),
  };
}
