// XoraPass Shield decision pipeline (pure).
//
// Layers, cheapest first:
//   L0  user allowlist / trusted — the user's explicit allowlist, their own
//       saved sites, platform-trusted domains (server config) and the built-in
//       list of major legitimate platforms. Allowed without further checks,
//       EXCEPT that a confirmed blocklist hit still wins over "trusted"
//       (a compromised page on a well-known host is exactly what lists catch).
//   L1  blocklist — local hash-prefix set, confirmed by full hash on a hit.
//   L2  local heuristics — lookalike/typosquat/homograph engine (domainRisk.ts)
//       plus the page-shape signals collected by the content script.
//   L3  server — threat-intel feeds + page classifier, ONLY when L2 found
//       something, or the page asks for a credential/card and isn't trusted.
//
// Everything here is side-effect free; background/shield.ts supplies inputs.

import { extractHostname, isDomainMatch, isUserContentHost, isFreeHostingHost, registrableDomain } from './siteTrust';
import { KNOWN_LEGITIMATE_DOMAINS, type DomainRiskAssessment } from './domainRisk';
import type { ShieldConfig } from './shieldConfig';
import type { PageSignals } from './pageSignals';

export type ShieldLayer = 'disabled' | 'unsupported' | 'allowlist' | 'blocklist' | 'trusted' | 'heuristic' | 'none';

export interface NavDecision {
  action: 'allow' | 'warn' | 'block';
  layer: ShieldLayer;
  reasons: string[];
  matchedTarget?: string | null;
  threatType?: string;
}

export interface BlocklistHit {
  threatType: string;
  source: string;
}

/** L0: is this host one we trust without asking anyone? */
export function isTrustedHost(host: string, knownHosts: readonly string[], trustedDomains: readonly string[]): boolean {
  const h = extractHostname(host);
  if (!h) return false;
  if (knownHosts.some((k) => isDomainMatch(h, k))) return true;
  if (isUserContentHost(h)) return false;
  const reg = registrableDomain(h);
  if (KNOWN_LEGITIMATE_DOMAINS.has(reg)) return true;
  return trustedDomains.some((t) => h === t || h.endsWith('.' + t));
}

export function isAllowlistedHost(host: string, allowlist: readonly string[]): boolean {
  const h = extractHostname(host);
  if (!h) return false;
  return allowlist.some((a) => {
    const x = extractHostname(a);
    return !!x && (h === x || h.endsWith('.' + x) || registrableDomain(h) === registrableDomain(x));
  });
}

const THREAT_LABELS: Record<string, string> = {
  // Qualified wording (Web Risk display rules): a listing is "suspected".
  SOCIAL_ENGINEERING: 'This page is on a list of suspected phishing and scam sites.',
  SOCIAL_ENGINEERING_EXTENDED_COVERAGE: 'This page is on a list of suspected phishing and scam sites.',
  MALWARE: 'This page is on a list of sites that may distribute malware.',
  UNWANTED_SOFTWARE: 'This page is on a list of sites that may push unwanted software.',
  XORAPASS_BLOCKLIST: 'XoraPass has blocked this site as likely dangerous.',
};

export function threatReason(threatType: string): string {
  return THREAT_LABELS[threatType] || 'This page is on a list of suspected dangerous sites.';
}

/**
 * Navigation-time verdict (runs before the page renders). Only 'block' is
 * acted on at this stage; softer findings are left to the page-level check
 * that has the page's structure to work with.
 */
export function decideNavigation(input: {
  url: string;
  config: ShieldConfig;
  active: boolean;
  userAllowlist: readonly string[];
  knownHosts: readonly string[];
  blocklistHit: BlocklistHit | null;
  local: DomainRiskAssessment | null;
}): NavDecision {
  const { url, config, active } = input;
  if (!active || !config.shield_enabled || !config.nav_guard.enabled) {
    return { action: 'allow', layer: 'disabled', reasons: [] };
  }
  if (!/^https?:\/\//i.test(url)) return { action: 'allow', layer: 'unsupported', reasons: [] };
  const host = extractHostname(url);
  if (!host) return { action: 'allow', layer: 'unsupported', reasons: [] };

  if (isAllowlistedHost(host, input.userAllowlist)) return { action: 'allow', layer: 'allowlist', reasons: [] };

  if (input.blocklistHit) {
    return {
      action: 'block',
      layer: 'blocklist',
      reasons: [threatReason(input.blocklistHit.threatType)],
      threatType: input.blocklistHit.threatType,
    };
  }

  if (isTrustedHost(host, input.knownHosts, config.trusted_domains)) {
    return { action: 'allow', layer: 'trusted', reasons: [] };
  }

  const local = input.local;
  if (local && local.decision === 'block' && local.riskScore >= config.nav_guard.block_score) {
    return { action: 'block', layer: 'heuristic', reasons: local.reasons, matchedTarget: local.matchedTarget };
  }
  if (local && local.decision !== 'allow') {
    return { action: 'warn', layer: 'heuristic', reasons: local.reasons, matchedTarget: local.matchedTarget };
  }
  return { action: 'allow', layer: 'none', reasons: [] };
}

/**
 * L3 gate: should this page-level check ask the server? Keeps ordinary
 * browsing off the network — the server only sees pages the local layers
 * found suspicious, or untrusted pages actually asking for a secret.
 */
export function shouldEscalateRemote(input: {
  config: ShieldConfig;
  local: DomainRiskAssessment;
  trusted: boolean;
  pageSignals?: PageSignals;
  hasCredentialForm?: boolean;
  hasLeadCaptureForm?: boolean;
  crossOriginFormAction?: boolean;
  scamCues?: string[];
}): boolean {
  const { config, local } = input;
  if (!config.shield_enabled || !config.remote.enabled) return false;
  if (local.isAllowlisted) return false;
  if (input.trusted) {
    // A trusted site posting credentials elsewhere is still worth a look.
    return !!input.crossOriginFormAction;
  }
  if (local.riskScore >= config.remote.min_local_score) return true;

  // Free hosting or user-content platforms (vercel.app, pages.dev, netlify.app, etc.)
  // are untrusted arbitrary tenant environments: always verify with threat intel.
  const host = local.pageHostname;
  if (isFreeHostingHost(host) || isUserContentHost(host)) return true;

  // High-risk TLD, suspicious keywords, or scam cues: escalate regardless of local score
  const isHighRiskTld = !!local.signals?.isHighRiskTld;
  const hasSuspiciousKeywords = (local.signals?.suspiciousKeywords?.length ?? 0) > 0;
  const hasScamCues = (input.scamCues?.length ?? 0) > 0;
  if (isHighRiskTld || hasSuspiciousKeywords || hasScamCues) return true;

  const credentialPage =
    !!input.hasCredentialForm ||
    !!input.hasLeadCaptureForm ||
    (input.pageSignals?.password_field_count ?? 0) > 0 ||
    !!input.pageSignals?.form_action_cross_origin;
  return config.remote.on_credential_forms && credentialPage;
}
