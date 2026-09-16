// Pure, on-device email phishing & sender impersonation detection.
// Free of DOM/chrome APIs for Vitest testing and zero-knowledge privacy.
// No email text or headers are ever transmitted across the network.

import { findLookalikeTarget, registrableDomain } from './siteTrust';

// Common high-target brands frequently impersonated in phishing campaigns
export const BRAND_DOMAINS: Record<string, string[]> = {
  paypal: ['paypal.com'],
  microsoft: ['microsoft.com', 'office.com', 'live.com', 'outlook.com'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'gmail.com'],
  amazon: ['amazon.com'],
  netflix: ['netflix.com'],
  chase: ['chase.com'],
  'bank of america': ['bankofamerica.com', 'bofa.com'],
  wells: ['wellsfargo.com'],
  meta: ['meta.com', 'facebook.com', 'instagram.com'],
  dhl: ['dhl.com'],
  fedex: ['fedex.com'],
  ups: ['ups.com'],
  usps: ['usps.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
  stripe: ['stripe.com'],
  dropbox: ['dropbox.com'],
  linkedin: ['linkedin.com'],
  github: ['github.com'],
};

export interface EmailSenderAnalysis {
  isImpersonation: boolean;
  claimedBrand: string | null;
  senderEmail: string;
  senderDomain: string;
  expectedDomains: string[];
  reasons: string[];
  riskScore: number;
}

/**
 * Extracts email address and domain from standard format: "Display Name <user@domain.com>" or "user@domain.com"
 */
export function parseSender(raw: string): { displayName: string; email: string; domain: string } {
  const trimmed = (raw || '').trim();
  const match = trimmed.match(/^(.*?)(?:<([^>]+)>)?$/);
  if (!match) return { displayName: '', email: '', domain: '' };

  const displayName = (match[1] || '').trim().replace(/^["']|["']$/g, '');
  const email = (match[2] || match[1] || '').trim().toLowerCase();

  const domainMatch = email.match(/@([^@\s]+)$/);
  const domain = domainMatch ? domainMatch[1].toLowerCase() : '';

  return { displayName, email, domain };
}

/**
 * Analyzes whether an email sender exhibits spoofing or display name impersonation.
 */
export function analyzeEmailSender(rawSender: string): EmailSenderAnalysis {
  const { displayName, email, domain } = parseSender(rawSender);
  const reasons: string[] = [];
  let claimedBrand: string | null = null;
  let expectedDomains: string[] = [];
  let riskScore = 0;

  const normalizedDisplay = displayName.toLowerCase();
  const regDomain = registrableDomain(domain) || domain;

  // Check if display name claims to be one of the high-target brands
  for (const [brand, allowedDomains] of Object.entries(BRAND_DOMAINS)) {
    const brandRegex = new RegExp(`\\b${brand.replace(/\s+/g, '[\\s-_]?')}\\b`, 'i');
    if (brandRegex.test(normalizedDisplay)) {
      claimedBrand = brand;
      expectedDomains = allowedDomains;

      const isAllowed = allowedDomains.some((d) => {
        const allowedReg = registrableDomain(d) || d;
        // Check exact match, subdomain, or base brand match on valid ccTLDs (e.g. paypal.co.uk)
        if (domain === d || domain.endsWith('.' + d) || regDomain === allowedReg) return true;
        const brandLabel = allowedReg.split('.')[0];
        if (regDomain.split('.')[0] === brandLabel) return true;
        return false;
      });

      if (!isAllowed) {
        riskScore = 85;
        reasons.push(
          `Sender display name claims to be "${displayName}", but originated from unverified domain "@${domain}".`
        );
      }
      break;
    }
  }

  // Check if the domain itself is a lookalike/typosquat of a major service
  if (!claimedBrand && domain) {
    const allKnownTargets: string[] = [];
    for (const doms of Object.values(BRAND_DOMAINS)) {
      allKnownTargets.push(...doms);
    }
    const lookalike = findLookalikeTarget(domain, allKnownTargets);
    if (lookalike) {
      riskScore = 80;
      reasons.push(`Sender domain "${domain}" mimics known service "${lookalike.target}".`);
    }
  }

  // Free webmail impersonating corporate security alerts
  const freeMailProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'proton.me', 'protonmail.com'];
  if (
    /security|support|billing|account[-_]?team|fraud|verification|alert/i.test(normalizedDisplay) &&
    freeMailProviders.includes(domain) &&
    !displayName.toLowerCase().includes('google') &&
    !displayName.toLowerCase().includes('microsoft')
  ) {
    riskScore = Math.max(riskScore, 75);
    reasons.push(
      `Official security or billing notice sent from a personal/free email address (@${domain}).`
    );
  }

  return {
    isImpersonation: reasons.length > 0,
    claimedBrand,
    senderEmail: email,
    senderDomain: domain,
    expectedDomains,
    reasons,
    riskScore,
  };
}

/**
 * Checks if the current page is a supported webmail interface.
 */
export function isSupportedWebmail(hostname: string): boolean {
  const h = (hostname || '').toLowerCase();
  return (
    h === 'mail.google.com' ||
    h === 'outlook.live.com' ||
    h === 'outlook.office.com' ||
    h === 'outlook.office365.com'
  );
}
