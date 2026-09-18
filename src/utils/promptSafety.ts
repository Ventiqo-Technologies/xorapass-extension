// AI "Is This Safe?" Analyzer Utility
// Analyzes user-pasted text, suspicious URLs, SMS, and emails for scams,
// phishing hooks, lookalike URLs, brand impersonation, and urgency traps.

import { extractHostname, registrableDomain } from './siteTrust';
import {
  assessDomainRisk,
  type DomainRiskAssessment,
} from './domainRisk';

export interface PromptAnalysisResult {
  input: string;
  verdict: 'safe' | 'suspicious' | 'phishing';
  riskScore: number; // 0-100
  title: string;
  summary: string;
  extractedUrls: string[];
  detectedBrands: string[];
  threatSignals: string[];
  recommendations: string[];
  urlAssessments?: { url: string; hostname: string; risk: DomainRiskAssessment }[];
}

// Regex to detect web URLs (with or without http/https)
const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|ai|co|uk|de|xyz|top|online|site|app|live|info|ru|cn|buzz|link|shop|club|vip|icu|cam|work|rest|fit|tk|ml|ga|cf|gq)(?:\/[^\s<>"'{}|\\^`\[\]]*)?/gi;

// Common high-profile brands targeted by phishers
const KNOWN_PHISHED_BRANDS = [
  { name: 'Netflix', domains: ['netflix.com'] },
  { name: 'PayPal', domains: ['paypal.com'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'] },
  { name: 'Google', domains: ['google.com', 'gmail.com'] },
  { name: 'Meta / Facebook', domains: ['facebook.com', 'meta.com', 'instagram.com'] },
  { name: 'Chase Bank', domains: ['chase.com'] },
  { name: 'Bank of America', domains: ['bankofamerica.com'] },
  { name: 'Wells Fargo', domains: ['wellsfargo.com'] },
  { name: 'UPS / FedEx / DHL', domains: ['ups.com', 'fedex.com', 'dhl.com'] },
  { name: 'USPS', domains: ['usps.com'] },
  { name: 'Coinbase', domains: ['coinbase.com'] },
  { name: 'Binance', domains: ['binance.com'] },
  { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'GitHub', domains: ['github.com'] },
  { name: 'Dropbox', domains: ['dropbox.com'] },
];

/** Registrable domains of commonly phished brands (for lookalike checks when the vault is locked). */
export const KNOWN_BRAND_DOMAINS: readonly string[] = Array.from(
  new Set(KNOWN_PHISHED_BRANDS.flatMap((b) => b.domains))
);

// High-urgency scam vocabulary
const URGENCY_TRIGGERS = [
  { pattern: /\b(suspended|disabled|deactivated|locked|terminated|closed)\b/i, signal: 'Account suspension threat' },
  { pattern: /\b(unauthorized|suspicious activity|fraudulent|compromised|breached)\b/i, signal: 'Unverified security alert' },
  { pattern: /\b(immediate|urgent|within 24 hours|action required|limited time|expires today)\b/i, signal: 'Artificial urgency / deadline' },
  { pattern: /\b(verify your identity|confirm your password|update your payment|billing error)\b/i, signal: 'Credential or payment verification request' },
  { pattern: /\b(refund|wire transfer|inheritance|lottery|winner|won|crypto payout)\b/i, signal: 'Financial payout / windfall lure' },
  { pattern: /\b(gift card|bitcoin|ethereum|seed phrase|private key)\b/i, signal: 'Irreversible payment / crypto solicitation' },
  { pattern: /\b(delivery failed|package pending|reschedule delivery|customs fee)\b/i, signal: 'Delivery / courier phishing lure' },
];

/**
 * Analyzes arbitrary user input (URL, SMS text, email snippet)
 * using local heuristics, brand mapping, and vault domain context.
 */
export function analyzePromptSafety(
  rawInput: string,
  knownVaultHosts: string[] = []
): PromptAnalysisResult {
  const input = (rawInput || '').trim();
  if (!input) {
    return {
      input: '',
      verdict: 'safe',
      riskScore: 0,
      title: 'No input provided',
      summary: 'Paste a link, SMS message, or email text to scan.',
      extractedUrls: [],
      detectedBrands: [],
      threatSignals: [],
      recommendations: ['Enter or paste text into the scanner.'],
    };
  }

  // 1. Extract URLs
  const rawUrls = input.match(URL_REGEX) || [];
  const extractedUrls = Array.from(new Set(rawUrls.map((u) => u.replace(/[.,;!?)]+$/, ''))));

  // Build full list of legitimate targets: known brands + user's vault domains
  const legitimateTargets = new Set<string>();
  for (const b of KNOWN_PHISHED_BRANDS) {
    for (const d of b.domains) legitimateTargets.add(d);
  }
  for (const h of knownVaultHosts) {
    const reg = registrableDomain(extractHostname(h));
    if (reg) legitimateTargets.add(reg);
  }
  const allKnownTargets = Array.from(legitimateTargets);

  // 2. Assess extracted URLs
  const threatSignals: string[] = [];
  const detectedBrands: string[] = [];
  const urlAssessments: { url: string; hostname: string; risk: DomainRiskAssessment }[] = [];
  let highestUrlRisk = 0;

  for (const rawUrl of extractedUrls) {
    const host = extractHostname(rawUrl);
    if (!host) continue;

    const risk = assessDomainRisk(host, allKnownTargets);
    urlAssessments.push({ url: rawUrl, hostname: host, risk });

    if (risk.riskScore > highestUrlRisk) {
      highestUrlRisk = risk.riskScore;
    }

    if (risk.matchedTarget) {
      detectedBrands.push(risk.matchedTarget);
    }
    if (risk.signals.hasPunycode) {
      threatSignals.push(`Punycode / Homograph domain detected in link: "${host}"`);
    }
    if (risk.signals.brandAbuse) {
      threatSignals.push(`Brand impersonation in URL: "${host}" impersonates "${risk.signals.brandAbuse.brand}"`);
    }
    if (risk.signals.typosquatTarget) {
      threatSignals.push(`Typosquatting link: "${host}" mimics legitimate "${risk.signals.typosquatTarget}"`);
    }
    if (risk.signals.isHighRiskTld) {
      threatSignals.push(`Suspicious high-risk TLD in link: "${host}"`);
    }
  }

  // 3. Brand mention analysis in text
  for (const b of KNOWN_PHISHED_BRANDS) {
    const brandRegex = new RegExp(`\\b${b.name.replace('/', '|')}\\b`, 'i');
    if (brandRegex.test(input)) {
      detectedBrands.push(b.name);

      // Check if text mentions brand but links to an unrelated domain
      if (extractedUrls.length > 0) {
        const hasLegitimateDomain = extractedUrls.some((u) => {
          const host = extractHostname(u);
          const reg = registrableDomain(host);
          return b.domains.some((d) => reg === d || host === d);
        });

        if (!hasLegitimateDomain) {
          threatSignals.push(
            `Brand mismatch: Message mentions ${b.name}, but link points to an external, unrelated destination.`
          );
          highestUrlRisk = Math.max(highestUrlRisk, 85);
        }
      }
    }
  }

  // 4. Urgency and lure analysis
  for (const trigger of URGENCY_TRIGGERS) {
    if (trigger.pattern.test(input)) {
      threatSignals.push(trigger.signal);
    }
  }

  // 5. Compute composite risk score
  let totalScore = 0;

  if (extractedUrls.length > 0) {
    totalScore += highestUrlRisk * 0.7;
  } else {
    // Plain text without URL (e.g. phone scam or crypto solicitation)
    totalScore += Math.min(threatSignals.length * 20, 70);
  }

  // Add weight for urgency triggers (each adds 10, max 30)
  const urgencyCount = URGENCY_TRIGGERS.filter((t) => t.pattern.test(input)).length;
  totalScore += Math.min(urgencyCount * 12, 30);

  // Shortlink detector
  const isShortlink = extractedUrls.some((u) =>
    /(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|ow\.ly|buff\.ly)/i.test(u)
  );
  if (isShortlink) {
    threatSignals.push('Obfuscated shortlink detected (e.g. bit.ly). Conceals final destination.');
    totalScore = Math.max(totalScore, 60);
  }

  const normalizedScore = Math.min(Math.round(totalScore), 100);

  // 6. Verdict & recommendations
  let verdict: 'safe' | 'suspicious' | 'phishing' = 'safe';
  let title = 'Looks Safe';
  let summary = 'No suspicious lookalikes, brand mismatches, or scam lures detected.';
  const recommendations: string[] = [];

  if (normalizedScore >= 70) {
    verdict = 'phishing';
    title = 'High Risk Phishing / Scam';
    summary = 'This message or link exhibits strong indicators of a credential harvesting or financial scam attempt.';
    recommendations.push('Do NOT click the link or follow instructions in this message.');
    recommendations.push('Do NOT enter your password, credit card, or 2FA codes.');
    if (detectedBrands.length > 0) {
      recommendations.push(`If you need to check your account, navigate to the official website directly.`);
    }
  } else if (normalizedScore >= 35) {
    verdict = 'suspicious';
    title = 'Suspicious / Caution Advised';
    summary = 'This message contains urgency tactics or unfamiliar links. Verify sender before proceeding.';
    recommendations.push('Verify the sender via a known trusted phone number or official app.');
    recommendations.push('Inspect where links lead before clicking.');
  } else {
    verdict = 'safe';
    title = 'No Threats Found';
    summary = 'The message and links match legitimate or safe patterns.';
    recommendations.push('Always ensure the browser address bar displays the official HTTPS lock icon.');
  }

  return {
    input,
    verdict,
    riskScore: normalizedScore,
    title,
    summary,
    extractedUrls,
    detectedBrands: Array.from(new Set(detectedBrands)),
    threatSignals: Array.from(new Set(threatSignals)),
    recommendations,
    urlAssessments,
  };
}
