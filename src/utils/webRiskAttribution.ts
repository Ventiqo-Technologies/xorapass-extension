// Google Web Risk display requirements
// (https://cloud.google.com/web-risk/docs/user-warnings):
//   • warnings must be qualified ("suspected", "likely", "may") — never
//     presented as certain;
//   • show "Advisory provided by Google" linking to the Web Risk advisory
//     page, plus a "learn more" resource for the threat type;
//   • before a user turns protection on, show Google's no-guarantee notice.

export interface ThreatAdvisory {
  text: string;
  url: string;
  learnMoreUrl: string;
}

export const GOOGLE_ADVISORY_URL = 'https://cloud.google.com/web-risk/docs/advisory';

export const GOOGLE_NO_GUARANTEE_NOTICE =
  'Phishing and malware protection uses Google Web Risk and other security services. Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be identified in error.';

const LEARN_MORE: Record<string, string> = {
  phishing: 'https://www.antiphishing.org/',
  malware: 'https://developers.google.com/search/docs/monitor-debug/security/malware',
  unwanted: 'https://www.google.com/about/unwanted-software-policy.html',
};

function advisory(kind: 'phishing' | 'malware' | 'unwanted'): ThreatAdvisory {
  return { text: 'Advisory provided by Google', url: GOOGLE_ADVISORY_URL, learnMoreUrl: LEARN_MORE[kind] };
}

/** From the server's threat_intel_signals: attribution when Google flagged the URL. */
export function webRiskAdvisoryFromSignals(signals?: Record<string, string> | null): ThreatAdvisory | null {
  const s = signals?.google_web_risk;
  if (s === 'phishing_hit') return advisory('phishing');
  if (s === 'malware_hit') return advisory('malware');
  if (s === 'suspicious_scan') return advisory('unwanted');
  return null;
}

/** From a blocklist threat type (Update API lists are Google's). */
export function webRiskAdvisoryFromThreatType(threatType?: string | null): ThreatAdvisory | null {
  switch (threatType) {
    case 'SOCIAL_ENGINEERING':
    case 'SOCIAL_ENGINEERING_EXTENDED_COVERAGE':
      return advisory('phishing');
    case 'MALWARE':
      return advisory('malware');
    case 'UNWANTED_SOFTWARE':
      return advisory('unwanted');
    default:
      return null;
  }
}
