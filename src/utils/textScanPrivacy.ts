export const TEXT_SCAN_CONSENT_KEY = 'shieldTextScanConsent';
export const TEXT_SCAN_CONSENT_VERSION = 'redacted-text-v1';
export const TEXT_SCAN_NOTICE = 'AI text analysis sends a limited, redacted page or email extract to XoraPass and OpenAI: title or subject, sender and Reply-To, link addresses and text, attachment names, and up to 2,000 characters of page text or 1,500 characters of email text. Known secret patterns are removed, but redaction cannot identify every password or confidential detail. Avoid analysis of sensitive content. Local protection continues without AI text analysis.';

export async function automaticTextScansAllowed(storage: { get(key: string): Promise<Record<string, unknown>> }): Promise<boolean> {
  try { return (await storage.get(TEXT_SCAN_CONSENT_KEY))[TEXT_SCAN_CONSENT_KEY] === TEXT_SCAN_CONSENT_VERSION; }
  catch { return false; }
}
