import { describe, expect, it } from 'vitest';
import { automaticTextScansAllowed, TEXT_SCAN_CONSENT_KEY, TEXT_SCAN_CONSENT_VERSION } from './textScanPrivacy';
import { redactText } from './pageContent';
describe('AI text scan privacy', () => {
  it.each([{}, { [TEXT_SCAN_CONSENT_KEY]: true }, { [TEXT_SCAN_CONSENT_KEY]: 'old-version' }, { [TEXT_SCAN_CONSENT_KEY]: null }])('defaults off and rejects absent, revoked or obsolete consent', async value => {
    expect(await automaticTextScansAllowed({ get: async () => value })).toBe(false);
  });
  it('requires the disclosed version and reads revocation on every call', async () => {
    const state = { [TEXT_SCAN_CONSENT_KEY]: TEXT_SCAN_CONSENT_VERSION as string | null };
    const storage = { get: async () => state };
    expect(await automaticTextScansAllowed(storage)).toBe(true);
    state[TEXT_SCAN_CONSENT_KEY] = null;
    expect(await automaticTextScansAllowed(storage)).toBe(false);
  });
  it('fails closed when preferences cannot be read', async () => {
    expect(await automaticTextScansAllowed({ get: async () => { throw new Error('unavailable'); } })).toBe(false);
  });
  it.each(['AKIAABCDEFGHIJKLMNOP', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'password=hunter-fixture', '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'])('removes known structured secrets before sending', secret => {
    const result = redactText(secret, 2000);
    expect(result).not.toContain(secret); expect(result).not.toContain('hunter-fixture');
  });
  it('documents the residual prose limitation instead of claiming universal redaction', () => {
    expect(redactText('a confidential sentence', 2000)).toBe('a confidential sentence');
  });
});
