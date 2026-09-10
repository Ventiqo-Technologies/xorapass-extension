import { describe, it, expect } from 'vitest';
import { parseTotpSecret, generateTotp, base32ToBytes } from './totp';

describe('TOTP Utils', () => {
  it('correctly decodes base32 strings', () => {
    // RFC 4648 test vectors
    // "JBSWY3DPEHPK3PXP" is standard test secret
    const bytes = base32ToBytes('JBSWY3DPEHPK3PXP');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(10);
  });

  it('parses otpauth URI', () => {
    const uri = 'otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    const parsed = parseTotpSecret(uri);
    expect(parsed).not.toBeNull();
    expect(parsed?.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(parsed?.issuer).toBe('Example');
  });

  it('parses raw base32 secret', () => {
    const raw = 'JBSW Y3DP EHPK 3PXP';
    const parsed = parseTotpSecret(raw);
    expect(parsed).not.toBeNull();
    expect(parsed?.secret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('generates standard 6-digit TOTP code and remaining seconds', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const res = await generateTotp(secret, 30, 6, 1700000000000);
    expect(res.code).toMatch(/^\d{6}$/);
    expect(res.remainingSeconds).toBeGreaterThan(0);
    expect(res.remainingSeconds).toBeLessThanOrEqual(30);
  });
});
