/**
 * Standard RFC 6238 TOTP (Time-based One-Time Password) implementation
 * Using native Web Crypto API (SubtleCrypto HMAC-SHA1).
 */

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a base32 string into a Uint8Array.
 * Tolerates spaces, dashes, and lowercase characters.
 */
export function base32ToBytes(base32: string): Uint8Array {
  const clean = base32.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_CHARS.indexOf(clean[i]);
    if (idx === -1) continue; // ignore unknown chars

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Parses an otpauth://totp/ URI or raw base32 secret.
 */
export function parseTotpSecret(secretOrUri: string): { secret: string; issuer?: string; account?: string } | null {
  if (!secretOrUri || typeof secretOrUri !== 'string') return null;
  const trimmed = secretOrUri.trim();

  if (trimmed.startsWith('otpauth://totp/')) {
    try {
      const url = new URL(trimmed);
      const secret = url.searchParams.get('secret');
      if (!secret) return null;
      const issuer = url.searchParams.get('issuer') || undefined;
      const label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
      return { secret, issuer, account: label };
    } catch {
      return null;
    }
  }

  // Raw secret string
  const clean = trimmed.replace(/[\s-]/g, '');
  if (/^[A-Za-z2-7=]+$/.test(clean) && clean.length >= 8) {
    return { secret: clean };
  }

  return null;
}

/**
 * Generates an RFC 6238 6-digit TOTP code and returns the code and remaining seconds in current 30s window.
 */
export async function generateTotp(
  secretKey: string,
  period = 30,
  digits = 6,
  timeMs: number = Date.now()
): Promise<{ code: string; remainingSeconds: number; period: number }> {
  const epochSeconds = Math.floor(timeMs / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remainingSeconds = period - (epochSeconds % period);

  const keyBytes = base32ToBytes(secretKey);
  if (keyBytes.length === 0) {
    throw new Error('Invalid TOTP secret');
  }

  // Counter as 8-byte big-endian buffer
  const counterBuf = new ArrayBuffer(8);
  const counterView = new DataView(counterBuf);
  // High 32 bits are 0 for timestamps up to year 2038+
  counterView.setUint32(0, Math.floor(counter / 0x100000000));
  counterView.setUint32(4, counter >>> 0);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const hmacSig = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const hmacBytes = new Uint8Array(hmacSig);

  // Dynamic truncation (RFC 4226)
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const binary =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  const code = otp.toString().padStart(digits, '0');

  return { code, remainingSeconds, period };
}
