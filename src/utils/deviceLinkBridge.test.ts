import { beforeAll, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';

// Same two setup requirements crypto.test.ts and messageGuard.test.ts each
// need separately: real WebCrypto for the ECDH/XChaCha20 primitives, and a
// minimal webextension-polyfill mock for validateMessage's origin checks.
beforeAll(() => {
  globalThis.window = {
    crypto: webcrypto,
    atob: (str: string) => Buffer.from(str, 'base64').toString('binary'),
    btoa: (str: string) => Buffer.from(str, 'binary').toString('base64'),
  } as any;
});

vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: {
      id: 'own-extension-id',
      getURL: (path: string) => `chrome-extension://own-extension-id/${path}`,
    },
  },
}));

import { generateSharingKeyPair, deriveSharedSecret, encryptPayload, decryptPayload, bytesToHex, hexToBytes } from './crypto';
import { validateMessage } from './messageGuard';

const externalWebSender = (): any => ({ url: 'https://app.xorapass.com/', origin: 'https://app.xorapass.com' });

// Regression test for two real bugs caught in review, both from the same
// root cause: a hand-typed fixture matching the WRONG shape instead of
// running the real protocol.
//
// 1. messageGuard once validated `encryptedEncKey` (a bare string) that
//    neither side ever actually sent -- the real field was `sealedEncKey`
//    (an EncryptedPayload object) plus `ephemeralPublicKey`.
// 2. The access token and email used to travel as plaintext fields next to
//    the encrypted vault key -- the same shape of risk as "extension sends
//    its access token to the website" mirrored. They now travel INSIDE the
//    sealed envelope (`sealed`) alongside the vault key, so the only
//    plaintext field left in the message is the ephemeral public key,
//    which is not secret by definition.
//
// This test runs the REAL protocol both sides use -- generate real keys,
// encrypt for real, validate the real resulting message -- so a shape drift
// between sender/handler/guard fails here immediately instead of silently
// passing a fixture that happens to agree with itself.
describe('device-link bridge: real protocol round trip', () => {
  it('a WEB_BRIDGE_DELIVER_KEY payload built the way the web app really builds it passes validateMessage and decrypts to the token/email/key/refreshToken', async () => {
    // "Extension" side: its own persistent device keypair.
    const deviceKeyPair = await generateSharingKeyPair();
    // "Web app" side: a fresh ephemeral keypair for this one delivery.
    const ephemeralKeyPair = await generateSharingKeyPair();

    const encKeyHex = bytesToHex(webcrypto.getRandomValues(new Uint8Array(32)));
    const token = 'jwt-token';
    const email = 'a@b.c';
    const refreshToken = 'refresh-secret';

    // Exactly what apps/web/src/utils/extensionLink.ts's deliverKeyToDevice
    // does: bundle encKeyHex/token/email/refreshToken into one JSON
    // plaintext, THEN encrypt that as a single envelope. refreshToken is
    // included conditionally there (a web app session without one, e.g. an
    // older build, just omits the field) -- covered here since it's the
    // whole reason a bridged extension session can now self-renew instead
    // of dying at its own natural expiry with nothing to rescue it.
    const sharedSecretSender = await deriveSharedSecret(ephemeralKeyPair.privateKey, deviceKeyPair.publicKey);
    const inner = JSON.stringify({ encKeyHex, token, email, refreshToken });
    const sealed = encryptPayload(inner, sharedSecretSender);
    const message = {
      type: 'WEB_BRIDGE_DELIVER_KEY',
      payload: {
        ephemeralPublicKey: ephemeralKeyPair.publicKey,
        sealed,
      },
    };

    const guard = validateMessage(message, externalWebSender());
    expect(guard.ok).toBe(true);

    // Exactly what background.ts's WEB_BRIDGE_DELIVER_KEY handler does.
    const sharedSecretReceiver = await deriveSharedSecret(deviceKeyPair.privateKey, message.payload.ephemeralPublicKey);
    const recovered = JSON.parse(decryptPayload(message.payload.sealed, sharedSecretReceiver));
    expect(hexToBytes(recovered.encKeyHex)).toEqual(hexToBytes(encKeyHex));
    expect(recovered.token).toBe(token);
    expect(recovered.email).toBe(email);
    expect(recovered.refreshToken).toBe(refreshToken);
  });

  it('a payload from a device that was NOT the intended recipient fails to decrypt', async () => {
    const intendedDevice = await generateSharingKeyPair();
    const wrongDevice = await generateSharingKeyPair();
    const ephemeralKeyPair = await generateSharingKeyPair();

    const inner = JSON.stringify({ encKeyHex: bytesToHex(webcrypto.getRandomValues(new Uint8Array(32))), token: 't', email: 'a@b.c' });
    const sharedSecretSender = await deriveSharedSecret(ephemeralKeyPair.privateKey, intendedDevice.publicKey);
    const sealed = encryptPayload(inner, sharedSecretSender);

    const wrongSharedSecret = await deriveSharedSecret(wrongDevice.privateKey, ephemeralKeyPair.publicKey);
    expect(() => decryptPayload(sealed, wrongSharedSecret)).toThrow();
  });

  // The pull direction (WEB_BRIDGE_REQUEST_SESSION): roles are reversed from
  // DELIVER_KEY -- the EXTENSION's persistent keypair now does the
  // encrypting, and the WEB APP's fresh ephemeral keypair does the
  // decrypting. Exercised with the real primitives for the same reason as
  // above: a hand-typed fixture can silently agree with itself even when it
  // doesn't match what either side actually sends.
  it('a WEB_BRIDGE_REQUEST_SESSION round trip: extension encrypts its live session to the web app\'s ephemeral key', async () => {
    // "Extension" side: its own persistent device keypair, plus a session it
    // is currently holding unlocked.
    const deviceKeyPair = await generateSharingKeyPair();
    const token = 'jwt-token';
    const email = 'a@b.c';
    const encKeyHex = bytesToHex(webcrypto.getRandomValues(new Uint8Array(32)));

    // "Web app" side: a fresh ephemeral keypair for this one request.
    const ephemeralKeyPair = await generateSharingKeyPair();
    const message = {
      type: 'WEB_BRIDGE_REQUEST_SESSION',
      payload: { ephemeralPublicKey: ephemeralKeyPair.publicKey },
    };
    expect(validateMessage(message, externalWebSender()).ok).toBe(true);

    // Exactly what background.ts's WEB_BRIDGE_REQUEST_SESSION handler does:
    // encrypt the live session to the caller's ephemeral public key using
    // this device's own persistent private key.
    const sharedSecretExtension = await deriveSharedSecret(deviceKeyPair.privateKey, ephemeralKeyPair.publicKey);
    const inner = JSON.stringify({ encKeyHex, token, email });
    const sealed = encryptPayload(inner, sharedSecretExtension);

    // Exactly what the web app does on the response: derive the same shared
    // secret from its ephemeral private key + the extension's persistent
    // public key (ECDH is symmetric either way round), then decrypt.
    const sharedSecretWebApp = await deriveSharedSecret(ephemeralKeyPair.privateKey, deviceKeyPair.publicKey);
    const recovered = JSON.parse(decryptPayload(sealed, sharedSecretWebApp));
    expect(hexToBytes(recovered.encKeyHex)).toEqual(hexToBytes(encKeyHex));
    expect(recovered.token).toBe(token);
    expect(recovered.email).toBe(email);
  });
});
