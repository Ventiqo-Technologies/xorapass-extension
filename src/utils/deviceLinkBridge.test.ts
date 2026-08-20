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

// Regression test for a real bug caught in review: messageGuard once
// validated a field name (`encryptedEncKey`, a bare string) that neither the
// web app ever sent nor the background handler ever read -- both actually
// use `sealedEncKey` (an EncryptedPayload object) and `ephemeralPublicKey`.
// Every hand-typed fixture happened to match the wrong shape too, so nothing
// caught it. This test instead runs the REAL protocol both sides use --
// generate real keys, encrypt for real, validate the real resulting message
// -- so a shape drift between sender/handler/guard fails here immediately.
describe('device-link bridge: real protocol round trip', () => {
  it('a WEB_BRIDGE_DELIVER_KEY payload built the way the web app really builds it passes validateMessage', async () => {
    // "Extension" side: its own persistent device keypair.
    const deviceKeyPair = await generateSharingKeyPair();
    // "Web app" side: a fresh ephemeral keypair for this one delivery.
    const ephemeralKeyPair = await generateSharingKeyPair();

    const encKeyHex = bytesToHex(webcrypto.getRandomValues(new Uint8Array(32)));

    // Exactly what apps/web/src/utils/extensionLink.ts's deliverKeyToDevice does.
    const sharedSecretSender = await deriveSharedSecret(ephemeralKeyPair.privateKey, deviceKeyPair.publicKey);
    const sealedEncKey = encryptPayload(encKeyHex, sharedSecretSender);
    const message = {
      type: 'WEB_BRIDGE_DELIVER_KEY',
      payload: {
        token: 'jwt-token',
        email: 'a@b.c',
        ephemeralPublicKey: ephemeralKeyPair.publicKey,
        sealedEncKey,
      },
    };

    const guard = validateMessage(message, externalWebSender());
    expect(guard.ok).toBe(true);

    // Exactly what background.ts's WEB_BRIDGE_DELIVER_KEY handler does.
    const sharedSecretReceiver = await deriveSharedSecret(deviceKeyPair.privateKey, message.payload.ephemeralPublicKey);
    const recoveredHex = decryptPayload(message.payload.sealedEncKey, sharedSecretReceiver);
    expect(hexToBytes(recoveredHex)).toEqual(hexToBytes(encKeyHex));
  });

  it('a payload from a device that was NOT the intended recipient fails to decrypt', async () => {
    const intendedDevice = await generateSharingKeyPair();
    const wrongDevice = await generateSharingKeyPair();
    const ephemeralKeyPair = await generateSharingKeyPair();

    const encKeyHex = bytesToHex(webcrypto.getRandomValues(new Uint8Array(32)));
    const sharedSecretSender = await deriveSharedSecret(ephemeralKeyPair.privateKey, intendedDevice.publicKey);
    const sealedEncKey = encryptPayload(encKeyHex, sharedSecretSender);

    const wrongSharedSecret = await deriveSharedSecret(wrongDevice.privateKey, ephemeralKeyPair.publicKey);
    expect(() => decryptPayload(sealedEncKey, wrongSharedSecret)).toThrow();
  });
});
