import { beforeAll, describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';

// Setup browser globals before importing crypto.ts
beforeAll(() => {
  globalThis.window = {
    crypto: webcrypto,
    atob: (str: string) => Buffer.from(str, 'base64').toString('binary'),
    btoa: (str: string) => Buffer.from(str, 'binary').toString('base64')
  } as any;
});

// Import code under test
import {
  deriveMasterKey,
  splitMasterKey,
  encryptPayload,
  decryptPayload,
  generateSharingKeyPair,
  deriveSharedSecret,
  bytesToHex,
  CURRENT_KEY_VERSION,
} from './crypto';

describe('Crypto SDK Security Tests', () => {
  const password = "SuperSecurePassword123!";
  const saltHex = "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"; // 32 bytes hex

  it('should correctly derive master key using Argon2id', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    expect(masterKey).toBeInstanceOf(Uint8Array);
    expect(masterKey.length).toBe(32);

    // Test determinism (same password + salt = same key)
    const masterKey2 = await deriveMasterKey(password, saltHex);
    expect(bytesToHex(masterKey)).toBe(bytesToHex(masterKey2));

    // Test sensitivity (different password = different key)
    const masterKeyDiff = await deriveMasterKey("different_password", saltHex);
    expect(bytesToHex(masterKey)).not.toBe(bytesToHex(masterKeyDiff));
  });

  it('should split master key into encKey and clientAuthHash using HKDF', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey, clientAuthHash } = await splitMasterKey(masterKey);

    expect(encKey).toBeInstanceOf(Uint8Array);
    expect(encKey.length).toBe(32);
    expect(typeof clientAuthHash).toBe('string');
    expect(clientAuthHash.length).toBe(64); // 32 bytes hex = 64 chars

    // Test sensitivity
    const masterKeyDiff = await deriveMasterKey("different_password", saltHex);
    const splitDiff = await splitMasterKey(masterKeyDiff);
    expect(bytesToHex(encKey)).not.toBe(bytesToHex(splitDiff.encKey));
    expect(clientAuthHash).not.toBe(splitDiff.clientAuthHash);
  });

  it('should successfully encrypt and decrypt a plaintext payload', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);
    const plaintext = "This is a highly sensitive secret note!";

    const payload = encryptPayload(plaintext, encKey);
    expect(payload.ciphertext).toBeTypeOf('string');
    expect(payload.tag).toBeTypeOf('string');
    expect(payload.nonce).toBeTypeOf('string');

    const decrypted = decryptPayload(payload, encKey);
    expect(decrypted).toBe(plaintext);
  });

  it('should fail decryption if ciphertext or tag is tampered with', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);
    const plaintext = "Tamper proof test";

    const payload = encryptPayload(plaintext, encKey);

    // Tamper with ciphertext
    const tamperedCiphertext = { ...payload, ciphertext: payload.ciphertext.slice(0, -4) + "AAAA" };
    expect(() => decryptPayload(tamperedCiphertext, encKey)).toThrow();

    // Tamper with tag
    const tamperedTag = { ...payload, tag: payload.tag.slice(0, -4) + "AAAA" };
    expect(() => decryptPayload(tamperedTag, encKey)).toThrow();
  });

  it('should fail decryption if a wrong key is used', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);

    const wrongMasterKey = await deriveMasterKey("WrongPassword", saltHex);
    const { encKey: wrongEncKey } = await splitMasterKey(wrongMasterKey);

    const plaintext = "Secret payload";
    const payload = encryptPayload(plaintext, encKey);

    expect(() => decryptPayload(payload, wrongEncKey)).toThrow();
  });
});

describe('Key Versioning Tests', () => {
  const password = "SuperSecurePassword123!";
  const saltHex = "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10";

  it('should stamp encrypted payload with CURRENT_KEY_VERSION', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);

    const payload = encryptPayload("versioning test", encKey);
    expect(payload.keyVersion).toBe(CURRENT_KEY_VERSION);
    expect(payload.keyVersion).toBe(1);
  });

  it('should successfully decrypt a payload that carries the correct keyVersion', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);
    const plaintext = "Key version round-trip";

    const payload = encryptPayload(plaintext, encKey);
    expect(payload.keyVersion).toBeDefined();

    const decrypted = decryptPayload(payload, encKey);
    expect(decrypted).toBe(plaintext);
  });
});

describe('Sharing Key Pair (ECDH P-256) Tests', () => {
  it('should generate a valid ECDH P-256 key pair', async () => {
    const keyPair = await generateSharingKeyPair();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();

    // JWK checks
    expect(keyPair.publicKey.kty).toBe('EC');
    expect(keyPair.publicKey.crv).toBe('P-256');
    expect(keyPair.publicKey.x).toBeDefined();
    expect(keyPair.publicKey.y).toBeDefined();
    // Public key must NOT expose d (the private scalar)
    expect(keyPair.publicKey.d).toBeUndefined();

    expect(keyPair.privateKey.kty).toBe('EC');
    expect(keyPair.privateKey.crv).toBe('P-256');
    expect(keyPair.privateKey.d).toBeDefined(); // private scalar present
  });

  it('should derive the same shared secret on both sides (ECDH agreement)', async () => {
    // Simulate two parties each generating their own key pair
    const aliceKeyPair = await generateSharingKeyPair();
    const bobKeyPair   = await generateSharingKeyPair();

    // Alice computes shared secret using her private key + Bob's public key
    const aliceSecret = await deriveSharedSecret(aliceKeyPair.privateKey, bobKeyPair.publicKey);

    // Bob computes shared secret using his private key + Alice's public key
    const bobSecret = await deriveSharedSecret(bobKeyPair.privateKey, aliceKeyPair.publicKey);

    // Both secrets must be identical — core ECDH property
    expect(aliceSecret).toBeInstanceOf(Uint8Array);
    expect(aliceSecret.length).toBe(32);
    expect(Array.from(aliceSecret)).toEqual(Array.from(bobSecret));
  });

  it('should NOT derive the same shared secret with a mismatched key pair', async () => {
    const aliceKeyPair   = await generateSharingKeyPair();
    const bobKeyPair     = await generateSharingKeyPair();
    const malloryKeyPair = await generateSharingKeyPair();

    const aliceSecret  = await deriveSharedSecret(aliceKeyPair.privateKey, bobKeyPair.publicKey);
    const mallorySecret = await deriveSharedSecret(malloryKeyPair.privateKey, bobKeyPair.publicKey);

    expect(Array.from(aliceSecret)).not.toEqual(Array.from(mallorySecret));
  });
});
