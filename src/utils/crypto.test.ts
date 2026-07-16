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
import { deriveMasterKey, splitMasterKey, encryptPayload, decryptPayload, bytesToHex } from './crypto';

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

    const { encryptedPayload, nonce } = encryptPayload(plaintext, encKey);
    expect(encryptedPayload.ciphertext).toBeTypeOf('string');
    expect(encryptedPayload.tag).toBeTypeOf('string');
    expect(nonce).toBeTypeOf('string');

    const decrypted = decryptPayload(encryptedPayload, nonce, encKey);
    expect(decrypted).toBe(plaintext);
  });

  it('should fail decryption if ciphertext or tag is tampered with', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);
    const plaintext = "Tamper proof test";

    const { encryptedPayload, nonce } = encryptPayload(plaintext, encKey);

    // Tamper with ciphertext
    const tamperedPayload = {
      ciphertext: encryptedPayload.ciphertext.slice(0, -4) + "AAAA",
      tag: encryptedPayload.tag
    };

    expect(() => decryptPayload(tamperedPayload, nonce, encKey)).toThrow();

    // Tamper with tag
    const tamperedTagPayload = {
      ciphertext: encryptedPayload.ciphertext,
      tag: encryptedPayload.tag.slice(0, -4) + "AAAA"
    };

    expect(() => decryptPayload(tamperedTagPayload, nonce, encKey)).toThrow();
  });

  it('should fail decryption if a wrong key is used', async () => {
    const masterKey = await deriveMasterKey(password, saltHex);
    const { encKey } = await splitMasterKey(masterKey);
    
    const wrongMasterKey = await deriveMasterKey("WrongPassword", saltHex);
    const { encKey: wrongEncKey } = await splitMasterKey(wrongMasterKey);

    const plaintext = "Secret payload";
    const { encryptedPayload, nonce } = encryptPayload(plaintext, encKey);

    expect(() => decryptPayload(encryptedPayload, nonce, wrongEncKey)).toThrow();
  });
});
