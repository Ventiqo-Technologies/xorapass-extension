import { argon2id } from 'hash-wasm';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import { encode as encodeUtf8, decode as decodeUtf8 } from '@stablelib/utf8';

/**
 * Key versioning: bump this when KDF parameters or cipher choice changes.
 * Every encrypted payload is stamped with this version so decryption
 * can route to the correct parameters during key rotation.
 */
export const CURRENT_KEY_VERSION = 1;

/** Structured encrypted payload — always carry the keyVersion for future rotation. */
export interface EncryptedPayload {
  ciphertext: string;  // base64
  tag: string;         // base64
  nonce: string;       // base64
  keyVersion: number;  // incremented when KDF params or cipher change
}

/** ECDH sharing key pair — exported as JWK for storage/transmission. */
export interface SharingKeyPair {
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}

// Helper: Convert Hex string to Uint8Array
export const hexToBytes = (hex: string): Uint8Array => {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};

// Helper: Convert Uint8Array to Hex string
export const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

// Helper: Convert Base64 string to Uint8Array
export const base64ToBytes = (base64: string): Uint8Array => {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
};

// Helper: Convert Uint8Array to Base64 string
export const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

/**
 * 1. Argon2id Key Derivation
 * Uses hash-wasm WebAssembly compilation.
 * Parameters follow OWASP minimums (65536 KB, 3 iterations, 4 parallelism).
 */
export async function deriveMasterKey(password: string, saltHex: string): Promise<Uint8Array> {
  const saltBytes = hexToBytes(saltHex);
  
  const hashHex = await argon2id({
    password: password,
    salt: saltBytes,
    iterations: 3,
    memorySize: 65536, // 64 MB
    parallelism: 4,
    hashLength: 32, // 256 bits
    outputType: 'hex',
  });
  
  return hexToBytes(hashHex);
}

/**
 * 2. HKDF-SHA256 Key Splitting
 * Uses the browser's native Web Crypto API to split K_master into K_enc and ClientAuthHash.
 */
export async function splitMasterKey(masterKey: Uint8Array): Promise<{ encKey: Uint8Array, clientAuthHash: string }> {
  // Import master key as raw material for derivation
  const baseKey = await crypto.subtle.importKey(
    'raw',
    masterKey as any,
    'HKDF',
    false,
    ['deriveBits']
  );
  
  // 2.1 Derive K_enc (Info = "enc_key")
  const encKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as ArrayBufferView, // empty salt
      info: encodeUtf8('enc_key') as ArrayBufferView
    } as any,
    baseKey,
    256 // 32 bytes
  );
  const encKey = new Uint8Array(encKeyBits);
  
  // 2.2 Derive ClientAuthHash (Info = "auth_hash")
  const authHashBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as ArrayBufferView,
      info: encodeUtf8('auth_hash') as ArrayBufferView
    } as any,
    baseKey,
    256 // 32 bytes
  );
  const clientAuthHash = bytesToHex(new Uint8Array(authHashBits));
  
  return { encKey, clientAuthHash };
}

/**
 * 3. XChaCha20-Poly1305 Encryption
 * Returns a structured EncryptedPayload stamped with the current keyVersion.
 * keyVersion must be persisted alongside the ciphertext so decryption can
 * select the correct KDF parameters during future key rotation.
 */
export function encryptPayload(plaintext: string, encKey: Uint8Array): EncryptedPayload {
  const cipher = new XChaCha20Poly1305(encKey);
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const plaintextBytes = encodeUtf8(plaintext);

  // Seal returns ciphertext with the 16-byte Poly1305 tag appended at the end
  const sealed = cipher.seal(nonce, plaintextBytes);

  const tagLength = 16;
  const ciphertextBytes = sealed.slice(0, sealed.length - tagLength);
  const tagBytes = sealed.slice(sealed.length - tagLength);

  return {
    ciphertext: bytesToBase64(ciphertextBytes),
    tag: bytesToBase64(tagBytes),
    nonce: bytesToBase64(nonce),
    keyVersion: CURRENT_KEY_VERSION,
  };
}

/**
 * 4. XChaCha20-Poly1305 Decryption
 * Accepts the full EncryptedPayload (including keyVersion).
 * Future versions should inspect payload.keyVersion to select the
 * correct KDF parameters or cipher before decrypting.
 */
export function decryptPayload(payload: EncryptedPayload, encKey: Uint8Array): string {
  // Future: if (payload.keyVersion !== CURRENT_KEY_VERSION) { /* re-derive with old params */ }
  const cipher = new XChaCha20Poly1305(encKey);
  const nonce = base64ToBytes(payload.nonce);
  const ciphertextBytes = base64ToBytes(payload.ciphertext);
  const tagBytes = base64ToBytes(payload.tag);

  // Recombine ciphertext and tag
  const sealed = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  sealed.set(ciphertextBytes, 0);
  sealed.set(tagBytes, ciphertextBytes.length);

  const openedBytes = cipher.open(nonce, sealed);
  if (!openedBytes) {
    throw new Error('Failed to decrypt: Authentication tag mismatch or corrupt payload');
  }

  return decodeUtf8(openedBytes);
}

// ─── Sharing Key Pair (ECDH P-256) ───────────────────────────────────────────

/**
 * 5. Generate an ECDH P-256 key pair for secure vault sharing.
 * The public key is shared with the recipient; the private key stays
 * on the sender's device, stored encrypted in the vault.
 *
 * Usage flow:
 *   Sender  → generates shareKeyPair, gives publicKey to recipient.
 *   Sender  → derives shared secret via ECDH(senderPrivate, recipientPublic).
 *   Sender  → encrypts vault key with shared secret (via encryptPayload).
 *   Sender  → transmits encrypted vault key + nonce to recipient.
 *   Recipient → derives same shared secret via ECDH(recipientPrivate, senderPublic).
 *   Recipient → decrypts vault key → accesses shared items.
 */
export async function generateSharingKeyPair(): Promise<SharingKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,           // extractable so we can export to JWK for storage
    ['deriveKey', 'deriveBits']
  );

  const publicKey  = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  return { publicKey, privateKey };
}

/**
 * 6. Derive a 256-bit shared secret from an ECDH key exchange.
 * Both sides independently compute the same secret without transmitting it.
 *
 * @param myPrivateKeyJwk  - Caller's own private key (JWK)
 * @param theirPublicKeyJwk - Counter-party's public key (JWK)
 * @returns 32-byte shared secret as Uint8Array
 */
export async function deriveSharedSecret(
  myPrivateKeyJwk: JsonWebKey,
  theirPublicKeyJwk: JsonWebKey
): Promise<Uint8Array> {
  const myPrivate = await crypto.subtle.importKey(
    'jwk',
    myPrivateKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

  const theirPublic = await crypto.subtle.importKey(
    'jwk',
    theirPublicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirPublic },
    myPrivate,
    256
  );

  return new Uint8Array(sharedBits);
}
