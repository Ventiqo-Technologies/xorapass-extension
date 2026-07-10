import { argon2id } from 'hash-wasm';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import { encode as encodeUtf8, decode as decodeUtf8 } from '@stablelib/utf8';

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
  const binaryString = window.atob(base64);
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
  return window.btoa(binary);
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
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    masterKey as any,
    'HKDF',
    false,
    ['deriveBits']
  );
  
  // 2.1 Derive K_enc (Info = "enc_key")
  const encKeyBits = await window.crypto.subtle.deriveBits(
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
  const authHashBits = await window.crypto.subtle.deriveBits(
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
 * Returns {"ciphertext": "base64", "tag": "base64"} and "nonce"
 */
export function encryptPayload(plaintext: string, encKey: Uint8Array): { encryptedPayload: { ciphertext: string, tag: string }, nonce: string } {
  const cipher = new XChaCha20Poly1305(encKey);
  const nonce = window.crypto.getRandomValues(new Uint8Array(24));
  const plaintextBytes = encodeUtf8(plaintext);
  
  // Seal returns ciphertext with the 16-byte Poly1305 tag appended at the end
  const sealed = cipher.seal(nonce, plaintextBytes);
  
  const tagLength = 16;
  const ciphertextBytes = sealed.slice(0, sealed.length - tagLength);
  const tagBytes = sealed.slice(sealed.length - tagLength);
  
  return {
    encryptedPayload: {
      ciphertext: bytesToBase64(ciphertextBytes),
      tag: bytesToBase64(tagBytes)
    },
    nonce: bytesToBase64(nonce)
  };
}

/**
 * 4. XChaCha20-Poly1305 Decryption
 */
export function decryptPayload(encryptedPayload: { ciphertext: string, tag: string }, nonceStr: string, encKey: Uint8Array): string {
  const cipher = new XChaCha20Poly1305(encKey);
  const nonce = base64ToBytes(nonceStr);
  const ciphertextBytes = base64ToBytes(encryptedPayload.ciphertext);
  const tagBytes = base64ToBytes(encryptedPayload.tag);
  
  // Recombine ciphertext and tag
  const sealed = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  sealed.set(ciphertextBytes, 0);
  sealed.set(tagBytes, ciphertextBytes.length);
  
  const openedBytes = cipher.open(nonce, sealed);
  if (!openedBytes) {
    throw new Error("Failed to decrypt: Authentication tag mismatch or corrupt payload");
  }
  
  return decodeUtf8(openedBytes);
}
