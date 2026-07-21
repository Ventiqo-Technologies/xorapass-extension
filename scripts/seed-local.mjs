// Seeds a local test account with autofill-ready vault entries.
//
// Local development only. It reproduces the popup's client-side crypto exactly
// (Argon2id -> HKDF split -> XChaCha20-Poly1305) so the entries it writes are
// decryptable by the extension, and it flips email_verified directly in
// Postgres because local dev has no working SMTP.
//
//   node scripts/seed-local.mjs
//
// Re-runnable: an existing account is reused (its master_salt is re-fetched via
// /auth/discover rather than regenerated, which would make the vault
// undecryptable).

import { argon2id } from 'hash-wasm';
import { XChaCha20Poly1305 } from '@stablelib/xchacha20poly1305';
import { encode as encodeUtf8 } from '@stablelib/utf8';
import { execFileSync } from 'node:child_process';

const API = process.env.API_BASE_URL || 'http://localhost:8000';
const EMAIL = process.env.SEED_EMAIL || 'test@local.dev';
const PASSWORD = process.env.SEED_PASSWORD || 'correct-horse-battery-staple';
const DB_CONTAINER = process.env.DB_CONTAINER || 'cloudpass-db';
const KEY_VERSION = 1;

// Entries deliberately span the cases the content script has to distinguish:
// a plain login, a subdomain, an entry with no URL (must never be offered),
// and a sensitive category (must trigger the confirm dialog).
const ENTRIES = [
  { label: 'GitHub', username: 'testuser@local.dev', value: 'gh-pw-9f3k2Lm!', url: 'https://github.com', category: 'login' },
  { label: 'GitLab', username: 'testuser', value: 'gl-pw-77xQ!vb2', url: 'https://gitlab.com', category: 'login' },
  { label: 'Example', username: 'demo@local.dev', value: 'ex-pw-Zq18!tt', url: 'https://example.com', category: 'login' },
  { label: 'Local test page', username: 'localuser', value: 'local-pw-4Kd!92', url: 'http://localhost:4173', category: 'login' },
  { label: 'Reused password A', username: 'a@local.dev', value: 'short', url: 'https://a.example.com', category: 'login' },
  { label: 'Reused password B', username: 'b@local.dev', value: 'short', url: 'https://b.example.com', category: 'login' },
  { label: 'Test Card', username: '4111111111111111', value: '123', url: 'https://example.com', category: 'card' },
  { label: 'No URL entry', username: 'nobody', value: 'never-offered', url: '', category: 'login' },
];

const hexToBytes = (hex) => Uint8Array.from(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
const bytesToBase64 = (b) => Buffer.from(b).toString('base64');

// Mirrors deriveMasterKey() in src/utils/crypto.ts — parameters must match
// exactly or the resulting vault is undecryptable by the extension.
async function deriveMasterKey(password, saltHex) {
  const hashHex = await argon2id({
    password,
    salt: hexToBytes(saltHex),
    iterations: 3,
    memorySize: 65536,
    parallelism: 4,
    hashLength: 32,
    outputType: 'hex',
  });
  return hexToBytes(hashHex);
}

// Mirrors splitMasterKey(): HKDF-SHA256 with empty salt, info "enc_key" / "auth_hash".
async function splitMasterKey(masterKey) {
  const baseKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const derive = (info) =>
    crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encodeUtf8(info) },
      baseKey,
      256
    );
  const encKey = new Uint8Array(await derive('enc_key'));
  const clientAuthHash = bytesToHex(new Uint8Array(await derive('auth_hash')));
  return { encKey, clientAuthHash };
}

// Mirrors encryptPayload(), but returns the nonce separately: the API stores
// `nonce` in its own column alongside `encrypted_payload`.
function encryptEntry(plaintext, encKey) {
  const cipher = new XChaCha20Poly1305(encKey);
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const sealed = cipher.seal(nonce, encodeUtf8(plaintext));
  const ciphertext = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  return {
    encrypted_payload: {
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag),
      keyVersion: KEY_VERSION,
    },
    nonce: bytesToBase64(nonce),
  };
}

async function api(path, body, token) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

async function main() {
  console.log(`→ API: ${API}`);
  console.log(`→ Account: ${EMAIL}`);

  // 1. Discover decides whether we are creating or reusing. Reusing MUST keep
  //    the stored master_salt, otherwise the derived key changes and every
  //    existing entry becomes undecryptable.
  const discover = await api('/api/auth/discover', { email: EMAIL });
  if (discover.status !== 200) {
    throw new Error(`discover failed (${discover.status}): ${JSON.stringify(discover.json)}`);
  }
  const exists = discover.json.exists === true;
  const masterSalt = exists ? discover.json.master_salt : bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  console.log(exists ? '✓ Account exists — reusing its master_salt' : '→ Creating new account');

  // 2. Derive the same keys the popup would.
  console.log('→ Deriving key (Argon2id, 64 MB — takes a moment)…');
  const masterKey = await deriveMasterKey(PASSWORD, masterSalt);
  const { encKey, clientAuthHash } = await splitMasterKey(masterKey);

  // 3. Register if needed.
  if (!exists) {
    const reg = await api('/api/auth/register', {
      email: EMAIL,
      first_name: 'Test',
      last_name: 'User',
      password_hash_server: clientAuthHash,
      master_salt: masterSalt,
    });
    if (reg.status !== 200 && reg.status !== 201) {
      throw new Error(`register failed (${reg.status}): ${JSON.stringify(reg.json)}`);
    }
    console.log('✓ Registered');
  }

  // 4. No SMTP locally, so mark the address verified directly.
  execFileSync('docker', [
    'exec', DB_CONTAINER, 'psql', '-U', 'cloudpass', '-d', 'cloudpass',
    '-c', `update users set email_verified = true where email = '${EMAIL}';`,
  ], { stdio: 'pipe' });
  console.log('✓ Email marked verified');

  // 5. Log in for a vault token.
  const login = await api('/api/auth/login', { email: EMAIL, client_auth_hash: clientAuthHash });
  if (login.status !== 200) {
    throw new Error(`login failed (${login.status}): ${JSON.stringify(login.json)}`);
  }
  if (login.json.mfa_required) {
    throw new Error('account has MFA enabled — disable it or use a fresh SEED_EMAIL');
  }
  const token = login.json.access_token;
  console.log(`✓ Logged in (device_approved=${login.json.device_approved})`);

  // 6. Encrypt and upload entries.
  let created = 0;
  for (const entry of ENTRIES) {
    const body = encryptEntry(JSON.stringify({ ...entry, notes: '' }), encKey);
    const res = await api('/api/vault', body, token);
    if (res.status === 200 || res.status === 201) {
      created++;
    } else {
      console.warn(`  ✗ ${entry.label}: ${res.status} ${JSON.stringify(res.json)}`);
    }
  }

  console.log(`✓ Created ${created}/${ENTRIES.length} vault entries`);
  console.log(`\nSign in to the extension with:\n  ${EMAIL}\n  ${PASSWORD}`);
}

main().catch((err) => {
  console.error('\n✗ Seed failed:', err.message);
  process.exit(1);
});
