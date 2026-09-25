/**
 * fieldFingerprint.ts
 *
 * Provides non-secret structural form memory cached in browser.storage.local.
 * Remembers which field selectors acted as username vs password on dynamic SPAs
 * or multi-step flows so subsequent visits can immediately locate and prioritize them.
 *
 * ZERO-KNOWLEDGE: NEVER stores usernames, passwords, or personal data. Only
 * stores structural CSS selectors and intent types per domain.
 */

import browser from 'webextension-polyfill';
import { querySelectorAllDeep } from './domDeep';

export interface FormFingerprint {
  hostname: string;
  usernameSelector?: string;
  passwordSelector?: string;
  currentPasswordSelector?: string;
  formIntent?: 'login' | 'signup' | 'password_change';
  updatedAt: number;
}

const STORAGE_PREFIX = 'xorapass_fp:';
const FINGERPRINT_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function escapeCss(str: string): string {
  if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') {
    return CSS.escape(str);
  }
  return str.replace(/([!"#$%&'()*+,.\/:;<=>?@[\\\]^`{|}~])/g, '\\$1');
}

/**
 * Derives a clean, reproducible CSS selector for an input element based on
 * non-sensitive structural attributes.
 */
export function computeFieldSelector(
  el: { id?: string; name?: string; getAttribute?(attr: string): string | null } | null | undefined
): string | undefined {
  if (!el || typeof el !== 'object') return undefined;

  // 1. Stable ID (avoid dynamic framework IDs with numbers or hashes like :r1:, dynamic-uuid)
  if (el.id && !/^[:\d]|--\d+|\b[a-f0-9]{8,}\b/i.test(el.id)) {
    try {
      const safeId = escapeCss(el.id);
      return `#${safeId}`;
    } catch {}
  }

  // 2. Name attribute
  if (el.name) {
    try {
      const safeName = escapeCss(el.name);
      return `input[name="${safeName}"]`;
    } catch {}
  }

  // 3. Autocomplete attribute
  const auto = typeof el.getAttribute === 'function' ? el.getAttribute('autocomplete') : null;
  if (auto && auto !== 'off' && auto !== 'on') {
    return `input[autocomplete="${escapeCss(auto)}"]`;
  }

  // 4. Data-testid or data-qa
  const testId = typeof el.getAttribute === 'function' ? (el.getAttribute('data-testid') || el.getAttribute('data-qa')) : null;
  if (testId) {
    return `input[data-testid="${escapeCss(testId)}"], input[data-qa="${escapeCss(testId)}"]`;
  }

  // 5. Placeholder
  const placeholder = typeof el.getAttribute === 'function' ? el.getAttribute('placeholder') : null;
  if (placeholder && placeholder.length < 50) {
    return `input[placeholder="${escapeCss(placeholder)}"]`;
  }

  // 6. Aria-label
  const aria = typeof el.getAttribute === 'function' ? el.getAttribute('aria-label') : null;
  if (aria && aria.length < 50) {
    return `input[aria-label="${escapeCss(aria)}"]`;
  }

  return undefined;
}

/**
 * Saves non-secret structural fingerprint for a given hostname.
 */
export async function saveFormFingerprint(
  hostname: string,
  fp: {
    usernameEl?: any;
    passwordEl?: any;
    currentPasswordEl?: any;
    formIntent?: 'login' | 'signup' | 'password_change';
  }
): Promise<void> {
  if (!hostname) return;

  const userSelector = computeFieldSelector(fp.usernameEl);
  const passSelector = computeFieldSelector(fp.passwordEl);
  const currentPassSelector = computeFieldSelector(fp.currentPasswordEl);

  if (!userSelector && !passSelector && !currentPassSelector) return;

  const key = `${STORAGE_PREFIX}${hostname}`;
  const data: FormFingerprint = {
    hostname,
    usernameSelector: userSelector,
    passwordSelector: passSelector,
    currentPasswordSelector: currentPassSelector,
    formIntent: fp.formIntent,
    updatedAt: Date.now(),
  };

  try {
    await browser.storage.local.set({ [key]: data });
  } catch (err) {
    console.warn('[XoraPass] Failed to save form fingerprint:', err);
  }
}

/**
 * Retrieves cached form fingerprint for a hostname if still valid.
 */
export async function getFormFingerprint(hostname: string): Promise<FormFingerprint | null> {
  if (!hostname) return null;
  const key = `${STORAGE_PREFIX}${hostname}`;

  try {
    const res = await browser.storage.local.get(key);
    const fp = res[key] as FormFingerprint | undefined;
    if (!fp) return null;

    // Check expiration
    if (Date.now() - fp.updatedAt > FINGERPRINT_TTL_MS) {
      void browser.storage.local.remove(key);
      return null;
    }

    return fp;
  } catch {
    return null;
  }
}

/**
 * Queries cached selectors on the active DOM (including through open Shadow DOMs).
 */
export function queryFingerprintedFields(
  root: ParentNode = typeof document !== 'undefined' ? document : (null as any),
  fp: FormFingerprint
): {
  usernameInput?: HTMLInputElement;
  passwordInput?: HTMLInputElement;
  currentPasswordInput?: HTMLInputElement;
} {
  const result: {
    usernameInput?: HTMLInputElement;
    passwordInput?: HTMLInputElement;
    currentPasswordInput?: HTMLInputElement;
  } = {};

  if (!root) return result;

  if (fp.usernameSelector) {
    const users = querySelectorAllDeep<HTMLInputElement>(root, fp.usernameSelector);
    if (users.length > 0) result.usernameInput = users[0];
  }

  if (fp.passwordSelector) {
    const passes = querySelectorAllDeep<HTMLInputElement>(root, fp.passwordSelector);
    if (passes.length > 0) result.passwordInput = passes[0];
  }

  if (fp.currentPasswordSelector) {
    const currentPasses = querySelectorAllDeep<HTMLInputElement>(root, fp.currentPasswordSelector);
    if (currentPasses.length > 0) result.currentPasswordInput = currentPasses[0];
  }

  return result;
}
