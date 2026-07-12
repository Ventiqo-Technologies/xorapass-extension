// Validation for internal extension messages received by the background service
// worker. Web pages cannot reach the extension (no `externally_connectable`),
// but other installed extensions and the page-side content-script world can
// attempt to send messages, so every message is validated for origin and shape
// before it is acted upon.
//
// This is the cross-browser (webextension-polyfill) variant: it uses the
// `browser.*` namespace and tolerates both `chrome-extension://` and
// `moz-extension://` internal page origins.

import browser from 'webextension-polyfill';
import type { Runtime } from 'webextension-polyfill';

/** Message types the background worker is willing to handle. */
export const KNOWN_MESSAGE_TYPES = [
  'GET_STATUS',
  'UNLOCK_VAULT',
  'LOCK_VAULT',
  'GET_MATCHING_CREDENTIALS',
  'GET_SITE_SETTINGS',
  'SET_SITE_DISABLED',
] as const;

export type MessageType = (typeof KNOWN_MESSAGE_TYPES)[number];

/**
 * Types that must originate from a privileged extension page (the popup) and
 * never from a content script running inside a web page. These carry or clear
 * decrypted secrets.
 */
const EXTENSION_PAGE_ONLY: ReadonlySet<string> = new Set([
  'UNLOCK_VAULT',
  'LOCK_VAULT',
  'GET_STATUS',
]);

export interface GuardResult {
  ok: boolean;
  /** Present only when ok === false. */
  reason?: string;
  type?: MessageType;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Returns whether a sender is an extension page belonging to THIS extension
 * (e.g. the popup) rather than a content script. Extension pages report an
 * internal `chrome-extension://<id>/...` (or `moz-extension://<uuid>/...` on
 * Firefox) url; a content script's `sender.url` is the web page's http(s) url
 * instead. `browser.runtime.getURL('')` yields our own base url on whichever
 * browser we are running, so we compare against that rather than hard-coding a
 * scheme.
 */
function isFromOwnExtensionPage(sender: Runtime.MessageSender): boolean {
  const ownBase = browser.runtime.getURL(''); // e.g. chrome-extension://<id>/
  const url = sender.url || '';
  return !!ownBase && url.startsWith(ownBase);
}

/**
 * Validates message origin and structure. `sender.id` is checked against our
 * own extension id first: this rejects messages relayed from other extensions.
 */
export function validateMessage(
  message: unknown,
  sender: Runtime.MessageSender
): GuardResult {
  // 1. Origin: only messages from our own extension are ever accepted.
  if (sender.id !== browser.runtime.id) {
    return { ok: false, reason: 'foreign-sender' };
  }

  // 2. Basic shape.
  if (!isPlainObject(message) || typeof message.type !== 'string') {
    return { ok: false, reason: 'malformed' };
  }

  const type = message.type;
  if (!(KNOWN_MESSAGE_TYPES as readonly string[]).includes(type)) {
    return { ok: false, reason: 'unknown-type' };
  }

  // 3. Secret-bearing operations must come from our own extension page.
  if (EXTENSION_PAGE_ONLY.has(type) && !isFromOwnExtensionPage(sender)) {
    return { ok: false, reason: 'privileged-from-content' };
  }

  // 4. Per-type payload validation.
  const payload = isPlainObject(message.payload) ? message.payload : undefined;

  switch (type) {
    case 'UNLOCK_VAULT':
      if (!payload || !Array.isArray(payload.decryptedItems) || typeof payload.email !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'GET_MATCHING_CREDENTIALS':
      if (!payload || typeof payload.hostname !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'GET_SITE_SETTINGS':
      if (!payload || typeof payload.hostname !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'SET_SITE_DISABLED':
      if (!payload || typeof payload.hostname !== 'string' || typeof payload.disabled !== 'boolean') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    // GET_STATUS and LOCK_VAULT need no payload.
  }

  return { ok: true, type: type as MessageType };
}
