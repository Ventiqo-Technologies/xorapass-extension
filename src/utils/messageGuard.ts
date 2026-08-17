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
  'GET_CREDENTIAL_SECRET',
  'REMEMBER_USERNAME',
  'CAPTURE_CREDENTIAL',
  'GET_PENDING_SAVE',
  'SAVE_CREDENTIAL',
  'DISMISS_PENDING_SAVE',
  'GET_SITE_SETTINGS',
  'SET_SITE_DISABLED',
  'GET_SETTINGS',
  'SET_AUTO_LOCK',
  'SET_LOCK_ON_SCREEN_LOCK',
  'SET_CLIPBOARD_CLEAR',
  'CLIPBOARD_COPIED',
  // AI Access: the extension is a consumer of XoraPass's AI-access API, using
  // the human's own login (never a bridge token -- this is the trusted client
  // surface that performs the actual fill once a human has approved a scoped,
  // JIT session). See BrokerAction / AIAccessSession in core-api/modules/ai.
  'AI_CHECK_TAB',
  'AI_FILL_CONFIRM',
  'AI_FILL_HANDLED',
  'AI_LIST_REQUESTS',
  'AI_DECIDE_REQUEST',
  'AI_LIST_SESSIONS',
  'AI_REVOKE_SESSION',
  // Secret paste guard: fetch the effective policy, report a secret-FREE
  // warning event for auditing, and save a detected secret into the vault.
  'AI_PASTE_POLICY',
  'AI_PASTE_EVENT',
  'AI_SAVE_SECRET',
  'WEB_BRIDGE_LOGIN',
  // Companion-device linking: a same-browser web login can hand this
  // extension a fresh session without a separate master-password unlock.
  // DEVICE_INFO only ever answers with a public key (never anything
  // secret); DELIVER_KEY carries the vault key pre-encrypted to that public
  // key, decryptable only by the private half this extension alone holds.
  'WEB_BRIDGE_DEVICE_INFO',
  'WEB_BRIDGE_DELIVER_KEY',
  // The pull direction: a logged-out web app asking this already-unlocked
  // extension for its current session. Answers with nothing unless the
  // extension is genuinely unlocked; there is no separate approval step here
  // because the real consent already happened when a human unlocked it.
  'WEB_BRIDGE_REQUEST_SESSION',
  'GET_COPIED_SECRET',
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
  'GET_SETTINGS',
  'SET_AUTO_LOCK',
  // Turning the screen-lock guard OFF weakens the vault, so it belongs to the
  // popup alone. A content script that could send this would be able to
  // silently disable the control that protects an unattended machine.
  'SET_LOCK_ON_SCREEN_LOCK',
  // Account-wide AI actions (every pending request / every session) --
  // reserved for the popup, same tier as the vault-lifecycle messages above.
  // The page-scoped ones (AI_CHECK_TAB, AI_FILL_CONFIRM, AI_FILL_HANDLED,
  // AI_REVOKE_SESSION) stay content-script-reachable, same trust tier as
  // GET_MATCHING_CREDENTIALS: our own injected UI is the only thing that ever
  // triggers them, exactly like the existing autofill button.
  'AI_LIST_REQUESTS',
  'AI_DECIDE_REQUEST',
  'AI_LIST_SESSIONS',
  'SET_CLIPBOARD_CLEAR',
  // A page has no business arming (or re-arming, and so postponing) the
  // clipboard clear; only the popup copies passwords.
  'CLIPBOARD_COPIED',
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
  // 1. Origin check:
  // For standard extension pages & content scripts, sender.id === runtime.id.
  // For other installed extensions, sender.id !== runtime.id and is defined.
  // For externally_connectable web pages, sender.id is undefined but sender.origin/url is set.
  const ownId = browser.runtime.id;
  const isFromOtherExtension = sender.id && sender.id !== ownId;
  const isExternalWebPage = !sender.id;

  if (isFromOtherExtension) {
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

  // Reject external web calls requesting internal/privileged extension-only actions.
  // The bridge types are the ONLY things an externally_connectable web page
  // (app.xorapass.com et al) may ever ask this extension to do.
  const EXTERNAL_WEB_ALLOWED: ReadonlySet<string> = new Set([
    'WEB_BRIDGE_LOGIN',
    'WEB_BRIDGE_DEVICE_INFO',
    'WEB_BRIDGE_DELIVER_KEY',
    'WEB_BRIDGE_REQUEST_SESSION',
  ]);
  if (isExternalWebPage && !EXTERNAL_WEB_ALLOWED.has(type)) {
    return { ok: false, reason: 'unauthorized-external-type' };
  }

  // 3. Secret-bearing operations must come from our own extension page.
  if (EXTENSION_PAGE_ONLY.has(type) && !isFromOwnExtensionPage(sender)) {
    return { ok: false, reason: 'privileged-from-content' };
  }

  // 4. Per-type payload validation.
  const payload = isPlainObject(message.payload) ? message.payload : undefined;

  switch (type) {
    case 'WEB_BRIDGE_LOGIN':
      if (!payload || typeof payload.token !== 'string' || typeof payload.encKey !== 'string' || typeof payload.email !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'WEB_BRIDGE_DEVICE_INFO':
      // No payload: this only ever asks "who are you", never carries data in.
      break;
    case 'WEB_BRIDGE_DELIVER_KEY': {
      // token/email/the vault key all travel INSIDE `sealed` (the
      // EncryptedPayload shape from utils/crypto -- ciphertext/tag/nonce,
      // all base64 strings) -- this guard can only check the envelope's
      // shape, not its contents; those are checked after decryption.
      const sealed = payload && isPlainObject(payload.sealed) ? payload.sealed : undefined;
      if (
        !payload ||
        !isPlainObject(payload.ephemeralPublicKey) ||
        !sealed ||
        typeof sealed.ciphertext !== 'string' ||
        typeof sealed.tag !== 'string' ||
        typeof sealed.nonce !== 'string'
      ) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    }
    case 'WEB_BRIDGE_REQUEST_SESSION':
      // Only an ephemeral public key goes in -- nothing to decrypt here,
      // since the caller has nothing encrypted to send yet at this point.
      if (!payload || !isPlainObject(payload.ephemeralPublicKey)) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'UNLOCK_VAULT':
      if (!payload || !Array.isArray(payload.decryptedItems) || typeof payload.email !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      // token and encKey back the refresh path: re-fetching the vault needs a
      // bearer token, and decrypting anything new needs the key.
      if (typeof payload.token !== 'string' || typeof payload.encKey !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'GET_MATCHING_CREDENTIALS':
      if (!payload || typeof payload.hostname !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'REMEMBER_USERNAME':
      if (!payload || typeof payload.username !== 'string' || !payload.username) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'CAPTURE_CREDENTIAL':
      // The submitted credential. The hostname is not taken from here — the
      // background derives it from the sender tab.
      if (
        !payload ||
        typeof payload.username !== 'string' ||
        typeof payload.password !== 'string' ||
        !payload.password
      ) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'GET_CREDENTIAL_SECRET':
      // Only the item id is trusted from the caller; the background re-derives
      // the requesting hostname from the sender tab rather than the payload.
      if (!payload || typeof payload.id !== 'string' || !payload.id) {
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
    case 'SET_AUTO_LOCK':
      if (!payload || typeof payload.minutes !== 'number' || !Number.isFinite(payload.minutes)) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'SET_CLIPBOARD_CLEAR':
      if (!payload || typeof payload.seconds !== 'number' || !Number.isFinite(payload.seconds)) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'SET_LOCK_ON_SCREEN_LOCK':
      if (!payload || typeof payload.enabled !== 'boolean') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    // GET_STATUS, LOCK_VAULT, GET_SETTINGS and CLIPBOARD_COPIED need no
    // payload — CLIPBOARD_COPIED deliberately carries no secret, it is only a
    // signal that the popup put a password on the clipboard.
    case 'AI_CHECK_TAB':
      if (!payload || typeof payload.hostname !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'AI_FILL_CONFIRM':
      if (!payload || typeof payload.sessionId !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'AI_FILL_HANDLED':
    case 'AI_REVOKE_SESSION':
      if (!payload || typeof payload.sessionId !== 'string') {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'AI_DECIDE_REQUEST':
      if (
        !payload ||
        typeof payload.requestId !== 'string' ||
        (payload.decision !== 'approve' && payload.decision !== 'deny')
      ) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'AI_PASTE_EVENT':
      // Secret-free by contract: hostname, detected type NAMES, the action, and optional vaultEntryId.
      if (
        !payload ||
        typeof payload.hostname !== 'string' ||
        !Array.isArray(payload.types) ||
        typeof payload.action !== 'string' ||
        (payload.vaultEntryId !== undefined && typeof payload.vaultEntryId !== 'string')
      ) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
    case 'AI_SAVE_SECRET':
      if (!payload || typeof payload.value !== 'string' || payload.value.length === 0) {
        return { ok: false, reason: 'bad-payload' };
      }
      break;
  }

  return { ok: true, type: type as MessageType };
}
