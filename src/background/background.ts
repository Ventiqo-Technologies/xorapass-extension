// XoraPass Background Service Worker (Manifest V3)
import browser from 'webextension-polyfill';
import { isDomainMatch, extractHostname, findLookalikeTarget, registrableDomain } from '../utils/siteTrust';
import { validateMessage } from '../utils/messageGuard';
import { encryptPayload, hexToBytes } from '../utils/crypto';
import { API_BASE_URL } from '../utils/config';
import {
  CLIPBOARD_PLACEHOLDER,
  clearDelayInMinutes,
  normalizeClearSeconds,
} from '../utils/clipboardPolicy';
import { coercePolicy, DEFAULT_POLICY, PastePolicy } from '../utils/pasteGuard';
import { base64ToBytes } from '../utils/crypto';

// Logged on every service-worker (cold) start. If the session were cleared by a
// mere page refresh you would NOT see this line on refresh — it only prints when
// the worker itself restarts, which is what actually resets storage.session.
console.debug('[XoraPass] service worker started at', new Date().toISOString());

const DISABLED_SITES_KEY = 'disabledSites';
const AUTO_LOCK_KEY = 'autoLockMinutes';
const AUTO_LOCK_ALARM = 'xorapass-auto-lock';
const DEFAULT_AUTO_LOCK_MINUTES = 15;

// AI Access heartbeat: chrome.alarms cannot fire faster than once a minute in
// MV3, so this is a backstop only -- the primary triggers for noticing a
// newly-approved AI session are the content script asking on page load/focus
// (AI_CHECK_TAB) and tab activation/navigation (see below), both of which are
// much faster in practice.
const AI_HEARTBEAT_ALARM = 'xorapass-ai-heartbeat';
const CLIPBOARD_KEY = 'clipboardClearSeconds';
const CLIPBOARD_ALARM = 'xorapass-clipboard-clear';
const CLIPBOARD_PENDING_KEY = 'clipboardPending';
const OFFSCREEN_TARGET = 'xorapass-offscreen';
const OFFSCREEN_URL = 'offscreen.html';

/** Idle-timeout (minutes) after which the vault auto-locks. 0 = never. */
async function getAutoLockMinutes(): Promise<number> {
  const res = await browser.storage.local.get([AUTO_LOCK_KEY]);
  const v = (res as Record<string, unknown>)[AUTO_LOCK_KEY];
  return typeof v === 'number' && v >= 0 ? v : DEFAULT_AUTO_LOCK_MINUTES;
}

// (Re)arm the idle auto-lock. Called on unlock and on any popup interaction, so
// the countdown restarts each time the user actively uses the extension.
async function scheduleAutoLock() {
  const minutes = await getAutoLockMinutes();
  await browser.alarms.clear(AUTO_LOCK_ALARM);
  if (minutes > 0) {
    browser.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: minutes });
  }
}

async function scheduleAiHeartbeat() {
  await browser.alarms.create(AI_HEARTBEAT_ALARM, { periodInMinutes: 1 });
}
async function clearAiHeartbeat() {
  await browser.alarms.clear(AI_HEARTBEAT_ALARM);
}

async function scheduleAiHeartbeat() {
  await browser.alarms.create(AI_HEARTBEAT_ALARM, { periodInMinutes: 1 });
}
async function clearAiHeartbeat() {
  await browser.alarms.clear(AI_HEARTBEAT_ALARM);
}

// ── Clipboard auto-clear ────────────────────────────────────────────────────
//
// The popup writes the password to the clipboard itself (it has a DOM and a
// user gesture), then tells us a copy happened. The secret never reaches the
// worker for this; we only own the timer, because the popup is torn down the
// moment it loses focus and any timer living inside it dies with it.

/** Delay (seconds) before a copied password is overwritten. 0 = never. */
async function getClipboardClearSeconds(): Promise<number> {
  const res = await browser.storage.local.get([CLIPBOARD_KEY]);
  return normalizeClearSeconds((res as Record<string, unknown>)[CLIPBOARD_KEY]);
}

/**
 * Creates the offscreen document if it is not already up. Returns false when
 * the browser has no offscreen API (Firefox, Safari), which leaves the
 * clipboard untouched rather than throwing.
 */
async function ensureOffscreenDocument(): Promise<boolean> {
  const api = (globalThis as any).chrome;
  if (!api?.offscreen?.createDocument) return false;

  try {
    if (api.runtime?.getContexts) {
      const contexts = await api.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
        documentUrls: [browser.runtime.getURL(OFFSCREEN_URL)],
      });
      if (contexts.length > 0) return true;
    }
    await api.offscreen.createDocument({
      url: OFFSCREEN_URL,
      reasons: ['CLIPBOARD'],
      justification: 'Clear a copied password from the clipboard on a timer.',
    });
    return true;
  } catch (err) {
    // Two concurrent clears can race to create the document; losing that race
    // is fine, the document we wanted exists either way.
    if (String(err).includes('Only a single offscreen')) return true;
    console.warn('[XoraPass] offscreen document unavailable:', err);
    return false;
  }
}

/** Overwrites the clipboard and drops the pending marker. */
async function clearClipboard(): Promise<void> {
  await browser.alarms.clear(CLIPBOARD_ALARM);
  const pending = await browser.storage.session.get([CLIPBOARD_PENDING_KEY]);
  if (!pending[CLIPBOARD_PENDING_KEY]) return;
  await browser.storage.session.remove(CLIPBOARD_PENDING_KEY);

  if (!(await ensureOffscreenDocument())) return;
  try {
    await browser.runtime.sendMessage({
      target: OFFSCREEN_TARGET,
      type: 'CLIPBOARD_WRITE',
      text: CLIPBOARD_PLACEHOLDER,
    });
    console.debug('[XoraPass] clipboard cleared');
  } catch (err) {
    console.warn('[XoraPass] clipboard clear failed:', err);
  } finally {
    const api = (globalThis as any).chrome;
    try {
      await api?.offscreen?.closeDocument?.();
    } catch {
      /* already closed */
    }
  }
}

/** Arms the clear timer after the popup reports a password copy. */
async function scheduleClipboardClear(): Promise<number> {
  const seconds = await getClipboardClearSeconds();
  await browser.alarms.clear(CLIPBOARD_ALARM);
  const delayInMinutes = clearDelayInMinutes(seconds);
  if (delayInMinutes === null) {
    await browser.storage.session.remove(CLIPBOARD_PENDING_KEY);
    return 0;
  }
  await browser.storage.session.set({ [CLIPBOARD_PENDING_KEY]: true });
  browser.alarms.create(CLIPBOARD_ALARM, { delayInMinutes });
  return seconds;
}

browser.alarms.onAlarm.addListener((alarm) => {
  // When the idle timer fires, purge the decrypted vault from session storage.
  if (alarm.name === AUTO_LOCK_ALARM) {
    console.debug('[XoraPass] auto-lock fired -> clearing session');
    // Locking must not leave a password sitting in the clipboard, so clear it
    // first — storage.session.clear() would otherwise drop the pending marker
    // and make the clear a no-op.
    void clearClipboard().finally(() => browser.storage.session.clear());
    return;
  }
  if (alarm.name === CLIPBOARD_ALARM) {
    void clearClipboard();
    void clearAiHeartbeat();
    return;
  }
  if (alarm.name === AI_HEARTBEAT_ALARM) {
    void pushAiFillToActiveTabs();
  }
});

interface VaultItem {
  id: string;
  label: string;
  username: string;
  value: string;
  url?: string;
  category?: string;
  notes?: string;
  organization?: string;
}

// A credential submitted on a page, awaiting the user's decision. Keyed by tab
// so a submit in one tab cannot surface a prompt in another. Held in
// storage.session, so it is memory-only and cleared by lock along with the
// vault itself.
interface PendingSave {
  hostname: string;
  username: string;
  password: string;
  mode: 'new' | 'update';
  entryId?: string;
}

const PENDING_KEY = 'pendingSaves';

// Two-step logins (LastPass, Google, Microsoft) collect the email on one screen
// and the password on the next, so by submit time the username field is gone
// from the DOM. The username seen earlier in the tab is kept here and used as
// the fallback, otherwise those sites all save as "(no username)".
const LAST_USERNAME_KEY = 'lastUsernames';

async function getLastUsernames(): Promise<Record<string, string>> {
  const res = await browser.storage.session.get([LAST_USERNAME_KEY]);
  const v = (res as Record<string, unknown>)[LAST_USERNAME_KEY];
  return (v && typeof v === 'object' ? v : {}) as Record<string, string>;
}

async function setLastUsername(tabId: number, username: string | null) {
  const all = await getLastUsernames();
  if (username) {
    all[String(tabId)] = username;
  } else {
    delete all[String(tabId)];
  }
  await browser.storage.session.set({ [LAST_USERNAME_KEY]: all });
}

async function getPendingSaves(): Promise<Record<string, PendingSave>> {
  const res = await browser.storage.session.get([PENDING_KEY]);
  const v = (res as Record<string, unknown>)[PENDING_KEY];
  return (v && typeof v === 'object' ? v : {}) as Record<string, PendingSave>;
}

async function setPendingSave(tabId: number, pending: PendingSave | null) {
  const all = await getPendingSaves();
  if (pending) {
    all[String(tabId)] = pending;
  } else {
    delete all[String(tabId)];
  }
  await browser.storage.session.set({ [PENDING_KEY]: all });
}

// Drop a tab's pending capture when the tab goes away, so prompts cannot
// resurface against a later page that happens to reuse the id.
browser.tabs.onRemoved.addListener((tabId) => {
  void setPendingSave(tabId, null);
  void setLastUsername(tabId, null);
});

// ── AI Access ────────────────────────────────────────────────────────────────
// The extension is the trusted client surface for the AI-credential-firewall
// story: once a human has approved an AI's request (in the web app, the Tk
// console -- anywhere), XoraPass mints a scoped, time-bound session. This
// worker notices that session and offers to perform the fill -- it is the
// piece described in ai.go's BrokerAction comment ("applied by XoraPass on
// the user's device") that did not exist until now.
//
// This ALWAYS authenticates with the human's own login (the same session the
// popup uses to fetch/decrypt the vault) -- never a bridge token. A bridge
// token is the AI's credential and is deliberately rejected on every one of
// these endpoints; the extension acts only after a human has already decided.

interface AiSession {
  id: string;
  request_id: string;
  status: string;
  granted_scopes: string[];
  ai_tool_name: string;
  vault_entry_id?: string;
  action: string;
  domain: string;
  environment: string;
  expires_at: string;
}

interface AiFillOffer {
  sessionId: string;
  vaultEntryId: string;
  aiToolName: string;
  action: string;
  domain: string;
  environment: string;
  grantedScopes: string[];
  expiresAt: string;
}

// Per-tab set of session ids the user already dismissed/handled, so the same
// offer isn't re-shown on every check. Cleared on navigation to a fresh page.
const dismissedByTab = new Map<number, Set<string>>();
browser.tabs.onRemoved.addListener((tabId) => {
  dismissedByTab.delete(tabId);
});

async function getJwt(): Promise<string> {
  const res = await browser.storage.session.get(['jwt']);
  const jwt = (res as Record<string, unknown>).jwt;
  return typeof jwt === 'string' ? jwt : '';
}

/** Calls core-api authenticated as the logged-in human -- never a bridge token. */
async function apiJwt(
  method: string,
  path: string,
  body?: unknown
): Promise<{ ok: boolean; status: number; data: any }> {
  const jwt = await getJwt();
  if (!jwt) return { ok: false, status: 0, data: { detail: 'locked' } };
  try {
    const res = await fetch(`${API_BASE_URL}/api${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let data: any = {};
    try {
      data = await res.json();
    } catch {
      /* empty body, e.g. some 204s */
    }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    console.warn('[XoraPass] AI Access API call failed:', e);
    return { ok: false, status: 0, data: { detail: 'network error' } };
  }
}

// ── Secret paste guard ──────────────────────────────────────────────────────
// The content script detects secrets on-device and asks here for (a) the
// effective policy, (b) to record a secret-FREE warning event, and (c) to save
// a detected secret into the vault. Detection never leaves the device; only the
// detected type NAMES and the action ever cross to the background/backend.

const PASTE_POLICY_KEY = 'pastePolicy'; // local user override (storage.local)

// Short-lived cache of the backend (org/admin) policy, so we don't fetch on
// every page load. Refreshed lazily.
let orgPolicyCache: { policy: PastePolicy | null; at: number } | null = null;
const ORG_POLICY_TTL_MS = 60_000;

function stricter(a: PastePolicy, b: PastePolicy): PastePolicy {
  const rank = (m: string) => (m === 'block' ? 3 : m === 'warn' ? 2 : 1);
  return {
    mode: rank(b.mode) > rank(a.mode) ? b.mode : a.mode,
    allowDismiss: a.allowDismiss && b.allowDismiss,
    scope: a.scope === 'all_sites' || b.scope === 'all_sites' ? 'all_sites' : 'ai_sites',
    source: b.source === 'admin' ? 'admin' : a.source,
  };
}

// Fetch the admin/org policy from the backend (JWT-authed). Returns null when
// the vault is locked, the call fails, or there's no org policy -- all of which
// fall back to the local/default policy. Snake_case → the policy shape.
async function fetchOrgPolicy(): Promise<PastePolicy | null> {
  const { ok, data } = await apiJwt('GET', '/ai/paste-policy');
  if (!ok || !data?.policy) return null;
  const p = data.policy;
  if (p.source !== 'admin') return null; // a "default" response adds nothing
  return coercePolicy({ mode: p.mode, allowDismiss: p.allow_dismiss, scope: p.scope, source: 'admin' });
}

/**
 * Resolves the effective paste policy: the STRICTER of the user's local choice
 * (or the safe default) and the org/admin policy from the backend. Fails safe --
 * if the backend is unreachable or the vault is locked, the local/default
 * policy still protects the user.
 */
async function getPastePolicy(): Promise<PastePolicy> {
  const res = await browser.storage.local.get([PASTE_POLICY_KEY]);
  const stored = (res as Record<string, unknown>)[PASTE_POLICY_KEY];
  const local = stored ? coercePolicy({ ...(stored as object), source: 'user' }) : DEFAULT_POLICY;

  // Use the cached org policy if fresh; otherwise refresh in the background and
  // combine what we have now (never block on the network for a paste decision).
  const now = Date.now();
  if (!orgPolicyCache || now - orgPolicyCache.at > ORG_POLICY_TTL_MS) {
    orgPolicyCache = { policy: orgPolicyCache?.policy ?? null, at: now };
    fetchOrgPolicy()
      .then((p) => {
        orgPolicyCache = { policy: p, at: Date.now() };
      })
      .catch(() => {});
  }
  return orgPolicyCache.policy ? stricter(local, orgPolicyCache.policy) : local;
}

/**
 * Records a paste-warning event. By contract this NEVER contains a secret
 * value -- only the hostname, the detected type NAMES, and the action taken.
 * Posts to the backend audit trail (when unlocked) and also keeps a small local
 * ring buffer; both are best-effort and never block the paste flow.
 */
async function recordPasteEvent(evt: {
  hostname: string;
  types: string[];
  action: string;
  isAiSite?: boolean;
}) {
  const entry = { ...evt, ts: new Date().toISOString() };

  // Backend audit (secret-free body). Silently no-ops when locked / offline.
  void apiJwt('POST', '/ai/paste-events', {
    hostname: evt.hostname,
    types: evt.types,
    action: evt.action,
    is_ai_site: !!evt.isAiSite,
  });

  try {
    const res = await browser.storage.session.get(['pasteEvents']);
    const log = Array.isArray((res as any).pasteEvents) ? (res as any).pasteEvents : [];
    log.push(entry);
    await browser.storage.session.set({ pasteEvents: log.slice(-50) });
  } catch {
    /* best-effort */
  }
}

/**
 * Encrypts a captured secret client-side and stores it as a new vault entry,
 * so the user can save a value instead of pasting it into an AI. The plaintext
 * is encrypted here with the session encKey and only ciphertext is sent to the
 * server (zero-knowledge, exactly like the popup's normal flow).
 */
async function saveSecretToVault(input: {
  value: string;
  label?: string;
  url?: string;
  username?: string;
}): Promise<{ ok: boolean; error?: string }> {
  const sess = await browser.storage.session.get(['encKey', 'vaultItems']);
  const encKeyB64 = (sess as Record<string, unknown>).encKey as string | undefined;
  if (!encKeyB64) return { ok: false, error: 'Vault is locked — unlock XoraPass first.' };

  let encKey: Uint8Array;
  try {
    encKey = base64ToBytes(encKeyB64);
  } catch {
    return { ok: false, error: 'Could not access the vault key — unlock again.' };
  }

  const label = (input.label || 'Secret captured from paste').slice(0, 120);
  const plaintext = JSON.stringify({
    label,
    username: input.username || '',
    value: input.value,
    notes: 'Captured by the XoraPass paste guard.',
    category: 'other',
    url: input.url || '',
    organization: '',
  });

  let payload;
  try {
    payload = encryptPayload(plaintext, encKey);
  } catch (e) {
    console.warn('[XoraPass] paste-guard encrypt failed:', e);
    return { ok: false, error: 'Encryption failed.' };
  }

  const { ok, status, data } = await apiJwt('POST', '/vault', {
    encrypted_payload: { ciphertext: payload.ciphertext, tag: payload.tag, keyVersion: payload.keyVersion },
    nonce: payload.nonce,
  });
  if (!ok) return { ok: false, error: data?.detail || `HTTP ${status}` };

  // Keep the in-memory session cache consistent so the new item is
  // immediately available for autofill without a full re-fetch.
  try {
    const items = Array.isArray((sess as any).vaultItems) ? (sess as any).vaultItems : [];
    items.push({ id: data?.id, label, username: input.username || '', value: input.value, url: input.url || '', category: 'other' });
    await browser.storage.session.set({ vaultItems: items });
  } catch {
    /* non-fatal */
  }
  return { ok: true };
}

// Tab switches and page loads each independently trigger a check, and both
// can fire together for the same tab (e.g. onActivated + onUpdated). Without
// this, rapid tab-switching would multiply into that many /ai/sessions calls
// in the same instant -- sharing one short-lived result keeps the offer
// discovery path cheap regardless of how many tabs trigger it at once. The
// fill-confirmation check (AI_FILL_CONFIRM) deliberately does NOT use this
// cache -- that one call is the moment-of-truth check right before a secret
// is used, and always reads live state.
let sessionsCache: { data: AiSession[]; fetchedAt: number } | null = null;
const SESSIONS_CACHE_MS = 4000;

async function getActiveAiSessions(): Promise<AiSession[]> {
  const now = Date.now();
  if (sessionsCache && now - sessionsCache.fetchedAt < SESSIONS_CACHE_MS) {
    return sessionsCache.data;
  }
  const { ok, data } = await apiJwt('GET', '/ai/sessions');
  const sessions = ok && Array.isArray(data) ? (data as AiSession[]) : [];
  sessionsCache = { data: sessions, fetchedAt: now };
  return sessions;
}

/**
 * Finds an active AI session, scoped to `autofill`, whose domain matches the
 * given hostname and hasn't already been dismissed in this tab. Returns null
 * when the vault is locked, nothing matches, or the call fails -- all
 * fail-closed (no offer), never fail-open.
 */
async function getAiFillForHostname(hostname: string, tabId: number): Promise<AiFillOffer | null> {
  if (!hostname) return null;
  const data = await getActiveAiSessions();

  const dismissed = dismissedByTab.get(tabId);
  const match = data.find(
    (s) =>
      s.status === 'active' &&
      !!s.domain &&
      isDomainMatch(hostname, s.domain) &&
      s.granted_scopes.includes('autofill') &&
      !(dismissed && dismissed.has(s.id))
  );
  if (!match || !match.vault_entry_id) return null;

  return {
    sessionId: match.id,
    vaultEntryId: match.vault_entry_id,
    aiToolName: match.ai_tool_name || 'An AI tool',
    action: match.action,
    domain: match.domain,
    environment: match.environment,
    grantedScopes: match.granted_scopes,
    expiresAt: match.expires_at,
  };
}

/** Push an offer to a specific tab if one exists. Never throws. */
async function pushAiFillCheck(tabId: number, url?: string) {
  const hostname = url ? extractHostname(url) : '';
  if (!hostname) return;
  const offer = await getAiFillForHostname(hostname, tabId);
  if (offer) {
    browser.tabs.sendMessage(tabId, { type: 'AI_FILL_AVAILABLE', payload: offer }).catch(() => {
      /* content script not present on this page (e.g. chrome:// tab) */
    });
  }
}

/** Backstop: re-checks every window's active tab once a minute. */
async function pushAiFillToActiveTabs() {
  const jwt = await getJwt();
  if (!jwt) return;
  const tabs = await browser.tabs.query({ active: true });
  for (const tab of tabs) {
    if (tab.id !== undefined) void pushAiFillCheck(tab.id, tab.url);
  }
}

// Re-check on tab switch (fast, cheap) and on navigation completing. A fresh
// navigation also clears this tab's dismissed set, so a re-visit can re-offer.
browser.tabs.onActivated.addListener(({ tabId }) => {
  browser.tabs.get(tabId).then((tab) => void pushAiFillCheck(tabId, tab.url)).catch(() => {});
});
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    dismissedByTab.delete(tabId);
  }
  if (changeInfo.status === 'complete') {
    void pushAiFillCheck(tabId, tab.url);
  }
});

/** Normalized set of hostnames on which the user has disabled autofill. */
async function getDisabledSites(): Promise<string[]> {
  const res = await browser.storage.local.get([DISABLED_SITES_KEY]);
  const list = (res as Record<string, unknown>)[DISABLED_SITES_KEY];
  return Array.isArray(list) ? (list as string[]) : [];
}

async function setSiteDisabled(hostname: string, disabled: boolean): Promise<boolean> {
  const host = extractHostname(hostname);
  if (!host) return false;

  const current = new Set(await getDisabledSites());
  if (disabled) {
    current.add(host);
  } else {
    current.delete(host);
  }
  await browser.storage.local.set({ [DISABLED_SITES_KEY]: Array.from(current) });
  return disabled;
}

async function isSiteDisabled(hostname: string): Promise<boolean> {
  const host = extractHostname(hostname);
  if (!host) return false;
  return (await getDisabledSites()).includes(host);
}

// Listen for messages from Content Scripts and the Popup UI.
//
// With webextension-polyfill the listener signals an async response by
// returning a Promise; the resolved value is delivered to the sender.
browser.runtime.onMessage.addListener((message, sender) => {
  // Reject any message that fails origin/shape validation before acting on it.
  const guard = validateMessage(message, sender);
  if (!guard.ok) {
    console.warn('[XoraPass] Rejected message:', guard.reason);
    return Promise.resolve({ error: 'invalid_message' });
  }

  const type = guard.type;
  const msg = message as { type: string; payload?: any };

  if (type === 'GET_STATUS') {
    return browser.storage.session.get(['unlocked', 'email', 'offline']).then((res) => {
      // The popup opening counts as activity: restart the idle auto-lock timer.
      if (res.unlocked) void scheduleAutoLock();
      console.debug('[XoraPass] GET_STATUS -> unlocked =', !!res.unlocked);
      return { unlocked: !!res.unlocked, email: res.email || null, offline: !!res.offline };
    });
  }

  if (type === 'UNLOCK_VAULT') {
    // jwt is optional for backward compatibility, but the popup always sends
    // it now -- without it, the AI Access checks below simply find nothing
    // (getJwt() returns '' and apiJwt() fails closed), never an error state.
    const { decryptedItems, email, jwt, encKey, token, offline } = msg.payload as {
      decryptedItems: unknown;
      email: string;
      jwt?: string;
      encKey?: string; // base64 -- needed only so "save to vault" can encrypt new entries
    };
    // token and encKey are held so the popup can re-fetch and decrypt the vault
    // without a full re-authentication. They live in storage.session, which is
    // memory-only, cleared on browser restart, and already restricted to
    // TRUSTED_CONTEXTS — the same place the decrypted vault itself sits.
    return browser.storage.session
      .set({
        unlocked: true,
        email,
        vaultItems: decryptedItems, jwt: jwt || '', encKey: encKey || '',
        token,
        encKey,
        // An offline unlock came from the cache and has no access token, so
        // writes have to wait for a connection.
        offline: !!offline,
      })
      .then(() => {
        void scheduleAutoLock();
        void scheduleAiHeartbeat();
        console.debug('[XoraPass] UNLOCK_VAULT -> session stored (', (decryptedItems as unknown[]).length, 'items )');
        return { success: true };
      });
  }

  if (type === 'LOCK_VAULT') {
    console.debug('[XoraPass] LOCK_VAULT -> clearing session');
    void browser.alarms.clear(AUTO_LOCK_ALARM);
    void clearAiHeartbeat();
    dismissedByTab.clear();
    // Same ordering as auto-lock: drain the clipboard before the pending
    // marker is wiped along with the rest of the session.
    return clearClipboard()
      .catch(() => undefined)
      .then(() => browser.storage.session.clear())
      .then(() => ({ success: true }));
  }

  if (type === 'GET_SETTINGS') {
    return Promise.all([getAutoLockMinutes(), getClipboardClearSeconds()]).then(
      ([autoLockMinutes, clipboardClearSeconds]) => ({ autoLockMinutes, clipboardClearSeconds })
    );
  }

  if (type === 'SET_CLIPBOARD_CLEAR') {
    const seconds = normalizeClearSeconds(msg.payload.seconds);
    return browser.storage.local
      .set({ [CLIPBOARD_KEY]: seconds })
      .then(() => ({ success: true, clipboardClearSeconds: seconds }));
  }

  if (type === 'CLIPBOARD_COPIED') {
    // No secret in the payload — this is only the signal to start the timer.
    return scheduleClipboardClear().then((clipboardClearSeconds) => ({
      success: true,
      clipboardClearSeconds,
    }));
  }

  if (type === 'SET_AUTO_LOCK') {
    const minutes = Math.max(0, Math.floor(msg.payload.minutes));
    return browser.storage.local
      .set({ [AUTO_LOCK_KEY]: minutes })
      .then(() => scheduleAutoLock())
      .then(() => ({ success: true, autoLockMinutes: minutes }));
  }

  if (type === 'GET_SITE_SETTINGS') {
    return isSiteDisabled(msg.payload.hostname).then((disabled) => ({ disabled }));
  }

  if (type === 'SET_SITE_DISABLED') {
    return setSiteDisabled(msg.payload.hostname, msg.payload.disabled).then((disabled) => ({
      success: true,
      disabled,
    }));
  }

  if (type === 'GET_MATCHING_CREDENTIALS') {
    const hostname: string = msg.payload.hostname || '';
    if (!hostname) {
      return Promise.resolve({ credentials: [], disabled: false, lookalike: null });
    }

    return Promise.all([
      browser.storage.session.get(['unlocked', 'vaultItems']),
      isSiteDisabled(hostname),
    ]).then(([res, disabled]) => {
      if (!res.unlocked || !res.vaultItems) {
        return { credentials: [], disabled, lookalike: null };
      }

      // If the user disabled autofill for this site, offer nothing.
      if (disabled) {
        return { credentials: [], disabled: true, lookalike: null };
      }

      const items = res.vaultItems as VaultItem[];

      // Safe, exact/subdomain/registrable-domain matching (no substring hacks).
      const matching = items.filter((item) => !!item.url && isDomainMatch(hostname, item.url!));

      // Warn if the current page looks like a deceptive variant of a site the
      // user actually has credentials for, but did not itself match.
      const knownHosts = items
        .filter((i) => !!i.url)
        .map((i) => extractHostname(i.url!))
        .filter(Boolean);
      const lookalike = matching.length === 0 ? findLookalikeTarget(hostname, knownHosts) : null;

      return {
        // NOTE: `value` (the secret) is deliberately NOT included here. The
        // content script only ever learns which items exist for this site; the
        // password is released one at a time by GET_CREDENTIAL_SECRET, after a
        // fresh domain re-check, when the user actually picks an entry.
        credentials: matching.map((item) => ({
          id: item.id,
          label: item.label,
          username: item.username,
          category: item.category || 'login',
        })),
        disabled: false,
        lookalike,
      };
    });
  }

  if (type === 'GET_CREDENTIAL_SECRET') {
    const id: string = msg.payload.id;

    // The hostname is taken from the sender tab, never from the message
    // payload: a compromised content script must not be able to name a
    // different site and pull that site's password.
    const senderUrl = sender.tab?.url || sender.url || '';
    const hostname = extractHostname(senderUrl);
    if (!hostname) {
      return Promise.resolve({ error: 'unknown_origin' });
    }

    return Promise.all([
      browser.storage.session.get(['unlocked', 'vaultItems']),
      isSiteDisabled(hostname),
    ]).then(([res, disabled]) => {
      if (!res.unlocked || !res.vaultItems) return { error: 'locked' };
      if (disabled) return { error: 'site_disabled' };

      const item = (res.vaultItems as VaultItem[]).find((i) => i.id === id);
      if (!item || !item.url) return { error: 'not_found' };

      // Re-authorize: the item must still match the tab's real hostname.
      if (!isDomainMatch(hostname, item.url)) {
        console.warn('[XoraPass] Refused secret for non-matching domain:', hostname);
        return { error: 'domain_mismatch' };
      }

      void scheduleAutoLock(); // filling counts as activity
      return { username: item.username, value: item.value };
    });
  }

  if (type === 'REMEMBER_USERNAME') {
    const tabId = sender.tab?.id;
    if (!tabId) return Promise.resolve({ success: false });
    return setLastUsername(tabId, msg.payload.username).then(() => ({ success: true }));
  }

  if (type === 'CAPTURE_CREDENTIAL') {
    const tabId = sender.tab?.id;
    const hostname = extractHostname(sender.tab?.url || sender.url || '');
    if (!tabId || !hostname) return Promise.resolve({ prompt: false });

    const captured = msg.payload as { username: string; password: string };
    const password = captured.password;

    return Promise.all([
      browser.storage.session.get(['unlocked', 'vaultItems']),
      isSiteDisabled(hostname),
      captured.username ? Promise.resolve(captured.username) : getLastUsernames().then((m) => m[String(tabId)] || ''),
    ]).then(async ([res, disabled, username]) => {
      // Nothing to offer while locked — encryption needs the session key — and
      // a site the user muted should stay silent here too.
      if (!res.unlocked || disabled) return { prompt: false };

      const items = (res.vaultItems as VaultItem[]) || [];
      const sameSite = items.filter((i) => !!i.url && isDomainMatch(hostname, i.url!));
      const existing = sameSite.find((i) => i.username === username);

      // Already stored with this exact password: nothing worth asking about.
      if (existing && existing.value === password) return { prompt: false };

      const pending: PendingSave = existing
        ? { hostname, username, password, mode: 'update', entryId: existing.id }
        : { hostname, username, password, mode: 'new' };

      await setPendingSave(tabId, pending);
      return { prompt: true, mode: pending.mode };
    });
  }

  if (type === 'GET_PENDING_SAVE') {
    const tabId = sender.tab?.id;
    const hostname = extractHostname(sender.tab?.url || sender.url || '');
    if (!tabId || !hostname) return Promise.resolve({ pending: null });

    return getPendingSaves().then((all) => {
      const pending = all[String(tabId)];
      // The capture must belong to the page currently asking. After a login
      // redirect the host is usually the same; if it is not, the prompt would
      // be about a different site.
      if (!pending || !isDomainMatch(hostname, pending.hostname)) return { pending: null };
      return {
        pending: { username: pending.username, mode: pending.mode, hostname: pending.hostname },
      };
    });
  }

  if (type === 'DISMISS_PENDING_SAVE') {
    const tabId = sender.tab?.id;
    if (!tabId) return Promise.resolve({ success: true });
    return setPendingSave(tabId, null).then(() => ({ success: true }));
  }

  if (type === 'SAVE_CREDENTIAL') {
    const tabId = sender.tab?.id;
    if (!tabId) return Promise.resolve({ error: 'no_tab' });
    return savePendingCredential(tabId);
  }

  // ── AI Access messages ──────────────────────────────────────────────────

  if (type === 'AI_CHECK_TAB') {
    const hostname: string = msg.payload.hostname;
    const tabId = sender.tab?.id;
    if (tabId === undefined) return Promise.resolve({ offer: null });
    return getAiFillForHostname(hostname, tabId).then((offer) => ({ offer }));
  }

  if (type === 'AI_FILL_CONFIRM') {
    // Re-verify against the LIVE server state at the moment of the click --
    // the banner may have been sitting open for a while, and the session
    // could have expired or been revoked (from the popup, the web app,
    // anywhere) since it was rendered. The vault entry to fill is also taken
    // from the server's own session record, never trusted from the caller --
    // a session only ever unlocks the one credential it was actually
    // approved for.
    const { sessionId } = msg.payload as { sessionId: string };
    return apiJwt('GET', '/ai/sessions').then(({ ok, data }) => {
      if (!ok || !Array.isArray(data)) {
        return { error: 'Could not verify this AI session -- try again.' };
      }
      const session = (data as AiSession[]).find((s) => s.id === sessionId);
      if (!session || session.status !== 'active' || !session.granted_scopes.includes('autofill') || !session.vault_entry_id) {
        return { error: 'This AI session is no longer active.' };
      }
      return browser.storage.session.get(['vaultItems']).then((res) => {
        const items = (res as Record<string, unknown>).vaultItems as VaultItem[] | undefined;
        const item = items?.find((i) => i.id === session.vault_entry_id);
        if (!item) return { error: 'Credential not found in this session -- try unlocking again.' };
        return { username: item.username, value: item.value };
      });
    });
  }

  if (type === 'AI_FILL_HANDLED') {
    const { sessionId } = msg.payload;
    const tabId = sender.tab?.id;
    if (tabId !== undefined) {
      const set = dismissedByTab.get(tabId) || new Set<string>();
      set.add(sessionId);
      dismissedByTab.set(tabId, set);
    }
    return Promise.resolve({ success: true });
  }

  if (type === 'AI_REVOKE_SESSION') {
    const { sessionId } = msg.payload;
    return apiJwt('POST', `/ai/sessions/${sessionId}/revoke`).then(({ ok, status, data }) => {
      if (ok) {
        for (const set of dismissedByTab.values()) set.add(sessionId);
        sessionsCache = null; // don't let a cached pre-revoke list re-offer it within the TTL
      }
      return ok ? { success: true } : { error: data?.detail || `HTTP ${status}` };
    });
  }

  if (type === 'AI_LIST_REQUESTS') {
    return apiJwt('GET', '/ai/access-requests').then(({ ok, data }) =>
      ok ? { requests: data } : { error: data?.detail || 'Failed to load requests', requests: [] }
    );
  }

  if (type === 'AI_LIST_SESSIONS') {
    return apiJwt('GET', '/ai/sessions').then(({ ok, data }) =>
      ok ? { sessions: data } : { error: data?.detail || 'Failed to load sessions', sessions: [] }
    );
  }

  if (type === 'AI_DECIDE_REQUEST') {
    const { requestId, decision, grantedScopes, durationSeconds, maxUses } = msg.payload as {
      requestId: string;
      decision: 'approve' | 'deny';
      grantedScopes?: string[];
      durationSeconds?: number;
      maxUses?: number;
    };
    const path = `/ai/access-requests/${requestId}/${decision}`;
    const body =
      decision === 'approve'
        ? {
            ...(grantedScopes && grantedScopes.length ? { granted_scopes: grantedScopes } : {}),
            ...(durationSeconds ? { duration_seconds: durationSeconds } : {}),
            ...(maxUses ? { max_uses: maxUses } : {}),
          }
        : undefined;
    return apiJwt('POST', path, body).then(({ ok, status, data }) =>
      ok ? { success: true, data } : { error: data?.detail || `HTTP ${status}` }
    );
  }

  // ── Secret paste guard messages ─────────────────────────────────────────

  if (type === 'AI_PASTE_POLICY') {
    return getPastePolicy().then((policy) => ({ policy }));
  }

  if (type === 'AI_PASTE_EVENT') {
    const { hostname, types, action, isAiSite } = msg.payload as {
      hostname: string;
      types: string[];
      action: string;
      isAiSite?: boolean;
    };
    // Defensive: only ever forward the type NAMES, never any value the caller
    // might have mistakenly attached.
    void recordPasteEvent({
      hostname,
      types: types.map(String).slice(0, 20),
      action,
      isAiSite: !!isAiSite,
    });
    return Promise.resolve({ success: true });
  }

  if (type === 'AI_SAVE_SECRET') {
    const { value, label, url, username } = msg.payload as {
      value: string;
      label?: string;
      url?: string;
      username?: string;
    };
    return saveSecretToVault({ value, label, url, username }).then((r) =>
      r.ok ? { success: true } : { error: r.error }
    );
  }

  // Should be unreachable because validateMessage allowlists types.
  return undefined;
});

// Encrypts the pending credential with the session key and writes it to the
// API. Runs in the worker because the encryption key lives in
// TRUSTED_CONTEXTS session storage, which content scripts cannot read.
async function savePendingCredential(
  tabId: number
): Promise<{ success?: boolean; error?: string; detail?: string | null }> {
  const all = await getPendingSaves();
  const pending = all[String(tabId)];
  if (!pending) return { error: 'nothing_pending' };

  const session = await browser.storage.session.get([
    'unlocked',
    'token',
    'encKey',
    'vaultItems',
    'offline',
  ]);
  if (!session.unlocked || !session.encKey) return { error: 'locked' };
  // Unlocked from the cache: readable and fillable, but there is no session to
  // write through. Saying "locked" here would send the user to re-unlock a
  // vault that is already open.
  if (!session.token || session.offline) return { error: 'offline' };

  const encKey = hexToBytes(session.encKey as string);
  const items = (session.vaultItems as VaultItem[]) || [];
  const existing = pending.entryId ? items.find((i) => i.id === pending.entryId) : undefined;

  const entry = {
    label: existing?.label || registrableDomain(pending.hostname) || pending.hostname,
    username: pending.username,
    value: pending.password,
    notes: existing?.notes || '',
    category: existing?.category || 'login',
    organization: existing?.organization || '',
    url: existing?.url || `https://${pending.hostname}`,
  };

  // encryptPayload bundles the nonce, but the API stores it in its own column.
  const { nonce, ...encrypted_payload } = encryptPayload(JSON.stringify(entry), encKey);

  const isUpdate = pending.mode === 'update' && !!pending.entryId;
  const url = isUpdate ? `${API_BASE_URL}/api/vault/${pending.entryId}` : `${API_BASE_URL}/api/vault`;

  try {
    const res = await fetch(url, {
      method: isUpdate ? 'PUT' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.token}`,
      },
      body: JSON.stringify({ encrypted_payload, nonce }),
    });

    if (res.status === 401 || res.status === 403) {
      await setPendingSave(tabId, null);
      return { error: 'session_expired' };
    }
    if (!res.ok) {
      // The API rejects creates that exceed the plan's vault limit with a
      // useful message; pass it through rather than saying "couldn't save".
      const detail = await res
        .json()
        .then((b: any) => (typeof b?.detail === 'string' ? b.detail : null))
        .catch(() => null);
      return { error: `http_${res.status}`, detail };
    }

    const saved = await res.json().catch(() => null);

    // Fold the entry into the cached vault so it autofills straight away,
    // instead of waiting for the next sync.
    const id = isUpdate ? pending.entryId! : saved?.id;
    const next = isUpdate
      ? items.map((i) => (i.id === id ? { ...i, ...entry } : i))
      : id
        ? [...items, { id, ...entry }]
        : items;

    await browser.storage.session.set({ vaultItems: next });
    await setPendingSave(tabId, null);
    void scheduleAutoLock();
    return { success: true };
  } catch (err) {
    console.warn('[XoraPass] Save failed:', err);
    return { error: 'network' };
  }
}

// Configure session storage access level (trusted context restriction) so
// content scripts cannot read decrypted secrets directly; only the
// background/popup (trusted contexts) can.
// NOTE: setAccessLevel is not supported by Firefox or Safari, so we must guard it.
if (browser.storage && browser.storage.session && (browser.storage.session as any).setAccessLevel) {
  (browser.storage.session as any).setAccessLevel({
    accessLevel: 'TRUSTED_CONTEXTS'
  }).catch((err: any) => {
    console.warn("Unable to restrict storage session access level:", err);
  });
}
