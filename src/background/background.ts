// XoraPass Background Service Worker (Manifest V3)
import browser from 'webextension-polyfill';
import { isDomainMatch, extractHostname, findLookalikeTarget, registrableDomain } from '../utils/siteTrust';
import { validateMessage } from '../utils/messageGuard';
import { encryptPayload, decryptPayload, hexToBytes } from '../utils/crypto';
import { API_BASE_URL, WEB_APP_URL } from '../utils/config';
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

// XoraPass's own web app is never an autofill target -- see the matching
// (and more detailed) comment in content.ts. This is the second of two checks:
// content.ts already disqualifies itself entirely on this domain, so nothing
// should even reach this handler for it. This exists as the same defense-in-
// depth this file already applies everywhere else (GET_CREDENTIAL_SECRET and
// AI_FILL_CONFIRM both re-verify the domain at the point of use rather than
// trusting a single earlier gate) -- so a future caller of this handler that
// bypasses the content-script gate still cannot get the master-password field
// treated as a matchable login.
const OWN_APP_HOSTNAME = (() => {
  try {
    return new URL(WEB_APP_URL).hostname;
  } catch {
    return '';
  }
})();
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

// ── Toolbar badge: "an AI is waiting on you" ────────────────────────────────
//
// Without this, a pending request is invisible: the popup's AI tab only fetches
// when it is opened, so noticing one required already suspecting it existed.
// The request expires in ten minutes, so a user who never thinks to look simply
// finds that nothing happened, with no way to tell a denial from an oversight.
//
// The badge carries a COUNT and nothing else. It is drawn on a surface visible
// on every site, including hostile ones, so it must not leak which credential
// or which site is involved — that detail belongs behind the popup, which only
// opens on a user gesture.
async function updateAiBadge(): Promise<void> {
  try {
    const session = await browser.storage.session.get(['unlocked']);
    if (!session.unlocked) return void clearAiBadge();

    const { ok, data } = await apiJwt('GET', '/ai/access-requests');
    if (!ok || !Array.isArray(data)) return;
    const pending = (data as { status?: string }[]).filter((r) => r.status === 'pending').length;

    await browser.action.setBadgeText({ text: pending > 0 ? String(pending) : '' });
    if (pending > 0) {
      await browser.action.setBadgeBackgroundColor({ color: '#f59e0b' });
      await browser.action.setTitle({ title: `XoraPass — ${pending} AI request${pending === 1 ? '' : 's'} awaiting your decision` });
    } else {
      await browser.action.setTitle({ title: 'XoraPass' });
    }
  } catch {
    // Never let a badge refresh surface as a failure; it is ambient.
  }
}

async function clearAiBadge(): Promise<void> {
  try {
    await browser.action.setBadgeText({ text: '' });
    await browser.action.setTitle({ title: 'XoraPass' });
  } catch {
    /* action API unavailable */
  }
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
    void clearAiBadge();
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
    // Same tick as the fill push: both answer "has anything changed for me?",
    // and the request list is the cheaper of the two calls.
    void updateAiBadge();
    // Catches an approval made from the WEB APP rather than this extension —
    // the only path this extension has to learn about it at all, since nothing
    // pushes to a browser extension from outside itself.
    void notifyForNewActiveSessions();
    // A brand-new pending request also needs an active nudge, same reasoning
    // as the session one above -- it can arrive (or be approved from the web
    // app, or seen for the first time) with no popup open to show it.
    void pushNewAiRequestsToActiveTab();
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

// ── OS-level nudge for a newly-approved session ─────────────────────────────
//
// The in-page banner (getAiFillForHostname) only ever shows on a tab the user
// is ALREADY looking at, because it is injected by the content script running
// on that page. It never told anyone anything: approving a request while the
// matching site was not the focused tab left the session sitting there with no
// way to discover it short of switching tabs by chance.
//
// This closes that gap with a real chrome.notifications toast — the closest
// this API surface gets to "pop the extension" — fired once per session,
// and ONLY when no currently-focused tab already matches (i.e. only when the
// banner is genuinely not visible to the user right now). Clicking it focuses
// the matching tab if one is open, or opens one, which is what then lets the
// existing tab-activation handlers show the real banner and — same as any
// other fill — still requires the user to press Fill themselves.
const notifiedSessionIds = new Set<string>();
// Notification id -> the domain to focus/open when it is clicked. This is a
// same-instance cache only now (see below for why it can't be the source of
// truth); still checked first as a fast path.
const notificationDomains = new Map<string, string>();
// In-flight guard, separate from notifiedSessionIds: this function is called
// from two places (the immediate post-approve nudge and the once-a-minute
// heartbeat) that can land within milliseconds of each other. Both would see
// notifiedSessionIds as empty and race each other through the async tab
// query below, both then calling notifications.create() for the same
// session -- which Chrome treats as re-triggering the same notification,
// not a no-op, so it can visibly flash/duplicate. Marking synchronously here,
// before the first await, closes that window; notifiedSessionIds (below)
// still only gets marked once a notification actually shows.
const checkingSessionIds = new Set<string>();

// notifiedSessionIds/notificationDomains above only guard a race WITHIN one
// service-worker lifetime. MV3 tears the worker down after a short idle
// period and respawns it fresh for the next event -- routine, not an edge
// case -- which wipes both Sets/Maps with it. A session left active across
// two heartbeat ticks that each happened to run in a different worker
// instance would then look "never notified" the second time too, and the
// user gets the same toast twice. storage.session survives a worker restart
// (cleared only on browser restart, or explicitly on LOCK_VAULT below), so
// it is the actual source of truth across ticks; the in-memory Sets/Map stay
// as the fast path for the same-tick race the comment above describes.
const AI_NOTIFIED_SESSIONS_KEY = 'aiNotifiedSessionIds';
const AI_NOTIFICATION_DOMAINS_KEY = 'aiNotificationDomains';

async function wasSessionNotifiedPersisted(sessionId: string): Promise<boolean> {
  const res = await browser.storage.session.get([AI_NOTIFIED_SESSIONS_KEY]);
  const ids = (res as Record<string, unknown>)[AI_NOTIFIED_SESSIONS_KEY];
  return Array.isArray(ids) && ids.includes(sessionId);
}

async function markSessionNotifiedPersisted(
  sessionId: string,
  notificationId: string,
  domain: string,
): Promise<void> {
  const res = await browser.storage.session.get([AI_NOTIFIED_SESSIONS_KEY, AI_NOTIFICATION_DOMAINS_KEY]);
  const prevIds = (res as Record<string, unknown>)[AI_NOTIFIED_SESSIONS_KEY];
  const ids = Array.isArray(prevIds) ? (prevIds as string[]) : [];
  const prevDomains = (res as Record<string, unknown>)[AI_NOTIFICATION_DOMAINS_KEY];
  const domains = (prevDomains && typeof prevDomains === 'object' ? prevDomains : {}) as Record<string, string>;
  // Bounded the same way every other per-request map in this file is: the key
  // space is a server-issued id, but nothing should grow unboundedly across
  // an extension install that is never uninstalled.
  const nextIds = ids.includes(sessionId) ? ids : [...ids, sessionId].slice(-500);
  domains[notificationId] = domain;
  await browser.storage.session.set({
    [AI_NOTIFIED_SESSIONS_KEY]: nextIds,
    [AI_NOTIFICATION_DOMAINS_KEY]: domains,
  });
}

/** Looks up (and forgets) the domain for a clicked/closed notification. */
async function takeNotificationDomain(notificationId: string): Promise<string | undefined> {
  const cached = notificationDomains.get(notificationId);
  notificationDomains.delete(notificationId);
  if (cached) return cached;

  // Not in this worker instance's memory -- the notification may have been
  // created by an earlier instance. Fall back to the persisted copy.
  const res = await browser.storage.session.get([AI_NOTIFICATION_DOMAINS_KEY]);
  const domains = (res as Record<string, unknown>)[AI_NOTIFICATION_DOMAINS_KEY];
  if (!domains || typeof domains !== 'object') return undefined;
  const map = domains as Record<string, string>;
  const domain = map[notificationId];
  if (domain !== undefined) {
    delete map[notificationId];
    await browser.storage.session.set({ [AI_NOTIFICATION_DOMAINS_KEY]: map });
  }
  return domain;
}

async function notifyIfNoMatchingActiveTab(
  sessionId: string,
  domain: string,
  aiToolName: string,
): Promise<void> {
  if (!domain || notifiedSessionIds.has(sessionId) || checkingSessionIds.has(sessionId)) return;
  checkingSessionIds.add(sessionId);

  try {
    if (await wasSessionNotifiedPersisted(sessionId)) {
      notifiedSessionIds.add(sessionId);
      return;
    }

    // "Active" tab per window is exactly what the user is looking at, and is
    // also what pushAiFillToActiveTabs uses to decide who gets the in-page
    // banner — so this check answers "would they have seen a banner already?"
    const activeTabs = await browser.tabs.query({ active: true });
    const alreadyVisible = activeTabs.some(
      (t) => t.url && isDomainMatch(extractHostname(t.url), domain),
    );
    // Deliberately NOT marked notified here: a tab being visible right now is
    // not evidence the user will still be on it a moment from now, or that
    // the fill actually happened. This function runs again on every
    // heartbeat tick while the session stays active, so a user who switches
    // away right after approving still gets the fallback notification on the
    // next tick, instead of this session being silently skipped forever
    // because it happened to look "handled" the first time it was checked.
    if (alreadyVisible) return;

    const api = (globalThis as any).chrome;
    if (!api?.notifications?.create) return; // e.g. Firefox without the API

    // Only a REAL notification earns the mark -- this is what actually
    // prevents re-notifying for the same session on the next tick.
    notifiedSessionIds.add(sessionId);
    if (notifiedSessionIds.size > 500) notifiedSessionIds.clear();

    const notificationId = `xorapass-ai-${sessionId}`;
    notificationDomains.set(notificationId, domain);
    // Persisted BEFORE create(): a worker restart between these two lines
    // would otherwise leave the toast shown but nothing recording that fact,
    // which is exactly the gap this whole mechanism exists to close.
    await markSessionNotifiedPersisted(sessionId, notificationId, domain);
    api.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: browser.runtime.getURL('icons/icon128.png'),
      title: 'XoraPass — AI sign-in approved',
      message: `${aiToolName || 'An AI tool'} was approved to fill your ${domain} login. Click to open it.`,
      priority: 2,
    });
  } catch (err) {
    console.warn('[XoraPass] AI session notification failed:', err);
  } finally {
    checkingSessionIds.delete(sessionId);
  }
}

// An AI session's `domain` is whatever the request payload sent -- a bare
// host ("github.com") historically, but now (core-api preserves the path
// rather than collapsing it) potentially a full URL ("https://github.com/
// login") too. Blindly prepending "https://" doubles the scheme on the
// latter, producing a malformed address the browser cannot load. Use the
// value as-is when it is already an absolute URL.
function toNavigableUrl(domain: string): string {
  try {
    return new URL(domain).toString();
  } catch {
    return `https://${domain}`;
  }
}

if ((globalThis as any).chrome?.notifications?.onClicked) {
  (globalThis as any).chrome.notifications.onClicked.addListener(async (notificationId: string) => {
    // A click can arrive in a worker instance that did not create this
    // notification (the one that did may have already been torn down), so
    // the in-memory map alone cannot be trusted -- takeNotificationDomain
    // falls back to the persisted copy when it is empty here.
    const domain = await takeNotificationDomain(notificationId);
    void (globalThis as any).chrome.notifications.clear(notificationId);
    if (!domain) return;

    // Prefer an already-open tab over a new one: it preserves scroll/typed
    // state, and is what a user clicking "go there" actually expects.
    const tabs = await browser.tabs.query({});
    const match = tabs.find(
      (t) => t.id !== undefined && t.url && isDomainMatch(extractHostname(t.url), domain),
    );
    if (match?.id !== undefined) {
      await browser.tabs.update(match.id, { active: true });
      if (match.windowId !== undefined) {
        await browser.windows.update(match.windowId, { focused: true }).catch(() => {});
      }
      // onActivated (below) fires from this and shows the real in-page banner.
    } else {
      await browser.tabs.create({ url: toNavigableUrl(domain) });
    }
  });
}

// Dismissed without a click (timeout, or the user closes it directly) still
// needs the mapping cleaned up, or it grows for as long as the browser stays
// open (storage.session, unlike the in-memory Map, isn't bounded by a single
// worker's lifetime).
if ((globalThis as any).chrome?.notifications?.onClosed) {
  (globalThis as any).chrome.notifications.onClosed.addListener((notificationId: string) => {
    void takeNotificationDomain(notificationId);
  });
}

/**
 * Notifies for every active AI session the user has not yet been told about.
 *
 * Covers BOTH approval paths with one function: the extension's own approve
 * action calls this immediately for a fast nudge, and the heartbeat calls it
 * on every tick so a request approved from the WEB APP — which this extension
 * has no other way to learn about — surfaces within one heartbeat interval.
 */
async function notifyForNewActiveSessions(): Promise<void> {
  const sessions = await getActiveAiSessions();
  for (const s of sessions) {
    if (s.status === 'active' && s.granted_scopes.includes('autofill')) {
      void notifyIfNoMatchingActiveTab(s.id, s.domain, s.ai_tool_name);
    }
  }
}
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

/** Forces the next getActiveAiSessions() call to hit the network.
 *
 * Needed right after this extension's own approve action: the cache may hold a
 * fetch from moments earlier that predates the session just created, and
 * without this the OS-notification fast path could read stale data and miss
 * it — falling back to the next heartbeat, up to 60s later.
 */
function invalidateSessionsCache(): void {
  sessionsCache = null;
}

// ── Brokered fills (the AI-initiated half of the flow) ──────────────────────
//
// When an AI calls use_credential, core-api creates a PENDING FILL and blocks
// waiting for a client to claim, apply, and report it. That record carries a
// reference (vault_entry_id) and a domain binding — never a secret; the server
// has never held one. This is the piece that closes the loop, so the AI learns
// "applied" or "not applied" instead of always being told nothing listened.
//
// Claiming is deliberately tied to the user pressing Fill rather than done
// eagerly on discovery. A claim starts the server's short result grace, so
// claiming before a human has decided would convert "waiting for the user" into
// "client crashed" and report a failure for a fill that was about to succeed.

interface PendingFill {
  id: string;
  session_id: string;
  vault_entry_id?: string;
  domain: string;
  scope: string;
}

/**
 * Claims the pending fill belonging to `sessionId`, if one is waiting.
 *
 * Returns null whenever there is nothing to claim, or the claim is lost to
 * another client — both are normal. A null result means "fill locally but do
 * not report", which preserves the pre-existing session-driven behaviour for
 * users whose AI never called use_credential at all.
 */
async function claimFillForSession(sessionId: string): Promise<PendingFill | null> {
  const list = await apiJwt('GET', '/ai/pending-fills');
  if (!list.ok) return null;
  const fills = (list.data?.pending_fills as PendingFill[] | undefined) ?? [];
  const waiting = fills.find((f) => f.session_id === sessionId);
  if (!waiting) return null;

  // 409 here means another client got it first. Returning null is correct: that
  // client owns reporting the outcome, and two reports would race.
  const claim = await apiJwt('POST', `/ai/pending-fills/${waiting.id}/claim`);
  if (!claim.ok) return null;
  return (claim.data?.fill as PendingFill | undefined) ?? waiting;
}

/**
 * Reports what actually happened. Never silently swallowed into "filled": the
 * server treats a claimed-but-unreported fill as failed, which is the correct
 * default, so a lost report degrades to "not applied" rather than a false
 * success in the audit trail.
 */
async function reportFillOutcome(fillId: string, outcome: 'filled' | 'failed', reason = ''): Promise<void> {
  const res = await apiJwt('POST', `/ai/pending-fills/${fillId}/result`, { outcome, reason });
  if (!res.ok) {
    console.warn('[XoraPass] could not report fill outcome:', outcome, reason, res.status);
  }
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

// Tracks pending AI request ids the in-page prompt has already been shown
// for, so the heartbeat doesn't re-open the same dialog on every tick while
// it's still awaiting a decision. Bounded like every other per-request set in
// this file, for the same reason: request ids are server-issued and open-ended.
const seenAiRequestIds = new Set<string>();

interface AiRequestOffer {
  id: string;
  aiToolName: string;
  action: string;
  domain: string;
  credentialLabel: string;
  riskLevel: string;
  reason: string;
  requestedScopes: string[];
  requestedDurationSeconds: number;
  credentialType: string;
  vaultEntryId?: string;
  requestKind?: string;
}

/**
 * Pushes an in-page Approve/Deny/Reduce-scope prompt to one active tab for
 * any pending AI request the user hasn't been shown yet -- the same "does the
 * user need to look at this" moment the toolbar badge already covers
 * passively, made active so a new request doesn't sit unnoticed until someone
 * happens to open the popup. Uses the same showConfirmDialog-style shadow-DOM
 * UI the secret-paste warning already uses, so a security-relevant prompt
 * looks consistent regardless of which one is showing.
 *
 * Only the first fresh request goes out, and only to one tab: stacking
 * several dialogs across windows (or several at once in one tab) for
 * requests that arrived together would be worse than the badge it
 * supplements. Anything left over stays covered by the badge until this one
 * is decided and the next heartbeat tick offers the next.
 */
async function pushNewAiRequestsToActiveTab(): Promise<void> {
  const jwt = await getJwt();
  if (!jwt) {
    console.debug('[XoraPass] pushNewAiRequestsToActiveTab: no jwt, skipping');
    return;
  }

  const { ok, data } = await apiJwt('GET', '/ai/access-requests');
  if (!ok || !Array.isArray(data)) {
    console.debug('[XoraPass] pushNewAiRequestsToActiveTab: bad /ai/access-requests response', ok, data);
    return;
  }

  const fresh = (data as any[]).find((r) => r.status === 'pending' && !seenAiRequestIds.has(r.id));
  if (!fresh) {
    console.debug(
      '[XoraPass] pushNewAiRequestsToActiveTab: nothing fresh',
      (data as any[]).map((r) => ({ id: r.id, status: r.status })),
      'already seen:',
      [...seenAiRequestIds],
    );
    return;
  }
  console.debug('[XoraPass] pushNewAiRequestsToActiveTab: fresh request', fresh.id, fresh.request_kind);

  const offer: AiRequestOffer = {
    id: fresh.id,
    aiToolName: fresh.ai_tool_name || 'An AI tool',
    action: fresh.action,
    domain: fresh.domain,
    credentialLabel: fresh.credential_label,
    riskLevel: fresh.risk_level,
    reason: fresh.reason,
    requestedScopes: fresh.requested_scopes || [],
    requestedDurationSeconds: fresh.requested_duration_seconds || 300,
    credentialType: fresh.credential_type,
    vaultEntryId: fresh.vault_entry_id,
    requestKind: fresh.request_kind,
  };

  // `active: true` with no windowId returns the active tab of EVERY open
  // window, not just the one the user is looking at right now. Earlier this
  // tried only the first of those and marked the request seen regardless of
  // whether delivery actually landed -- a tab that had no content script
  // listening yet (still loading, a chrome:// tab, a restricted page) burned
  // the request's only shot at the popup, silently, forever. Unlike the
  // desktop notification (a direct OS call needing no tab at all), this UI
  // has nowhere to render without a live content script, so every candidate
  // tab is tried and the request is marked seen only once one of them
  // actually confirms it showed the dialog.
  const tabs = await browser.tabs.query({ active: true });
  console.debug(
    '[XoraPass] pushNewAiRequestsToActiveTab: candidate tabs',
    tabs.map((t) => ({ id: t.id, url: t.url, windowId: t.windowId })),
  );
  for (const t of tabs) {
    if (t.id === undefined) continue;
    try {
      const ack: any = await browser.tabs.sendMessage(t.id, { type: 'AI_REQUEST_AVAILABLE', payload: offer });
      console.debug('[XoraPass] pushNewAiRequestsToActiveTab: ack from tab', t.id, ack);
      if (ack && ack.received) {
        seenAiRequestIds.add(fresh.id);
        if (seenAiRequestIds.size > 500) seenAiRequestIds.clear();
        return;
      }
    } catch (err) {
      console.debug('[XoraPass] pushNewAiRequestsToActiveTab: sendMessage failed for tab', t.id, err);
    }
  }
  console.debug('[XoraPass] pushNewAiRequestsToActiveTab: no tab acknowledged delivery, will retry next heartbeat');
  // No eligible tab right now. Left un-seen on purpose: the next heartbeat
  // tick retries, and the badge covers the gap until then.
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
    const payload = msg.payload as {
      decryptedItems: unknown;
      email: string;
      jwt?: string;
      encKey?: string; // base64 -- needed only so "save to vault" can encrypt new entries
      token?: string;
      offline?: boolean;
    };
    const { decryptedItems, email, jwt, encKey, token, offline } = payload;
    // token and encKey are held so the popup can re-fetch and decrypt the vault
    // without a full re-authentication. They live in storage.session, which is
    // memory-only, cleared on browser restart, and already restricted to
    // TRUSTED_CONTEXTS — the same place the decrypted vault itself sits.
    const sessionData = {
      unlocked: true,
      email,
      vaultItems: decryptedItems,
      jwt: jwt || '',
      encKey: encKey || '',
      token: token || '',
      // An offline unlock came from the cache and has no access token, so
      // writes have to wait for a connection.
      offline: !!offline,
    };
    return browser.storage.session
      .set(sessionData)
      .then(() => {
        void scheduleAutoLock();
        void scheduleAiHeartbeat();
        // Immediately, not on the next heartbeat: a request raised while the
        // vault was locked would otherwise sit unbadged for up to a minute
        // after unlocking, which is most of its ten-minute life.
        void updateAiBadge();
        console.debug('[XoraPass] UNLOCK_VAULT -> session stored (', (decryptedItems as unknown[]).length, 'items )');
        return { success: true };
      });
  }

  if (type === 'LOCK_VAULT') {
    console.debug('[XoraPass] LOCK_VAULT -> clearing session');
    void browser.alarms.clear(AUTO_LOCK_ALARM);
    void clearAiHeartbeat();
    // The count is session state and must not outlive the session: a badge left
    // behind would claim pending work to someone who can no longer see it.
    void clearAiBadge();
    dismissedByTab.clear();
    // A notification already shown must not resurface after re-unlock claiming
    // to be new, and its session id may not even be valid anymore.
    notifiedSessionIds.clear();
    notificationDomains.clear();
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
    if (!hostname || (OWN_APP_HOSTNAME && hostname === OWN_APP_HOSTNAME)) {
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
    // Refused outright, not just unmatched: a saved entry genuinely CAN carry
    // this exact URL (see OWN_APP_HOSTNAME above), so the normal domain
    // re-check below would legitimately pass it. This is a narrower rule than
    // "does the domain match" -- it is "this domain is never a fill target",
    // which the URL-matching logic has no way to express on its own.
    if (OWN_APP_HOSTNAME && hostname === OWN_APP_HOSTNAME) {
      return Promise.resolve({ error: 'not_fillable' });
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

    // The hostname comes from the SENDER TAB, never the payload — the same rule
    // GET_CREDENTIAL_SECRET follows. The offer was pushed to a matching tab, but
    // that is not evidence the tab still matches: it may have navigated since,
    // and a compromised content script must not be able to name a domain.
    const senderHost = extractHostname(sender.tab?.url || sender.url || '');
    if (!senderHost) return Promise.resolve({ error: 'Unknown page origin.' });

    return apiJwt('GET', '/ai/sessions').then(async ({ ok, data }) => {
      if (!ok || !Array.isArray(data)) {
        return { error: 'Could not verify this AI session -- try again.' };
      }
      const session = (data as AiSession[]).find((s) => s.id === sessionId);
      if (!session || session.status !== 'active' || !session.granted_scopes.includes('autofill') || !session.vault_entry_id) {
        return { error: 'This AI session is no longer active.' };
      }
      // Re-authorize the domain at the moment of use, against live state.
      if (!session.domain || !isDomainMatch(senderHost, session.domain)) {
        console.warn('[XoraPass] AI fill refused: page does not match approved domain', senderHost);
        return { error: 'This page does not match the approved domain.' };
      }

      const res = await browser.storage.session.get(['vaultItems']);
      const items = (res as Record<string, unknown>).vaultItems as VaultItem[] | undefined;
      const item = items?.find((i) => i.id === session.vault_entry_id);
      if (!item) return { error: 'Credential not found in this session -- try unlocking again.' };

      // Claim last, once everything else has passed. A claim starts the server's
      // result grace, so it must not be taken on a path that can still refuse.
      const fill = await claimFillForSession(sessionId);
      if (fill) {
        // The fill carries its own binding, and the server explicitly delegates
        // this check to us: it never sees the page. A mismatch here is reported
        // rather than filled, which releases the reserved use.
        if (fill.domain && !isDomainMatch(senderHost, fill.domain)) {
          console.warn('[XoraPass] AI fill refused: page does not match fill domain', senderHost);
          void reportFillOutcome(fill.id, 'failed', 'domain_mismatch');
          return { error: 'This page does not match the approved domain.' };
        }
      }

      return { username: item.username, value: item.value, fillId: fill?.id };
    });
  }

  if (type === 'AI_FILL_RESULT') {
    // Reported by the content script once it has actually typed (or failed to).
    // Only the tab that received the fillId can resolve it, and the server
    // accepts exactly one result per claim.
    const { fillId, outcome, reason } = msg.payload as {
      fillId: string;
      outcome: 'filled' | 'failed';
      reason?: string;
    };
    return reportFillOutcome(fillId, outcome, reason || '').then(() => ({ success: true }));
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

  if (type === 'AI_LIST_VAULT_ITEMS') {
    // Label-only, for the in-page dialog's "which saved item did the AI
    // mean?" picker -- never the value. storage.session already holds the
    // fully decrypted vault for the popup's own picker; this strips it down
    // to what a content script is allowed to see, same as
    // GET_MATCHING_CREDENTIALS does for the credential-picker menu.
    return browser.storage.session.get(['vaultItems']).then((res) => {
      const items = ((res as Record<string, unknown>).vaultItems as VaultItem[] | undefined) || [];
      return {
        items: items.map((i) => ({ id: i.id, label: i.label, username: i.username, category: i.category })),
      };
    });
  }

  if (type === 'AI_DECIDE_REQUEST') {
    const { requestId, decision, grantedScopes, durationSeconds, maxUses, vaultEntryId } = msg.payload as {
      requestId: string;
      decision: 'approve' | 'deny';
      grantedScopes?: string[];
      durationSeconds?: number;
      maxUses?: number;
      // Which credential a label-only ("unbound") personal request actually
      // means. The server requires this and refuses the approval without it
      // (400 "vault_entry_id is required") -- the AI names a credential the
      // way a person would ("GitHub Dev Token") and never learns which real
      // entry was chosen, so the popup has to ask before approving one.
      vaultEntryId?: string;
    };
    const path = `/ai/access-requests/${requestId}/${decision}`;
    const body =
      decision === 'approve'
        ? {
            ...(grantedScopes && grantedScopes.length ? { granted_scopes: grantedScopes } : {}),
            ...(durationSeconds ? { duration_seconds: durationSeconds } : {}),
            ...(maxUses ? { max_uses: maxUses } : {}),
            ...(vaultEntryId ? { vault_entry_id: vaultEntryId } : {}),
          }
        : undefined;
    return apiJwt('POST', path, body).then(({ ok, status, data }) => {
      if (!ok) return { error: data?.detail || `HTTP ${status}` };
      // Deciding is the moment the count changes, and the user is looking right
      // at the toolbar when they do it. Waiting for the next heartbeat would
      // leave the badge asserting work they just finished.
      void updateAiBadge();
      // An approval mints a session, so the tab they are on may now have a fill
      // to offer. Pushing here is what makes "approve, then switch to the tab"
      // work without waiting a minute for the heartbeat to notice.
      if (decision === 'approve') {
        void pushAiFillToActiveTabs();
        invalidateSessionsCache();
        void notifyForNewActiveSessions();
      }
      return { success: true, data };
    });
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

// ── Secure Web Bridge: External Messages Listener ────────────────────────────
// Listens for external calls from trusted externally_connectable origins (e.g. app.xorapass.com)
// to securely receive login payloads containing JWTs and derived master encryption keys.
const api = (globalThis as any).chrome;
if (api?.runtime?.onMessageExternal) {
  api.runtime.onMessageExternal.addListener((message: any, sender: any, sendResponse: (r: any) => void) => {
    // Validate message payload structure
    const guard = validateMessage(message, sender);
    if (!guard.ok) {
      console.warn('[XoraPass Bridge] Rejected external message:', guard.reason);
      sendResponse({ error: 'invalid_message', reason: guard.reason });
      return;
    }

    if (guard.type === 'WEB_BRIDGE_LOGIN') {
      const { token, encKey, email } = message.payload;
      console.debug('[XoraPass Bridge] Received login bridge for:', email);

      // Perform secure unlocking
      // 1. Convert encKey base64 string to bytes
      let derivedEncBytes;
      try {
        derivedEncBytes = base64ToBytes(encKey);
      } catch (e) {
        sendResponse({ error: 'invalid_enc_key_base64' });
        return;
      }

      // 2. Fetch vault items from server using the bridge token
      fetch(`${API_BASE_URL}/api/vault`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      .then(res => {
        if (!res.ok) throw new Error(`Vault API error ${res.status}`);
        return res.json();
      })
      .then(async (vaultData) => {
        // 3. Store the decrypted session context
        const decryptedItems = vaultData.map((entry: any) => {
          try {
            const rawCiphertext = entry.encrypted_payload;
            const opened = decryptPayload({ ...rawCiphertext, nonce: entry.nonce }, derivedEncBytes);
            const parsed = JSON.parse(opened);
            return {
              id: entry.id,
              label: parsed.label || "Unnamed Entry",
              username: parsed.username || "",
              value: parsed.value || "",
              notes: parsed.notes || "",
              category: parsed.category || "login",
              organization: parsed.organization || "",
              url: parsed.url || "",
              cardholderName: parsed.cardholderName || "",
              cardNumber: parsed.cardNumber || "",
              expiryDate: parsed.expiryDate || "",
              cvv: parsed.cvv || "",
              privateKey: parsed.privateKey || "",
              publicKey: parsed.publicKey || "",
              passphrase: parsed.passphrase || ""
            };
          } catch {
            return { id: entry.id, label: "Couldn't decrypt", username: "", value: "", category: "login", url: "" };
          }
        });

        // 4. Save session context
        // NOTE: encKey must be stored as hex (matching bytesToHex from the popup login path)
        // so that refreshVault can correctly recover it with hexToBytes.
        const encKeyHex = Array.from(derivedEncBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        await browser.storage.session.set({
          unlocked: true,
          email,
          token,
          jwt: token,
          encKey: encKeyHex, // stored as hex to match popup storeSession convention
          vaultItems: decryptedItems,
          offline: false,
        });

        void scheduleAutoLock();
        void scheduleAiHeartbeat();
        // Immediately, not on the next heartbeat: a request raised while the
        // vault was locked would otherwise sit unbadged for up to a minute
        // after unlocking, which is most of its ten-minute life.
        void updateAiBadge();

        console.debug('[XoraPass Bridge] Bridge unlock complete');
        sendResponse({ success: true });
      })
      .catch(err => {
        console.error('[XoraPass Bridge] Bridge sync failed:', err);
        sendResponse({ error: 'sync_failed', detail: String(err) });
      });

      return true; // Keep message channel open for async response
    }
  });
}

