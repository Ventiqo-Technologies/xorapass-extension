// XoraPass Background Service Worker (Manifest V3)
import browser from 'webextension-polyfill';
import { isDomainMatch, extractHostname, findLookalikeTarget, registrableDomain } from '../utils/siteTrust';
import { validateMessage } from '../utils/messageGuard';
import { encryptPayload, hexToBytes } from '../utils/crypto';
import { API_BASE_URL } from '../utils/config';

// Logged on every service-worker (cold) start. If the session were cleared by a
// mere page refresh you would NOT see this line on refresh — it only prints when
// the worker itself restarts, which is what actually resets storage.session.
console.debug('[XoraPass] service worker started at', new Date().toISOString());

const DISABLED_SITES_KEY = 'disabledSites';
const AUTO_LOCK_KEY = 'autoLockMinutes';
const AUTO_LOCK_ALARM = 'xorapass-auto-lock';
const DEFAULT_AUTO_LOCK_MINUTES = 15;

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

// When the idle timer fires, purge the decrypted vault from session storage.
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) {
    console.debug('[XoraPass] auto-lock fired -> clearing session');
    browser.storage.session.clear();
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
    return browser.storage.session.get(['unlocked', 'email']).then((res) => {
      // The popup opening counts as activity: restart the idle auto-lock timer.
      if (res.unlocked) void scheduleAutoLock();
      console.debug('[XoraPass] GET_STATUS -> unlocked =', !!res.unlocked);
      return { unlocked: !!res.unlocked, email: res.email || null };
    });
  }

  if (type === 'UNLOCK_VAULT') {
    const { decryptedItems, email, token, encKey } = msg.payload;
    // token and encKey are held so the popup can re-fetch and decrypt the vault
    // without a full re-authentication. They live in storage.session, which is
    // memory-only, cleared on browser restart, and already restricted to
    // TRUSTED_CONTEXTS — the same place the decrypted vault itself sits.
    return browser.storage.session
      .set({ unlocked: true, email, vaultItems: decryptedItems, token, encKey })
      .then(() => {
        void scheduleAutoLock();
        console.debug('[XoraPass] UNLOCK_VAULT -> session stored (', decryptedItems.length, 'items )');
        return { success: true };
      });
  }

  if (type === 'LOCK_VAULT') {
    console.debug('[XoraPass] LOCK_VAULT -> clearing session');
    void browser.alarms.clear(AUTO_LOCK_ALARM);
    return browser.storage.session.clear().then(() => ({ success: true }));
  }

  if (type === 'GET_SETTINGS') {
    return getAutoLockMinutes().then((autoLockMinutes) => ({ autoLockMinutes }));
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

  const session = await browser.storage.session.get(['unlocked', 'token', 'encKey', 'vaultItems']);
  if (!session.unlocked || !session.token || !session.encKey) return { error: 'locked' };

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
