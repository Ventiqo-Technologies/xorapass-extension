// XoraPass Background Service Worker (Manifest V3)
import browser from 'webextension-polyfill';
import { isDomainMatch, extractHostname, findLookalikeTarget } from '../utils/siteTrust';
import { validateMessage } from '../utils/messageGuard';

const DISABLED_SITES_KEY = 'disabledSites';

interface VaultItem {
  id: string;
  label: string;
  username: string;
  value: string;
  url?: string;
  category?: string;
}

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
    return browser.storage.session.get(['unlocked', 'email']).then((res) => ({
      unlocked: !!res.unlocked,
      email: res.email || null,
    }));
  }

  if (type === 'UNLOCK_VAULT') {
    const { decryptedItems, email } = msg.payload;
    return browser.storage.session
      .set({ unlocked: true, email, vaultItems: decryptedItems })
      .then(() => ({ success: true }));
  }

  if (type === 'LOCK_VAULT') {
    return browser.storage.session.clear().then(() => ({ success: true }));
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
        credentials: matching.map((item) => ({
          id: item.id,
          label: item.label,
          username: item.username,
          value: item.value,
          category: item.category || 'login',
        })),
        disabled: false,
        lookalike,
      };
    });
  }

  // Should be unreachable because validateMessage allowlists types.
  return undefined;
});

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
