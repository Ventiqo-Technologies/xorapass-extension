// XoraPass Background Service Worker (Manifest V3)
import browser from 'webextension-polyfill';

// Listen for messages from Content Scripts and the Popup UI
browser.runtime.onMessage.addListener((message, _sender) => {
  if (message.type === 'GET_STATUS') {
    // Return whether the vault is currently unlocked
    return browser.storage.session.get(['unlocked', 'email']).then((res) => {
      return { unlocked: !!res.unlocked, email: res.email || null };
    });
  }

  if (message.type === 'UNLOCK_VAULT') {
    const { decryptedItems, email } = message.payload;
    // Cache the decrypted items in secure volatile session storage
    return browser.storage.session.set({
      unlocked: true,
      email,
      vaultItems: decryptedItems
    }).then(() => {
      return { success: true };
    });
  }

  if (message.type === 'LOCK_VAULT') {
    // Purge the secure volatile session storage
    return browser.storage.session.clear().then(() => {
      return { success: true };
    });
  }

  if (message.type === 'GET_MATCHING_CREDENTIALS') {
    const hostname = message.payload?.hostname || '';
    if (!hostname) {
      return Promise.resolve({ credentials: [] });
    }

    return browser.storage.session.get(['unlocked', 'vaultItems']).then((res) => {
      if (!res.unlocked || !res.vaultItems) {
        return { credentials: [] };
      }

      // Filter credentials matching the hostname
      const matching = res.vaultItems.filter((item: any) => {
        if (!item.url) return false;
        try {
          // Normalize URLs for comparison
          const cleanHost = hostname.toLowerCase().replace(/^www\./, '');
          
          // Extract hostname from credential URL
          let credUrlStr = item.url.trim().toLowerCase();
          if (!credUrlStr.startsWith('http://') && !credUrlStr.startsWith('https://')) {
            credUrlStr = 'https://' + credUrlStr;
          }
          const credUrl = new URL(credUrlStr);
          const cleanCredHost = credUrl.hostname.replace(/^www\./, '');

          return cleanHost.includes(cleanCredHost) || cleanCredHost.includes(cleanHost);
        } catch (e) {
          // Fallback if URL parsing fails
          return item.url.toLowerCase().includes(hostname.toLowerCase());
        }
      });

      // Map to only expose credentials fields needed for autofill
      return {
        credentials: matching.map((item: any) => ({
          id: item.id,
          label: item.label,
          username: item.username,
          value: item.value
        }))
      };
    });
  }
});

// Configure session storage access level (trusted context restriction)
// NOTE: setAccessLevel is not supported by Firefox or Safari, so we must guard it.
if (browser.storage && browser.storage.session && (browser.storage.session as any).setAccessLevel) {
  (browser.storage.session as any).setAccessLevel({
    accessLevel: 'TRUSTED_CONTEXTS'
  }).catch((err: any) => {
    console.warn("Unable to restrict storage session access level:", err);
  });
}

