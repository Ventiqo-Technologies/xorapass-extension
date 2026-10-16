import type { Runtime } from 'webextension-polyfill';

// Older polyfill typings omit the browser's MessageSender.origin field.
type CredentialSender = Runtime.MessageSender & { origin?: string };

function webUrl(value: string | undefined): URL | null {
  try {
    const url = new URL(value || '');
    return url.protocol === 'https:' || url.protocol === 'http:' ? url : null;
  } catch {
    return null;
  }
}

/**
 * Credential requests belong to the actual requesting document, never a
 * payload hostname or the top tab by proxy. Cross-origin and opaque frames
 * cannot inherit the top page's credential authority.
 */
export function credentialRequestUrl(sender: CredentialSender): string | null {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (typeof tabId !== 'number' || !Number.isInteger(tabId) || tabId < 0 ||
      typeof frameId !== 'number' || !Number.isInteger(frameId) || frameId < 0) return null;

  const frame = webUrl(sender.url);
  const top = webUrl(sender.tab?.url);
  if (!frame || !top || frame.origin !== top.origin) return null;

  // A sandboxed frame may have an HTTPS URL but an opaque ("null") origin.
  // Where origin metadata is unavailable, only the top frame is supported:
  // URL equality alone cannot establish a subframe's effective origin.
  if (sender.origin !== undefined) {
    if (sender.origin !== frame.origin) return null;
  } else if (frameId !== 0) {
    return null;
  }

  // Chromium may retain the document's original sender URL after a same-
  // document navigation (or omit its fragment). The browser's tab URL is
  // current for frame zero. Use it only after validating the actual frame's
  // origin above; child frames never inherit their parent's path authority.
  return frameId === 0 ? top.href : frame.href;
}
