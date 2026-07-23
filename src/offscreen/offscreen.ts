// Offscreen document — exists only to touch the clipboard on the service
// worker's behalf.
//
// An MV3 service worker has no DOM and therefore no clipboard access, and the
// popup is destroyed the moment it loses focus, so neither can clear the
// clipboard on a timer. An offscreen document can, and it stays invisible to
// the user.
//
// `navigator.clipboard.writeText` requires a focused document, which an
// offscreen document never is; the legacy textarea + `execCommand('copy')`
// path has no such requirement and is the documented recipe for this reason.
//
// Chrome-only by construction — Firefox and Safari have no offscreen API, so
// the background never creates this document there.

import browser from 'webextension-polyfill';

const OFFSCREEN_TARGET = 'xorapass-offscreen';

interface ClipboardMessage {
  target?: string;
  type?: string;
  text?: string;
}

function writeClipboard(text: string): boolean {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  // Keep it out of the layout and out of the accessibility tree; it exists for
  // the length of one selection.
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  textarea.remove();
  return ok;
}

browser.runtime.onMessage.addListener((message: unknown) => {
  const msg = message as ClipboardMessage;
  // Every extension context receives every runtime message, so ignore anything
  // not explicitly addressed here. Returning undefined leaves the response to
  // whichever context the message was actually for.
  if (!msg || msg.target !== OFFSCREEN_TARGET || msg.type !== 'CLIPBOARD_WRITE') {
    return undefined;
  }
  const ok = writeClipboard(typeof msg.text === 'string' ? msg.text : '');
  return Promise.resolve({ ok });
});
