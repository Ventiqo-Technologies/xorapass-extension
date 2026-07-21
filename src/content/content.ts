// XoraPass Content Script (Manifest V3)
//
// Responsibilities are deliberately narrow: detect login fields, ask the
// background worker what may be offered here, and render the overlay. All
// authoritative decisions — domain matching, lookalike detection, and the
// release of any actual secret — happen in the background worker.
//
// This script never holds the full set of passwords. It receives labels and
// usernames only; the password for a single entry is fetched on demand when
// the user picks it, and the background re-checks the tab's real domain before
// handing it over.
import browser from 'webextension-polyfill';
import { looksLikeUsername } from './fieldHeuristics';
import {
  attachIcon,
  hasIcon,
  openDropdown,
  closeDropdown,
  scheduleReposition,
  showConfirmDialog,
  showSavePrompt,
  closeSavePrompt,
  isSavePromptOpen,
  clearAll,
  type OverlayCredential,
} from './overlay';

let activeCredentials: OverlayCredential[] = [];
let lookalikeWarning: { target: string; reason: string } | null = null;

/** Password field -> its paired username field (null when none was found). */
const fieldPairs = new WeakMap<HTMLInputElement, HTMLInputElement | null>();

// Categories whose values are sensitive enough to always require an explicit
// confirmation before being written into a page.
const SENSITIVE_CATEGORIES = new Set(['card', 'identity']);

// ---------------------------------------------------------------------------
// Page-context trust guards
// ---------------------------------------------------------------------------

interface FrameAssessment {
  isTop: boolean;
  isCrossOriginFrame: boolean;
}

// Determines whether we are running inside a third-party (cross-origin) iframe.
// Autofill overlays are never injected into such frames, because a malicious
// top page could otherwise frame a look-alike login form to harvest secrets.
function assessFrame(): FrameAssessment {
  const isTop = window.top === window.self;
  if (isTop) return { isTop: true, isCrossOriginFrame: false };

  let isCrossOrigin = true;
  try {
    // Reading the top frame's origin throws for cross-origin parents.
    const topOrigin = window.top?.location.origin;
    isCrossOrigin = topOrigin !== window.location.origin;
  } catch {
    isCrossOrigin = true;
  }

  // Corroborate with ancestorOrigins (any cross-origin ancestor => untrusted).
  try {
    const ancestors = window.location.ancestorOrigins;
    if (ancestors && ancestors.length) {
      for (let i = 0; i < ancestors.length; i++) {
        if (ancestors[i] !== window.location.origin) {
          isCrossOrigin = true;
          break;
        }
      }
    }
  } catch {
    /* ancestorOrigins unsupported – keep prior assessment */
  }

  return { isTop: false, isCrossOriginFrame: isCrossOrigin };
}

// True for pages served over plaintext HTTP (excluding local development).
function isInsecureContext(): boolean {
  if (window.location.protocol !== 'http:') return false;
  const host = window.location.hostname;
  return host !== 'localhost' && host !== '127.0.0.1' && host !== '[::1]';
}

// ---------------------------------------------------------------------------
// Credential loading
// ---------------------------------------------------------------------------

// Request the credential list (labels/usernames only) for the current domain.
function loadCredentials(): void {
  const hostname = window.location.hostname;
  browser.runtime
    .sendMessage({ type: 'GET_MATCHING_CREDENTIALS', payload: { hostname } })
    .then((response: any) => {
      if (!response) return;

      // Respect the per-site disable list.
      if (response.disabled) {
        activeCredentials = [];
        clearAll();
        return;
      }

      lookalikeWarning = response.lookalike || null;
      activeCredentials = response.credentials || [];

      if (activeCredentials.length > 0) {
        scanForLoginFields();
      } else {
        clearAll();
      }
    })
    .catch(() => {
      /* background unavailable – nothing to fill */
    });
}

// ---------------------------------------------------------------------------
// Field detection
// ---------------------------------------------------------------------------

// An input is fillable if it's visible and user-editable.
function isFillable(el: HTMLInputElement): boolean {
  if (!el || el.type === 'hidden' || el.disabled || el.readOnly) return false;
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

/**
 * Finds password fields and attaches an overlay icon to each, plus to its
 * paired username field. Safe to call repeatedly — `hasIcon` makes it
 * idempotent, so the MutationObserver can call it freely.
 */
function scanForLoginFields(): void {
  if (activeCredentials.length === 0) return;

  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[];

  for (const passInput of passwordInputs) {
    if (!isFillable(passInput)) continue;
    if (hasIcon(passInput)) continue;

    const usernameInput = findUsernameField(passInput);
    fieldPairs.set(passInput, usernameInput);

    // Offer autofill on the password field, and on the username field when one
    // was found. This keeps autofill working on pages that don't wrap inputs in
    // a <form> or that split username/password across containers.
    attachIcon(passInput, () => activate(passInput));
    if (usernameInput && !hasIcon(usernameInput)) {
      fieldPairs.set(usernameInput, usernameInput);
      attachIcon(usernameInput, () => activate(passInput));
    }
  }
}

// Attempts to locate the username/email field preceding a password input.
// Searches the enclosing <form> when present, otherwise the whole document, in
// DOM order — so it works even when fields live in separate containers.
function findUsernameField(passInput: HTMLInputElement): HTMLInputElement | null {
  const scope: ParentNode = passInput.form || document;
  const inputs = Array.from(scope.querySelectorAll('input')) as HTMLInputElement[];
  const passIdx = inputs.indexOf(passInput);
  if (passIdx === -1) return null;

  // Scan backwards from the password field for the nearest username-like input.
  for (let i = passIdx - 1; i >= 0; i--) {
    const el = inputs[i];
    if (!isFillable(el)) continue;
    const matches = looksLikeUsername({
      type: el.type,
      autocomplete: el.getAttribute('autocomplete'),
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
    });
    if (matches) return el;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Fill flow
// ---------------------------------------------------------------------------

// Opens the credential menu anchored to whichever field the user clicked.
function activate(passInput: HTMLInputElement): void {
  openDropdown(passInput, {
    credentials: activeCredentials,
    warning: lookalikeWarning
      ? `This site resembles "${lookalikeWarning.target}". Verify the address before filling.`
      : null,
    onPick: (id) => void handlePick(id, passInput),
  });
}

async function handlePick(id: string, passInput: HTMLInputElement): Promise<void> {
  const cred = activeCredentials.find((c) => c.id === id);
  if (!cred) return;

  const confirmed = await confirmFillIfNeeded(cred);
  if (!confirmed) return;

  // Fetch the secret only now, for this one entry.
  const res = (await browser.runtime
    .sendMessage({ type: 'GET_CREDENTIAL_SECRET', payload: { id } })
    .catch(() => null)) as { username?: string; value?: string; error?: string } | null;

  if (!res || res.error || typeof res.value !== 'string') {
    console.warn('[XoraPass] Fill refused:', res?.error || 'no_response');
    return;
  }

  const usernameEl = fieldPairs.get(passInput) ?? null;
  if (usernameEl && usernameEl !== passInput && res.username) {
    autofillField(usernameEl, res.username);
  }
  autofillField(passInput, res.value);
}

// Decides whether a fill needs explicit confirmation, and if so, asks the user.
// Returns true when the fill may proceed.
async function confirmFillIfNeeded(cred: OverlayCredential): Promise<boolean> {
  const warnings: string[] = [];

  if (SENSITIVE_CATEGORIES.has(cred.category)) {
    warnings.push(
      `You are about to autofill sensitive ${cred.category} details ("${cred.label}").`
    );
  }
  if (isInsecureContext()) {
    warnings.push(
      'This page is served over insecure HTTP. Data you enter can be intercepted.'
    );
  }
  if (lookalikeWarning) {
    warnings.push(
      `The address of this page resembles "${lookalikeWarning.target}" but does not match it.`
    );
  }

  if (warnings.length === 0) return true;

  return showConfirmDialog({
    title: 'Confirm autofill',
    body: warnings,
    confirmLabel: 'Fill anyway',
    cancelLabel: 'Cancel',
  });
}

/**
 * Writes a value into a page input. Uses the native value setter so that
 * frameworks which track the property (React, Vue) observe the change — a
 * plain `el.value = x` is silently reverted by React's controlled inputs.
 */
function autofillField(el: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value'
  )?.set;

  if (setter) {
    setter.call(el, value);
  } else {
    el.value = value;
  }

  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  el.dispatchEvent(new Event('blur', { bubbles: true }));
}

// ---------------------------------------------------------------------------
// Credential capture
// ---------------------------------------------------------------------------

// Guards against re-capturing the same values when a page fires both a click
// and a submit for one login attempt.
let lastCaptured = '';

// Reads the credential out of a scope that contains a filled password field.
function readCredential(scope: ParentNode): { username: string; password: string } | null {
  const passwords = Array.from(
    scope.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[];

  const filled = passwords.find((p) => p.value && isFillable(p));
  if (!filled) return null;

  // A sign-up form usually has several password boxes (password + confirm).
  // Capturing those is out of scope here: they need the "did the account
  // actually get created" signal that a login redirect gives us.
  const filledCount = passwords.filter((p) => p.value).length;
  if (filledCount > 1) return null;

  const usernameEl = findUsernameField(filled);
  return { username: usernameEl?.value || '', password: filled.value };
}

function captureFrom(scope: ParentNode): void {
  const cred = readCredential(scope);
  if (!cred) return;

  const fingerprint = `${cred.username} ${cred.password}`;
  if (fingerprint === lastCaptured) return;
  lastCaptured = fingerprint;

  browser.runtime
    .sendMessage({ type: 'CAPTURE_CREDENTIAL', payload: cred })
    .then((res: any) => {
      // The worker decides whether this is new, changed, or already stored.
      // A full page navigation usually kills this script before the timer
      // fires; the prompt is then raised by checkPendingSave on the next load.
      if (res && res.prompt) {
        setTimeout(checkPendingSave, 1200);
      }
    })
    .catch(() => {
      /* worker unavailable */
    });
}

// Asks whether this tab has a capture awaiting a decision, and renders it.
function checkPendingSave(): void {
  if (isSavePromptOpen()) return;

  browser.runtime
    .sendMessage({ type: 'GET_PENDING_SAVE' })
    .then((res: any) => {
      const pending = res && res.pending;
      if (!pending) return;

      showSavePrompt({
        username: pending.username,
        hostname: pending.hostname,
        mode: pending.mode,
        onSave: () =>
          browser.runtime.sendMessage({ type: 'SAVE_CREDENTIAL' }).then((r: any) => {
            if (r && r.success) loadCredentials();
            return r || { error: 'no_response' };
          }),
        onDismiss: () => {
          void browser.runtime.sendMessage({ type: 'DISMISS_PENDING_SAVE' });
        },
      });
    })
    .catch(() => {
      /* worker unavailable */
    });
}

// Reports a username as it is entered so it survives into the next step of a
// two-step login, where the field itself is gone by the time the password is
// submitted. Only fires on change, and only for fields the heuristic accepts.
let lastReported = '';

function watchForUsernameEntry(): void {
  document.addEventListener(
    'change',
    (e) => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement)) return;
      const value = el.value.trim();
      if (!value || value === lastReported) return;

      const matches = looksLikeUsername({
        type: el.type,
        autocomplete: el.getAttribute('autocomplete'),
        name: el.name,
        id: el.id,
        placeholder: el.getAttribute('placeholder'),
        ariaLabel: el.getAttribute('aria-label'),
      });
      if (!matches) return;

      lastReported = value;
      void browser.runtime
        .sendMessage({ type: 'REMEMBER_USERNAME', payload: { username: value } })
        .catch(() => {
          /* worker unavailable */
        });
    },
    true
  );
}

function watchForSubmission(): void {
  // Classic form posts.
  document.addEventListener(
    'submit',
    (e) => {
      const form = e.target as HTMLElement;
      if (form && form instanceof HTMLFormElement) captureFrom(form);
    },
    true
  );

  // Single-page logins that never fire submit: a click on anything
  // button-shaped, with the whole document as scope.
  document.addEventListener(
    'click',
    (e) => {
      const el = e.target as HTMLElement | null;
      if (!el) return;
      const btn = el.closest('button, [type="submit"], [role="button"]');
      if (!btn) return;
      captureFrom(document);
    },
    true
  );

  // Enter inside a password field submits on many login forms.
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Enter') return;
      const el = e.target as HTMLElement | null;
      if (el instanceof HTMLInputElement && el.type === 'password' && el.value) {
        captureFrom(el.form || document);
      }
    },
    true
  );
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const frame = assessFrame();
if (frame.isTop || !frame.isCrossOriginFrame) {
  // Only run in the top frame or in a same-origin (first-party) sub-frame.
  loadCredentials();
  watchForUsernameEntry();
  watchForSubmission();
  // A login that navigated lands here: the capture was stored by the previous
  // page's script, and this one raises the prompt.
  checkPendingSave();

  // React to DOM changes instead of polling. SPAs swap login forms in without a
  // navigation, so a mutation-driven rescan is both faster to appear and far
  // cheaper than the previous 2.5s interval running on every open tab.
  const observer = new MutationObserver((records) => {
    let structural = false;
    for (const r of records) {
      if (r.type === 'childList' && (r.addedNodes.length || r.removedNodes.length)) {
        structural = true;
        break;
      }
      if (r.type === 'attributes') {
        structural = true;
        break;
      }
    }
    if (!structural) return;
    scanForLoginFields();
    scheduleReposition();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type', 'style', 'class', 'hidden', 'disabled', 'readonly'],
  });

  // Keep overlay icons glued to their inputs as the page moves underneath them.
  window.addEventListener('scroll', scheduleReposition, { passive: true, capture: true });
  window.addEventListener('resize', scheduleReposition, { passive: true });
  window.addEventListener('focus', loadCredentials);

  // A tab returning from the background may have been locked in the meantime.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) loadCredentials();
  });

  // Never leave a menu floating over a page the user navigated away from.
  window.addEventListener('pagehide', () => {
    closeDropdown();
    closeSavePrompt();
  });
} else {
  // Third-party iframe: autofill deliberately blocked.
  console.debug('[XoraPass] Autofill disabled inside third-party iframe.');
}
