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
//
// It also runs the SECRET PASTE GUARD: when the user pastes (or drops) text
// containing a detectable secret into an AI prompt, the paste is intercepted
// and a warning is shown. All detection is on-device -- the pasted text is
// never sent anywhere to be scanned.
import browser from 'webextension-polyfill';
import { scanForSecrets, redact, ScanResult } from '../utils/secretScan';
import { coercePolicy, DEFAULT_POLICY, shouldGuard, isAiSite, PastePolicy } from '../utils/pasteGuard';
import { looksLikeUsername, looksLikeNewPassword } from './fieldHeuristics';
import { generatePassword } from '../utils/passwordGenerator';
import {
  attachIcon,
  hasIcon,
  openDropdown,
  closeDropdown,
  isDropdownOpen,
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

/** Password field -> whether it is choosing a new password rather than entering one. */
const newPasswordFields = new WeakMap<HTMLInputElement, boolean>();

/**
 * Any decorated field (username or password) -> the password field its menu
 * should act on. Focusing a mapped field opens that menu, the way 1Password and
 * Bitwarden surface logins the moment a field is focused rather than making the
 * user find and click a small icon.
 */
const focusActivators = new WeakMap<HTMLInputElement, HTMLInputElement>();

// ── AI Access ────────────────────────────────────────────────────────────────
// This page's part of the AI-credential-firewall story: once a human has
// approved an AI's request elsewhere (the web app, the desktop console),
// XoraPass mints a scoped, time-bound session. This banner is how that
// authorization actually becomes a fill on the page -- distinct from, and
// requiring its own explicit click on top of, the manual autofill button
// above. No fill ever happens without this page-level click, no matter how
// many approvals happened upstream.
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

let aiBanner: HTMLElement | null = null;

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

      // Always scan: with no saved credentials there is nothing to fill, but a
      // sign-up field still gets an icon so a password can be generated.
      clearAll();
      scanForLoginFields();
    })
    .catch(() => {
      /* background unavailable – nothing to fill */
    });
}

// Ask background whether an AI-approved fill is available for this page.
function checkAiFill() {
  const hostname = window.location.hostname;
  browser.runtime
    .sendMessage({ type: 'AI_CHECK_TAB', payload: { hostname } })
    .then((response: any) => {
      if (response && response.offer) {
        renderAiBanner(response.offer as AiFillOffer);
      } else {
        removeAiBanner();
      }
    })
    .catch(() => {
      /* background unavailable */
    });
}

// Background pushes this when it notices a new session on tab switch,
// navigation, or its once-a-minute backstop.
browser.runtime.onMessage.addListener((message: any) => {
  if (!message || typeof message.type !== 'string') return undefined;
  if (message.type === 'AI_FILL_AVAILABLE') {
    renderAiBanner(message.payload as AiFillOffer);
  }
  return undefined;
});

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
  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[];

  const visible = passwordInputs.filter(isFillable);
  const hasSibling = visible.length > 1;

  for (const passInput of visible) {
    const isNew = looksLikeNewPassword(
      {
        autocomplete: passInput.getAttribute('autocomplete'),
        name: passInput.name,
        id: passInput.id,
        placeholder: passInput.getAttribute('placeholder'),
        ariaLabel: passInput.getAttribute('aria-label'),
      },
      hasSibling
    );

    // Sign-up fields are worth decorating even with an empty vault — that is
    // exactly when there is nothing to fill but a password to generate.
    if (!isNew && activeCredentials.length === 0) continue;
    if (hasIcon(passInput)) continue;

    newPasswordFields.set(passInput, isNew);

    const usernameInput = findUsernameField(passInput);
    fieldPairs.set(passInput, usernameInput);

    // Offer autofill on the password field, and on the username field when one
    // was found. This keeps autofill working on pages that don't wrap inputs in
    // a <form> or that split username/password across containers.
    attachIcon(passInput, () => activate(passInput, passInput));
    focusActivators.set(passInput, passInput);
    if (usernameInput && !hasIcon(usernameInput) && activeCredentials.length > 0) {
      fieldPairs.set(usernameInput, usernameInput);
      attachIcon(usernameInput, () => activate(passInput, usernameInput));
      focusActivators.set(usernameInput, passInput);
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

// Opens the credential menu for `passInput`, positioned at `anchor` — the field
// the user actually clicked or focused, so the menu appears where they are
// looking. On a sign-up field the menu leads with a generated password.
function activate(passInput: HTMLInputElement, anchor: HTMLInputElement): void {
  const isNew = newPasswordFields.get(passInput) === true;

  openDropdown(anchor, {
    credentials: activeCredentials,
    warning: lookalikeWarning
      ? `This site resembles "${lookalikeWarning.target}". Verify the address before filling.`
      : null,
    onPick: (id) => void handlePick(id, passInput),
    suggestion: isNew
      ? {
          password: generatePassword(),
          onRegenerate: () => generatePassword(),
          onUse: (pw) => applyGeneratedPassword(passInput, pw),
        }
      : undefined,
  });
}

/**
 * Fills a generated password into the field and any confirm box beside it.
 * Filling the confirm field matters: leaving it empty means the user has to
 * retype a 20-character random string by hand.
 */
function applyGeneratedPassword(passInput: HTMLInputElement, password: string): void {
  autofillField(passInput, password);

  const others = (Array.from(
    document.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[]).filter((p) => p !== passInput && isFillable(p) && !p.value);

  for (const other of others) {
    const isNew = looksLikeNewPassword(
      {
        autocomplete: other.getAttribute('autocomplete'),
        name: other.name,
        id: other.id,
        placeholder: other.getAttribute('placeholder'),
        ariaLabel: other.getAttribute('aria-label'),
      },
      true
    );
    if (isNew) autofillField(other, password);
  }
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

// ---------------------------------------------------------------------------
// AI Access banner
// ---------------------------------------------------------------------------

function removeAiBanner() {
  aiBanner?.remove();
  aiBanner = null;
}

function renderAiBanner(offer: AiFillOffer) {
  // Don't stack duplicate banners for the same session, and don't downgrade
  // an already-shown banner for a different offer without replacing it.
  if (aiBanner && aiBanner.dataset.sessionId === offer.sessionId) return;
  removeAiBanner();

  const bar = document.createElement('div');
  bar.dataset.sessionId = offer.sessionId;
  Object.assign(bar.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '10px',
    padding: '10px 16px',
    background: 'linear-gradient(90deg, #312e81, #3730a3)',
    borderBottom: '1px solid rgba(129, 140, 248, 0.4)',
    boxShadow: '0 4px 20px rgba(49, 46, 129, 0.4)',
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: '13px',
    color: '#e0e7ff',
  });

  const label = document.createElement('span');
  label.innerHTML = `🤖 <b>${escapeHtml(offer.aiToolName)}</b> was approved to ${escapeHtml(
    offer.action
  )} on this page — fill now?`;
  label.style.flex = '1';
  label.style.minWidth = '200px';
  bar.appendChild(label);

  const mkBtn = (text: string, bg: string, color: string) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.innerText = text;
    Object.assign(b.style, {
      padding: '6px 14px',
      fontSize: '12px',
      fontWeight: '700',
      color,
      background: bg,
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
      fontSize: '12px',
      color: '#e2e8f0',
      borderBottom: '1px solid rgba(255, 255, 255, 0.03)',
      transition: 'background-color 0.15s, color 0.15s',
      display: 'block',
    });

    item.addEventListener('mouseover', () => {
      item.style.backgroundColor = 'rgba(0, 210, 255, 0.08)';
      item.style.color = '#00D2FF';
    });
    item.addEventListener('mouseout', () => {
      item.style.backgroundColor = 'transparent';
      item.style.color = '#e2e8f0';
    });

    item.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeAllDropdowns();

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

// ---------------------------------------------------------------------------
// AI Access banner
// ---------------------------------------------------------------------------

function removeAiBanner() {
  aiBanner?.remove();
  aiBanner = null;
}

function renderAiBanner(offer: AiFillOffer) {
  // Don't stack duplicate banners for the same session, and don't downgrade
  // an already-shown banner for a different offer without replacing it.
  if (aiBanner && aiBanner.dataset.sessionId === offer.sessionId) return;
  removeAiBanner();

  const bar = document.createElement('div');
  bar.dataset.sessionId = offer.sessionId;
  Object.assign(bar.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '10px',
    padding: '10px 16px',
    background: 'linear-gradient(90deg, #312e81, #3730a3)',
    borderBottom: '1px solid rgba(129, 140, 248, 0.4)',
    boxShadow: '0 4px 20px rgba(49, 46, 129, 0.4)',
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: '13px',
    color: '#e0e7ff',
  });

  const label = document.createElement('span');
  label.innerHTML = `🤖 <b>${escapeHtml(offer.aiToolName)}</b> was approved to ${escapeHtml(
    offer.action
  )} on this page — fill now?`;
  label.style.flex = '1';
  label.style.minWidth = '200px';
  bar.appendChild(label);

  const mkBtn = (text: string, bg: string, color: string) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.innerText = text;
    Object.assign(b.style, {
      padding: '6px 14px',
      fontSize: '12px',
      fontWeight: '700',
      color,
      background: bg,
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
    });
    return b;
  };

  const fillBtn = mkBtn('Fill', 'linear-gradient(90deg, #818cf8, #6366f1)', '#0f172a');
  fillBtn.addEventListener('click', () => void handleAiFill(offer, false));
  bar.appendChild(fillBtn);

  if (offer.grantedScopes.includes('submit')) {
    const submitBtn = mkBtn('Fill & Submit', 'rgba(255,255,255,0.15)', '#e0e7ff');
    submitBtn.addEventListener('click', () => void handleAiFill(offer, true));
    bar.appendChild(submitBtn);
  }

  const dismissBtn = mkBtn('Not now', 'rgba(255,255,255,0.08)', '#c7d2fe');
  dismissBtn.addEventListener('click', () => {
    browser.runtime
      .sendMessage({ type: 'AI_FILL_HANDLED', payload: { sessionId: offer.sessionId } })
      .catch(() => {});
    removeAiBanner();
  });
  bar.appendChild(dismissBtn);

  const revokeBtn = mkBtn('Revoke access', 'transparent', '#fca5a5');
  revokeBtn.style.textDecoration = 'underline';
  revokeBtn.addEventListener('click', () => {
    browser.runtime
      .sendMessage({ type: 'AI_REVOKE_SESSION', payload: { sessionId: offer.sessionId } })
      .catch(() => {});
    removeAiBanner();
  });
  bar.appendChild(revokeBtn);

  document.documentElement.appendChild(bar);
  aiBanner = bar;
}

// Performs the actual fill for an AI-approved session, gated by the same
// insecure-context / lookalike-domain checks manual autofill uses, plus the
// explicit click on this banner that got us here.
async function handleAiFill(offer: AiFillOffer, alsoSubmit: boolean) {
  const warnings: string[] = [];
  if (isInsecureContext()) {
    warnings.push('This page is served over insecure HTTP. Data you enter can be intercepted.');
  }
  if (lookalikeWarning) {
    warnings.push(`The address of this page resembles "${lookalikeWarning.target}" but does not match it.`);
  }
  if (warnings.length > 0) {
    const proceed = await showConfirmDialog({
      title: 'Confirm AI-approved autofill',
      body: warnings,
      confirmLabel: 'Fill anyway',
      cancelLabel: 'Cancel',
    });
    if (!proceed) return;
  }

  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
  const passEl = passwordInputs.find(isFillable);
  if (!passEl) {
    removeAiBanner();
    return;
  }
  const usernameEl = findUsernameField(passEl);

  // The credential to fill is derived server-side from the session record --
  // this only needs to name which session is being used.
  const response: any = await browser.runtime
    .sendMessage({ type: 'AI_FILL_CONFIRM', payload: { sessionId: offer.sessionId } })
    .catch(() => null);

  if (!response || response.error) {
    removeAiBanner();
    return;
  }

  if (usernameEl && response.username) autofillField(usernameEl, response.username);
  autofillField(passEl, response.value);

  if (alsoSubmit) {
    const form = passEl.form;
    const submitter =
      form?.querySelector('button[type="submit"], input[type="submit"]') ||
      (form ? null : document.querySelector('button[type="submit"], input[type="submit"]'));
    if (form && typeof form.requestSubmit === 'function') {
      form.requestSubmit(submitter as HTMLElement | undefined);
    } else if (submitter instanceof HTMLElement) {
      submitter.click();
    }
  }

  browser.runtime
    .sendMessage({ type: 'AI_FILL_HANDLED', payload: { sessionId: offer.sessionId } })
    .catch(() => {});
  removeAiBanner();
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

  // Several filled password boxes are fine when they all hold the same value —
  // that is a sign-up form's "password + confirm", and it is a credential worth
  // offering to save. Differing values mean a change-password form, where which
  // one to store is ambiguous, so leave those alone.
  const filledValues = new Set(passwords.filter((p) => p.value).map((p) => p.value));
  if (filledValues.size > 1) return null;

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
        brandLogoUrl: browser.runtime.getURL('xorapass_logo_horizontal.png'),
        onSave: () =>
          browser.runtime.sendMessage({ type: 'SAVE_CREDENTIAL' }).then((r: any) => {
            if (r && r.success) loadCredentials();
            return r || { error: 'no_response' };
          }),
        onDismiss: () => {
          void browser.runtime.sendMessage({ type: 'DISMISS_PENDING_SAVE' });
        },
        onNever: () => {
          void browser.runtime.sendMessage({ type: 'DISMISS_PENDING_SAVE' });
          void browser.runtime.sendMessage({
            type: 'SET_SITE_DISABLED',
            payload: { hostname: pending.hostname, disabled: true },
          });
          clearAll();
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

// Opens the credential menu when a decorated field is focused, so logins are
// offered without the user having to spot and click the icon.
function watchForFocus(): void {
  document.addEventListener(
    'focusin',
    (e) => {
      const el = e.target;
      if (!(el instanceof HTMLInputElement)) return;

      const passInput = focusActivators.get(el);
      if (!passInput) return;
      if (isDropdownOpen()) return;

      // Only auto-open on an empty field. A field with a value means the user is
      // editing, not looking for a credential — and because focusin fires once
      // per focus, a menu they dismiss with Escape or an outside click does not
      // reopen while focus stays on the same field.
      if (el.value) return;

      activate(passInput, el);
    },
    true
  );
}

// ---------------------------------------------------------------------------
// Secret paste guard
// ---------------------------------------------------------------------------

// Cached policy, refreshed from the background on load/focus. Until the real
// policy arrives we use the safe default (warn on AI sites), so a paste in the
// first moments after load is never missed.
let pastePolicy: PastePolicy = DEFAULT_POLICY;
let guardActive = false; // prevents overlapping warning dialogs

function refreshPastePolicy() {
  browser.runtime
    .sendMessage({ type: 'AI_PASTE_POLICY' })
    .then((res: any) => {
      if (res && res.policy) pastePolicy = coercePolicy(res.policy);
    })
    .catch(() => {
      /* keep the current/default policy */
    });
}

// The editable element a paste/drop targets, or null if it's not a text input
// we guard. Password fields are deliberately excluded -- pasting into a login
// password box is a normal action, not a prompt leak.
function guardedEditable(target: EventTarget | null): HTMLElement | null {
  const t = target as HTMLElement | null;
  if (!t) return null;
  if (t instanceof HTMLTextAreaElement) return t;
  if (t instanceof HTMLInputElement) {
    const type = (t.type || 'text').toLowerCase();
    return ['text', 'search', 'url', 'email', 'tel'].includes(type) ? t : null;
  }
  if (t.isContentEditable) return t;
  const ce = t.closest?.('[contenteditable=""],[contenteditable="true"]');
  return (ce as HTMLElement) || null;
}

// The caret position captured at paste time, so text can be inserted at the
// right spot even after the async warning dialog stole focus.
interface CaretSnapshot {
  inputRange?: { start: number; end: number };
  domRange?: Range;
}

function captureCaret(el: HTMLElement): CaretSnapshot {
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    return { inputRange: { start: el.selectionStart ?? el.value.length, end: el.selectionEnd ?? el.value.length } };
  }
  const sel = window.getSelection();
  return sel && sel.rangeCount ? { domRange: sel.getRangeAt(0).cloneRange() } : {};
}

// Insert text at the captured caret of an input/textarea/contenteditable,
// undo-friendly where the platform supports it.
function insertTextAtCaret(el: HTMLElement, text: string, caret: CaretSnapshot) {
  el.focus();
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    const start = caret.inputRange?.start ?? el.selectionStart ?? el.value.length;
    const end = caret.inputRange?.end ?? el.selectionEnd ?? el.value.length;
    el.setRangeText(text, start, end, 'end');
    el.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }
  // contenteditable: restore the saved range before inserting.
  const sel = window.getSelection();
  if (caret.domRange && sel) {
    sel.removeAllRanges();
    sel.addRange(caret.domRange);
  }
  const inserted = document.execCommand && document.execCommand('insertText', false, text);
  if (!inserted && sel && sel.rangeCount) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

type PasteChoice = 'cancel' | 'redact' | 'save' | 'paste';

// The warning dialog. Lists what was detected (masked, never the full value)
// and offers the policy-appropriate actions.
function showPasteWarningDialog(scan: ScanResult, policy: PastePolicy): Promise<PasteChoice> {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    Object.assign(backdrop.style, {
      position: 'fixed',
      inset: '0',
      backgroundColor: 'rgba(2, 6, 23, 0.65)',
      backdropFilter: 'blur(2px)',
      zIndex: '2147483647',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Inter, system-ui, sans-serif',
    });

    const modal = document.createElement('div');
    Object.assign(modal.style, {
      width: '380px',
      maxWidth: '92vw',
      backgroundColor: '#0f172a',
      border: '1px solid rgba(244, 63, 94, 0.35)',
      borderRadius: '12px',
      boxShadow: '0 24px 48px -12px rgba(0, 0, 0, 0.75)',
      overflow: 'hidden',
      color: '#e2e8f0',
    });

    const title = document.createElement('div');
    title.innerText = '⚠  Secret detected before paste';
    Object.assign(title.style, {
      padding: '14px 16px',
      fontSize: '13px',
      fontWeight: '700',
      color: '#fca5a5',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
      backgroundColor: '#020617',
    });
    modal.appendChild(title);

    const body = document.createElement('div');
    Object.assign(body.style, { padding: '14px 16px', fontSize: '12px', lineHeight: '1.5' });

    const intro = document.createElement('p');
    intro.style.margin = '0 0 10px 0';
    intro.innerText =
      policy.mode === 'block'
        ? 'Your organization blocks pasting secrets into AI tools. This looks like:'
        : 'You’re about to paste what looks like a secret into an AI tool. This could expose it to the model, its logs, or its provider. Detected:';
    body.appendChild(intro);

    // Distinct detected types, with one masked example each.
    const seen = new Set<string>();
    const list = document.createElement('div');
    Object.assign(list.style, { display: 'flex', flexDirection: 'column', gap: '4px', marginBottom: '4px' });
    for (const m of scan.matches) {
      if (seen.has(m.type)) continue;
      seen.add(m.type);
      const row = document.createElement('div');
      Object.assign(row.style, {
        display: 'flex',
        justifyContent: 'space-between',
        gap: '10px',
        padding: '5px 8px',
        background: 'rgba(244,63,94,0.08)',
        border: '1px solid rgba(244,63,94,0.18)',
        borderRadius: '6px',
      });
      const name = document.createElement('span');
      name.style.fontWeight = '600';
      name.innerText = m.label;
      const prev = document.createElement('span');
      Object.assign(prev.style, { fontFamily: 'monospace', color: '#94a3b8' });
      prev.innerText = m.preview;
      row.appendChild(name);
      row.appendChild(prev);
      list.appendChild(row);
    }
    body.appendChild(list);
    modal.appendChild(body);

    const actions = document.createElement('div');
    Object.assign(actions.style, {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '8px',
      padding: '0 16px 16px 16px',
      justifyContent: 'flex-end',
    });

    const cleanup = (choice: PasteChoice) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(choice);
    };

    const mkBtn = (text: string, choice: PasteChoice, style: Partial<CSSStyleDeclaration>) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.innerText = text;
      Object.assign(
        b.style,
        {
          padding: '8px 12px',
          fontSize: '12px',
          fontWeight: '700',
          borderRadius: '8px',
          cursor: 'pointer',
          border: '1px solid transparent',
        },
        style
      );
      b.addEventListener('click', () => cleanup(choice));
      return b;
    };

    // Cancel (safe default), Redact & paste, Save to vault, and -- only when the
    // policy allows dismissing -- Paste anyway.
    actions.appendChild(
      mkBtn('Cancel paste', 'cancel', {
        color: '#e2e8f0',
        background: 'rgba(255,255,255,0.06)',
        borderColor: 'rgba(255,255,255,0.1)',
      })
    );
    actions.appendChild(
      mkBtn('Save to vault', 'save', {
        color: '#22d3ee',
        background: 'rgba(34,211,238,0.1)',
        borderColor: 'rgba(34,211,238,0.25)',
      })
    );
    actions.appendChild(
      mkBtn('Redact & paste', 'redact', {
        color: '#020617',
        background: 'linear-gradient(90deg, #2dd4bf, #22d3ee)',
      })
    );
    if (policy.mode !== 'block' && policy.allowDismiss) {
      actions.appendChild(
        mkBtn('Paste anyway', 'paste', {
          color: '#fca5a5',
          background: 'transparent',
          borderColor: 'rgba(244,63,94,0.4)',
        })
      );
    }
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup('cancel');
    });
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') cleanup('cancel');
    };
    document.addEventListener('keydown', onKey);
    document.body.appendChild(backdrop);
    confirmBtn.focus();
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function autofillField(el: HTMLInputElement, value: string) {
  el.value = value;
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

  // Several filled password boxes are fine when they all hold the same value —
  // that is a sign-up form's "password + confirm", and it is a credential worth
  // offering to save. Differing values mean a change-password form, where which
  // one to store is ambiguous, so leave those alone.
  const filledValues = new Set(passwords.filter((p) => p.value).map((p) => p.value));
  if (filledValues.size > 1) return null;

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

function removeAllOverlays() {
  overlayElements = [];
  scannedForms.clear();
}

function closeAllDropdowns() {
  document.querySelectorAll('.xorapass-dropdown').forEach((d) => d.remove());
  document.removeEventListener('click', closeDropdownsOnOutsideClick);
}

function onDrop(e: DragEvent) {
  if (guardActive) {
    e.preventDefault();
    return;
  }
  if (!shouldGuard(pastePolicy, window.location.hostname)) return;
  const el = guardedEditable(e.target);
  if (!el) return;
  const text = e.dataTransfer?.getData('text/plain') ?? '';
  if (!text) return;
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  const caret = captureCaret(el);
  e.preventDefault();
  e.stopPropagation();
  void runPasteGuard(text, el, scan, caret);
}

function initPasteGuard() {
  refreshPastePolicy();
  window.addEventListener('focus', refreshPastePolicy);
  // Capture phase so we intercept before the page's own paste handling.
  document.addEventListener('paste', onPaste, true);
  document.addEventListener('drop', onDrop, true);
}

// ---------------------------------------------------------------------------
// Secret paste guard
// ---------------------------------------------------------------------------

// Cached policy, refreshed from the background on load/focus. Until the real
// policy arrives we use the safe default (warn on AI sites), so a paste in the
// first moments after load is never missed.
let pastePolicy: PastePolicy = DEFAULT_POLICY;
let guardActive = false; // prevents overlapping warning dialogs

function refreshPastePolicy() {
  browser.runtime
    .sendMessage({ type: 'AI_PASTE_POLICY' })
    .then((res: any) => {
      if (res && res.policy) pastePolicy = coercePolicy(res.policy);
    })
    .catch(() => {
      /* keep the current/default policy */
    });
}

// The editable element a paste/drop targets, or null if it's not a text input
// we guard. Password fields are deliberately excluded -- pasting into a login
// password box is a normal action, not a prompt leak.
function guardedEditable(target: EventTarget | null): HTMLElement | null {
  const t = target as HTMLElement | null;
  if (!t) return null;
  if (t instanceof HTMLTextAreaElement) return t;
  if (t instanceof HTMLInputElement) {
    const type = (t.type || 'text').toLowerCase();
    return ['text', 'search', 'url', 'email', 'tel'].includes(type) ? t : null;
  }
  if (t.isContentEditable) return t;
  const ce = t.closest?.('[contenteditable=""],[contenteditable="true"]');
  return (ce as HTMLElement) || null;
}

// The caret position captured at paste time, so text can be inserted at the
// right spot even after the async warning dialog stole focus.
interface CaretSnapshot {
  inputRange?: { start: number; end: number };
  domRange?: Range;
}

function captureCaret(el: HTMLElement): CaretSnapshot {
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    return { inputRange: { start: el.selectionStart ?? el.value.length, end: el.selectionEnd ?? el.value.length } };
  }
  const sel = window.getSelection();
  return sel && sel.rangeCount ? { domRange: sel.getRangeAt(0).cloneRange() } : {};
}

// Insert text at the captured caret of an input/textarea/contenteditable,
// undo-friendly where the platform supports it.
function insertTextAtCaret(el: HTMLElement, text: string, caret: CaretSnapshot) {
  el.focus();
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    const start = caret.inputRange?.start ?? el.selectionStart ?? el.value.length;
    const end = caret.inputRange?.end ?? el.selectionEnd ?? el.value.length;
    el.setRangeText(text, start, end, 'end');
    el.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }
  // contenteditable: restore the saved range before inserting.
  const sel = window.getSelection();
  if (caret.domRange && sel) {
    sel.removeAllRanges();
    sel.addRange(caret.domRange);
  }
  const inserted = document.execCommand && document.execCommand('insertText', false, text);
  if (!inserted && sel && sel.rangeCount) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

// Reads the full current text of a guarded editable (used by the typing guard,
// which must scan what's already in the field rather than an incoming payload).
function readEditableText(el: HTMLElement): string {
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) return el.value;
  return el.innerText ?? el.textContent ?? '';
}

// Replaces the entire content of a guarded editable and moves the caret to the
// end. Used to remove/redact a typed secret in place.
function setEditableText(el: HTMLElement, text: string) {
  el.focus();
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    el.value = text;
    try {
      el.setSelectionRange(text.length, text.length);
    } catch {
      /* some input types disallow selection ranges */
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }
  // contenteditable: select the whole field and replace via execCommand, which
  // rich editors (ProseMirror/Lexical) intercept and apply to their own model —
  // directly setting textContent would desync or be overwritten by them.
  const sel = window.getSelection();
  if (sel) {
    const range = document.createRange();
    range.selectNodeContents(el);
    sel.removeAllRanges();
    sel.addRange(range);
  }
  const replaced = document.execCommand && document.execCommand('insertText', false, text);
  if (!replaced) {
    el.textContent = text; // fallback for editors without execCommand support
    if (sel) {
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

type PasteChoice = 'cancel' | 'redact' | 'save' | 'paste';

// The warning dialog. Lists what was detected (masked, never the full value)
// and offers the policy-appropriate actions. `source` tailors the wording and
// button labels for a paste/drop vs. a secret that was typed in.
function showPasteWarningDialog(
  scan: ScanResult,
  policy: PastePolicy,
  source: 'paste' | 'typing' = 'paste'
): Promise<PasteChoice> {
  const typing = source === 'typing';
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    Object.assign(backdrop.style, {
      position: 'fixed',
      inset: '0',
      backgroundColor: 'rgba(2, 6, 23, 0.65)',
      backdropFilter: 'blur(2px)',
      zIndex: '2147483647',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Inter, system-ui, sans-serif',
    });

    const modal = document.createElement('div');
    Object.assign(modal.style, {
      width: '380px',
      maxWidth: '92vw',
      backgroundColor: '#0f172a',
      border: '1px solid rgba(244, 63, 94, 0.35)',
      borderRadius: '12px',
      boxShadow: '0 24px 48px -12px rgba(0, 0, 0, 0.75)',
      overflow: 'hidden',
      color: '#e2e8f0',
    });

    const title = document.createElement('div');
    title.innerText = typing ? '⚠  Secret detected in your input' : '⚠  Secret detected before paste';
    Object.assign(title.style, {
      padding: '14px 16px',
      fontSize: '13px',
      fontWeight: '700',
      color: '#fca5a5',
      borderBottom: '1px solid rgba(255,255,255,0.06)',
      backgroundColor: '#020617',
    });
    modal.appendChild(title);

    const body = document.createElement('div');
    Object.assign(body.style, { padding: '14px 16px', fontSize: '12px', lineHeight: '1.5' });

    const intro = document.createElement('p');
    intro.style.margin = '0 0 10px 0';
    if (policy.mode === 'block') {
      intro.innerText = typing
        ? 'Your organization blocks entering secrets into AI tools. This looks like:'
        : 'Your organization blocks pasting secrets into AI tools. This looks like:';
    } else {
      intro.innerText = typing
        ? 'You’ve typed what looks like a secret into an AI tool. This could expose it to the model, its logs, or its provider. Detected:'
        : 'You’re about to paste what looks like a secret into an AI tool. This could expose it to the model, its logs, or its provider. Detected:';
    }
    body.appendChild(intro);

    // Distinct detected types, with one masked example each.
    const seen = new Set<string>();
    const list = document.createElement('div');
    Object.assign(list.style, { display: 'flex', flexDirection: 'column', gap: '4px', marginBottom: '4px' });
    for (const m of scan.matches) {
      if (seen.has(m.type)) continue;
      seen.add(m.type);
      const row = document.createElement('div');
      Object.assign(row.style, {
        display: 'flex',
        justifyContent: 'space-between',
        gap: '10px',
        padding: '5px 8px',
        background: 'rgba(244,63,94,0.08)',
        border: '1px solid rgba(244,63,94,0.18)',
        borderRadius: '6px',
      });
      const name = document.createElement('span');
      name.style.fontWeight = '600';
      name.innerText = m.label;
      const prev = document.createElement('span');
      Object.assign(prev.style, { fontFamily: 'monospace', color: '#94a3b8' });
      prev.innerText = m.preview;
      row.appendChild(name);
      row.appendChild(prev);
      list.appendChild(row);
    }
    body.appendChild(list);
    modal.appendChild(body);

    const actions = document.createElement('div');
    Object.assign(actions.style, {
      display: 'flex',
      flexWrap: 'wrap',
      gap: '8px',
      padding: '0 16px 16px 16px',
      justifyContent: 'flex-end',
    });

    const cleanup = (choice: PasteChoice) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(choice);
    };

    const mkBtn = (text: string, choice: PasteChoice, style: Partial<CSSStyleDeclaration>) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.innerText = text;
      Object.assign(
        b.style,
        {
          padding: '8px 12px',
          fontSize: '12px',
          fontWeight: '700',
          borderRadius: '8px',
          cursor: 'pointer',
          border: '1px solid transparent',
        },
        style
      );
      b.addEventListener('click', () => cleanup(choice));
      return b;
    };

    // Cancel/remove (safe default), Redact, Save to vault, and -- only when the
    // policy allows dismissing -- keep it. Labels differ for paste vs. typing:
    // a paste can be prevented outright, whereas typed text is removed/redacted
    // from the field after the fact.
    actions.appendChild(
      mkBtn(typing ? 'Remove secret' : 'Cancel paste', 'cancel', {
        color: '#e2e8f0',
        background: 'rgba(255,255,255,0.06)',
        borderColor: 'rgba(255,255,255,0.1)',
      })
    );
    actions.appendChild(
      mkBtn('Save to vault', 'save', {
        color: '#22d3ee',
        background: 'rgba(34,211,238,0.1)',
        borderColor: 'rgba(34,211,238,0.25)',
      })
    );
    actions.appendChild(
      mkBtn(typing ? 'Redact' : 'Redact & paste', 'redact', {
        color: '#020617',
        background: 'linear-gradient(90deg, #2dd4bf, #22d3ee)',
      })
    );
    if (policy.mode !== 'block' && policy.allowDismiss) {
      actions.appendChild(
        mkBtn(typing ? 'Keep anyway' : 'Paste anyway', 'paste', {
          color: '#fca5a5',
          background: 'transparent',
          borderColor: 'rgba(244,63,94,0.4)',
        })
      );
    }
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup('cancel');
    });
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') cleanup('cancel');
    };
    document.addEventListener('keydown', onKey);
    document.body.appendChild(backdrop);
  });
}

// A tiny transient toast, e.g. after saving to vault.
function showToast(message: string, tone: 'ok' | 'err' = 'ok') {
  const t = document.createElement('div');
  Object.assign(t.style, {
    position: 'fixed',
    bottom: '20px',
    left: '50%',
    transform: 'translateX(-50%)',
    zIndex: '2147483647',
    padding: '10px 16px',
    borderRadius: '8px',
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: '12px',
    fontWeight: '600',
    color: tone === 'ok' ? '#022c22' : '#450a0a',
    background: tone === 'ok' ? 'linear-gradient(90deg, #2dd4bf, #22d3ee)' : '#fca5a5',
    boxShadow: '0 8px 20px rgba(0,0,0,0.4)',
  });
  t.innerText = message;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2600);
}

function reportPasteEvent(types: string[], action: string) {
  browser.runtime
    .sendMessage({
      type: 'AI_PASTE_EVENT',
      // Secret-free: only the detected type NAMES, the host, and the action.
      payload: { hostname: window.location.hostname, types, action, isAiSite: isAiSite(window.location.hostname) },
    })
    .catch(() => {});
}

// Core handler shared by paste and drop. `text` is the incoming content, `el`
// the editable target, `commit` inserts accepted text. Returns true when it
// intercepted (the caller must have already prevented the default).
async function runPasteGuard(text: string, el: HTMLElement, scan: ScanResult, caret: CaretSnapshot) {
  guardActive = true;
  try {
    const choice = await showPasteWarningDialog(scan, pastePolicy);
    switch (choice) {
      case 'redact': {
        insertTextAtCaret(el, redact(text, scan.matches), caret);
        reportPasteEvent(scan.types, 'redacted');
        break;
      }
      case 'save': {
        const label = `Secret from ${window.location.hostname}`;
        const res: any = await browser.runtime
          .sendMessage({ type: 'AI_SAVE_SECRET', payload: { value: text, label, url: window.location.origin } })
          .catch(() => ({ error: 'Could not reach XoraPass.' }));
        if (res && res.success) {
          showToast('Saved to your vault — not pasted.');
          reportPasteEvent(scan.types, 'saved_to_vault');
        } else {
          showToast(res?.error || 'Could not save to vault.', 'err');
          reportPasteEvent(scan.types, 'save_failed');
        }
        break;
      }
      case 'paste': {
        insertTextAtCaret(el, text, caret);
        reportPasteEvent(scan.types, 'pasted_anyway');
        break;
      }
      case 'cancel':
      default:
        reportPasteEvent(scan.types, pastePolicy.mode === 'block' ? 'blocked' : 'cancelled');
        break;
    }
  } finally {
    guardActive = false;
    // The user consciously acted on this content; record it so the typing guard
    // doesn't immediately re-warn about the same text (e.g. after "paste anyway").
    acknowledgeCurrent(el);
  }
}

// ---------------------------------------------------------------------------
// Typing guard: the same secret detection, but for secrets TYPED into an AI
// input rather than pasted. Because the text is already in the field, we scan
// the field's current content (debounced) and, on a hit, offer to remove or
// redact it in place instead of preventing an incoming paste.
// ---------------------------------------------------------------------------

const TYPING_DEBOUNCE_MS = 650;
let typingTimer: ReturnType<typeof setTimeout> | undefined;
// Per-element text the user explicitly chose to keep, so we don't nag on every
// subsequent keystroke for content they've already decided about.
const acknowledgedText = new WeakMap<HTMLElement, string>();

function acknowledgeCurrent(el: HTMLElement) {
  acknowledgedText.set(el, readEditableText(el));
}

function onInput(e: Event) {
  if (guardActive) return;
  if (!shouldGuard(pastePolicy, window.location.hostname)) return;
  const el = guardedEditable(e.target);
  if (!el) return;
  if (typingTimer) clearTimeout(typingTimer);
  typingTimer = setTimeout(() => scanTypedInput(el), TYPING_DEBOUNCE_MS);
}

function scanTypedInput(el: HTMLElement) {
  if (guardActive) return;
  if (!el.isConnected) return; // element was removed while we waited
  const text = readEditableText(el);
  if (!text) return;
  if (acknowledgedText.get(el) === text) return; // already decided about this exact text
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  void runTypingGuard(el, text, scan);
}

async function runTypingGuard(el: HTMLElement, text: string, scan: ScanResult) {
  guardActive = true;
  try {
    const choice = await showPasteWarningDialog(scan, pastePolicy, 'typing');
    switch (choice) {
      // For typed input, both "Remove secret" and "Redact" strip the secret from
      // the field; only the audit label differs.
      case 'cancel':
      case 'redact': {
        setEditableText(el, redact(text, scan.matches));
        reportPasteEvent(scan.types, choice === 'redact' ? 'typed_redacted' : 'typed_removed');
        break;
      }
      case 'save': {
        const label = `Secret from ${window.location.hostname}`;
        const res: any = await browser.runtime
          .sendMessage({ type: 'AI_SAVE_SECRET', payload: { value: text, label, url: window.location.origin } })
          .catch(() => ({ error: 'Could not reach XoraPass.' }));
        if (res && res.success) {
          setEditableText(el, redact(text, scan.matches));
          showToast('Saved to your vault — removed from the field.');
          reportPasteEvent(scan.types, 'typed_saved_to_vault');
        } else {
          showToast(res?.error || 'Could not save to vault.', 'err');
          reportPasteEvent(scan.types, 'typed_save_failed');
        }
        break;
      }
      case 'paste': {
        // "Keep anyway" — leave the text, but remember it so we don't re-warn.
        reportPasteEvent(scan.types, 'typed_kept');
        break;
      }
    }
  } finally {
    guardActive = false;
    acknowledgeCurrent(el);
  }
}

// Polling fallback. Rich editors (ChatGPT's ProseMirror, Claude, Slack, etc.)
// manage their own DOM and don't always surface a bubbling `input` event a
// document-level listener can see. Rather than depend on each editor's event
// model, we also poll the currently-focused editable and scan it when its text
// changes. This is what makes typed-secret detection work on those editors.
const lastPolledText = new WeakMap<HTMLElement, string>();

// The truly-focused element, descending through open shadow roots (some editors
// nest their editable inside a shadow tree).
function deepActiveElement(): Element | null {
  let el: Element | null = document.activeElement;
  while (el && el.shadowRoot && el.shadowRoot.activeElement) {
    el = el.shadowRoot.activeElement;
  }
  return el;
}

function pollActiveEditable() {
  if (guardActive) return;
  if (!shouldGuard(pastePolicy, window.location.hostname)) return;
  const el = guardedEditable(deepActiveElement());
  if (!el) return;
  const text = readEditableText(el);
  if (!text) return;
  if (lastPolledText.get(el) === text) return; // unchanged since last poll
  lastPolledText.set(el, text);
  if (acknowledgedText.get(el) === text) return; // already decided about this text
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  void runTypingGuard(el, text, scan);
}

function onPaste(e: ClipboardEvent) {
  if (guardActive) {
    e.preventDefault();
    return;
  }
  if (!shouldGuard(pastePolicy, window.location.hostname)) return;
  const el = guardedEditable(e.target);
  if (!el) return;
  const text = e.clipboardData?.getData('text/plain') ?? '';
  if (!text) return;
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  // Block the default paste synchronously, capture the caret, then decide via
  // the async dialog.
  const caret = captureCaret(el);
  e.preventDefault();
  e.stopPropagation();
  void runPasteGuard(text, el, scan, caret);
}

function onDrop(e: DragEvent) {
  if (guardActive) {
    e.preventDefault();
    return;
  }
  if (!shouldGuard(pastePolicy, window.location.hostname)) return;
  const el = guardedEditable(e.target);
  if (!el) return;
  const text = e.dataTransfer?.getData('text/plain') ?? '';
  if (!text) return;
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  const caret = captureCaret(el);
  e.preventDefault();
  e.stopPropagation();
  void runPasteGuard(text, el, scan, caret);
}

function initPasteGuard() {
  refreshPastePolicy();
  window.addEventListener('focus', refreshPastePolicy);
  // Capture phase so we intercept before the page's own paste handling.
  document.addEventListener('paste', onPaste, true);
  document.addEventListener('drop', onDrop, true);
  // Typed secrets: scan the field's content (debounced) after input. Not capture
  // phase — we react to the value after the keystroke lands, not before.
  document.addEventListener('input', onInput, true);
  // Fallback for rich editors whose input events don't reach us: poll the
  // focused editable and scan it when its text changes.
  setInterval(pollActiveEditable, 700);
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const frame = assessFrame();
if (frame.isTop || !frame.isCrossOriginFrame) {
  // Only run in the top frame or in a same-origin (first-party) sub-frame.
  loadCredentials();
  checkAiFill();
  initPasteGuard();
  watchForUsernameEntry();
  watchForSubmission();
  watchForFocus();
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
  window.addEventListener('focus', () => {
    loadCredentials();
    checkAiFill();
  });

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
  // Third-party iframe: autofill deliberately blocked, and so is AI-approved
  // fill -- the same framing attack this guard exists for applies equally.
  console.debug('[XoraPass] Autofill disabled inside third-party iframe.');
}
