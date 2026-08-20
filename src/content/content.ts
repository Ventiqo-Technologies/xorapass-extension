// XoraPass Content Script (Manifest V3)
//
// Responsibilities are deliberately narrow: detect login fields, ask the
// background worker what may be offered here, and render the overlay. All
// authoritative decisions â€” domain matching, lookalike detection, and the
// release of any actual secret â€” happen in the background worker.
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
import { WEB_APP_URL } from '../utils/config';
import { looksLikeUsername, looksLikeNewPassword } from './fieldHeuristics';
import { generatePassword } from '../utils/passwordGenerator';
import { scanForSecrets, redact, type ScanResult } from '../utils/secretScan';
import { coercePolicy, DEFAULT_POLICY, isAiSite, shouldGuard, type PastePolicy } from '../utils/pasteGuard';
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
  SHIELD_SVG,
  showAiRequestPrompt,
  type OverlayCredential,
  type AiRequestPromptOffer,
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

let pastePolicy: PastePolicy = DEFAULT_POLICY;
let pasteGuardInitialized = false;

interface CaretSnapshot {
  kind: 'text' | 'contenteditable';
  start?: number;
  end?: number;
  range?: Range;
}

// â”€â”€ AI Access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
// The offer background last handed us, held even when there is nothing on the
// page to fill yet -- see renderAiBanner for why.
let pendingAiOffer: AiFillOffer | null = null;
// Guards against firing a second concurrent auto-fill for a session that is
// already mid-flight -- a DOM mutation can retrigger tryShowAiBanner() before
// the first attempt's own cleanup has run (see tryShowAiBanner). Content
// scripts get a fresh JS context on every navigation, so this never needs
// explicit clearing the way the background worker's longer-lived maps do.
const autoFilledSessions = new Set<string>();

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

// XoraPass's own web app is never an autofill target.
//
// The content script has no way to tell a login field apart from any other
// password-type input, so without this it decorates the MASTER PASSWORD field
// on the vault's own sign-in page exactly like any third-party login -- and
// will offer to autofill whatever the user separately saved as a vault entry
// literally named "xorapass.com". That entry (if it exists at all) is not the
// master password: it is unrelated secret being offered into the one field
// that actually derives the encryption key, which is confusing at best and
// teaches the user to treat their master password like any other autofillable
// value at worst -- exactly the habit a zero-knowledge product cannot afford.
//
// So the whole content script disqualifies itself here, once, at the same
// point the third-party-iframe check does -- no icon, no menu, no AI-fill
// banner, no save-prompt capture -- rather than patching each feature
// individually and risking a new one forgetting the exclusion.
const OWN_APP_HOSTNAME = (() => {
  try {
    return new URL(WEB_APP_URL).hostname;
  } catch {
    return '';
  }
})();

function isOwnAppDomain(): boolean {
  return !!OWN_APP_HOSTNAME && window.location.hostname === OWN_APP_HOSTNAME;
}

function escapeHtml(s: string): string {
  return (s || '').replace(/[&<>"]|'/g, (c) => {
    switch (c) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
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
    /* ancestorOrigins unsupported â€“ keep prior assessment */
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
      /* background unavailable â€“ nothing to fill */
    });
}

// Ask background whether an AI-approved fill is available for this page.
function checkAiFill() {
  const hostname = window.location.hostname;
  browser.runtime
    .sendMessage({ type: 'AI_CHECK_TAB', payload: { hostname } })
    .then((response: any) => {
      if (response && response.offer) {
        pendingAiOffer = response.offer as AiFillOffer;
        tryShowAiBanner();
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
    pendingAiOffer = message.payload as AiFillOffer;
    tryShowAiBanner();
  }
  if (message.type === 'AI_REQUEST_AVAILABLE') {
    void handleNewAiRequest(message.payload as AiRequestPromptOffer);
  }
  return undefined;
});

// Shows the in-page Approve/Deny/Adjust dialog background pushed here for a
// brand-new pending AI request, and carries out whatever the user decides.
// Label-only vault-item metadata is fetched fresh each time rather than
// cached, since the vault can change between one request and the next.
async function handleNewAiRequest(offer: AiRequestPromptOffer): Promise<void> {
  const isWorkflow = !!offer.requestKind && offer.requestKind !== 'credential_access';
  const needsBinding = !isWorkflow && offer.credentialType === 'personal' && !offer.vaultEntryId;
  let vaultItems: { id: string; label: string; username: string }[] = [];
  if (needsBinding) {
    const res: any = await browser.runtime.sendMessage({ type: 'AI_LIST_VAULT_ITEMS' }).catch(() => null);
    vaultItems = res?.items || [];
  }

  const decision = await showAiRequestPrompt(offer, vaultItems);
  if (!decision) return; // dismissed -- the badge still covers it

  const payload: Record<string, unknown> = { requestId: offer.id, decision: decision.action };
  if (decision.action === 'approve') {
    if (decision.vaultEntryId) payload.vaultEntryId = decision.vaultEntryId;
    if (decision.grantedScopes) payload.grantedScopes = decision.grantedScopes;
    if (decision.durationSeconds) payload.durationSeconds = decision.durationSeconds;
    if (decision.maxUses) payload.maxUses = decision.maxUses;
  }
  void browser.runtime.sendMessage({ type: 'AI_DECIDE_REQUEST', payload }).catch(() => {});
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
 * paired username field. Safe to call repeatedly â€” `hasIcon` makes it
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

    // Sign-up fields are worth decorating even with an empty vault â€” that is
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
    if (usernameInput && !hasIcon(usernameInput)) {
      fieldPairs.set(usernameInput, usernameInput);
      attachIcon(usernameInput, () => activate(passInput, usernameInput));
      focusActivators.set(usernameInput, passInput);
    }
  }
}

// Attempts to locate the username/email field preceding a password input.
// Searches the enclosing <form> when present, otherwise the whole document, in
// DOM order â€” so it works even when fields live in separate containers.
function findUsernameField(passInput: HTMLInputElement): HTMLInputElement | null {
  const scope: ParentNode = passInput.form || document;
  const inputs = Array.from(scope.querySelectorAll('input')) as HTMLInputElement[];
  const passIdx = inputs.indexOf(passInput);
  if (passIdx === -1) return null;

  let fallbackField: HTMLInputElement | null = null;

  // Scan backwards from the password field for the nearest username-like input.
  for (let i = passIdx - 1; i >= 0; i--) {
    const el = inputs[i];
    if (!isFillable(el)) continue;

    const type = (el.type || 'text').toLowerCase();
    if (type !== 'password' && type !== 'hidden' && type !== 'submit' && type !== 'button' && type !== 'checkbox' && type !== 'radio') {
      if (!fallbackField) {
        fallbackField = el;
      }
    }

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
  return fallbackField;
}

// ---------------------------------------------------------------------------
// Fill flow
// ---------------------------------------------------------------------------

// Opens the credential menu for `passInput`, positioned at `anchor` â€” the field
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

/** Removes the visible banner AND drops the offer -- use for an explicit
 *  dismissal (Not now / Revoke / a fill that actually happened), where a
 *  later DOM change must not resurrect what the user just decided on. */
function removeAiBanner() {
  aiBanner?.remove();
  aiBanner = null;
  pendingAiOffer = null;
}

/** Hides the banner without forgetting the offer -- for "nothing to show
 *  against right now", not a decision. tryShowAiBanner() can bring it back
 *  the moment a fillable field appears (see the MutationObserver hook). */
function hideAiBanner() {
  aiBanner?.remove();
  aiBanner = null;
}

/** Swaps the banner's content for a plain status line, then removes it. Used
 *  for the rare click-time race where a field vanished after the banner was
 *  shown -- a brief, visible reason instead of the banner just disappearing. */
function flashAiBannerMessage(text: string) {
  if (aiBanner) {
    aiBanner.innerHTML = '';
    const msg = document.createElement('span');
    msg.textContent = text;
    Object.assign(msg.style, { flex: '1', color: '#e2e8f0' });
    aiBanner.appendChild(msg);
  }
  setTimeout(removeAiBanner, 1800);
}

/**
 * Shows pendingAiOffer if -- and only if -- the page currently has a fillable
 * password field. Re-run on every structural DOM change (see the
 * MutationObserver below), not just once at offer time.
 *
 * Without this, the banner offered itself on domain match alone: an approved
 * session for "github.com" showed "fill now?" on ANY github.com page, not
 * just the sign-in one. Clicking Fill on, say, the dashboard found no
 * password field and quietly did nothing -- from the user's side, a banner
 * that offers to do something it visibly can't. Gating on the same
 * `isFillable` check handleAiFill uses means the banner is never shown unless
 * that click can actually succeed, and re-running it on mutation means an
 * SPA's login form appearing after the fact still gets offered rather than
 * being missed because the very first check ran too early.
 */
function tryShowAiBanner() {
  if (!pendingAiOffer) return;
  const hasField = Array.from(document.querySelectorAll('input[type="password"]')).some((el) =>
    isFillable(el as HTMLInputElement)
  );
  if (!hasField) {
    hideAiBanner();
    return;
  }

  // Auto-fill an AI-approved session the moment there is something to fill,
  // rather than waiting on a click -- but only on an ordinary page. A warning
  // condition (insecure HTTP, lookalike domain) still renders the normal
  // banner below and waits for Fill, because that click is what the warning
  // dialog is gated on; skipping it would fill straight through the one check
  // meant to catch a lookalike site. Manual autofill (the credential-picker
  // icon a user clicks themselves) is a completely separate code path and is
  // untouched by any of this -- this function only ever runs for a session an
  // AI already asked for and a human already approved.
  if (!autoFilledSessions.has(pendingAiOffer.sessionId) && !hasSecurityWarnings()) {
    autoFilledSessions.add(pendingAiOffer.sessionId);
    renderAiBanner(pendingAiOffer);
    void handleAiFill(pendingAiOffer, false);
    return;
  }

  renderAiBanner(pendingAiOffer);
}

function renderAiBanner(offer: AiFillOffer) {
  pendingAiOffer = offer;
  // Don't stack duplicate banners for the same session, and don't downgrade
  // an already-shown banner for a different offer without replacing it.
  if (aiBanner && aiBanner.dataset.sessionId === offer.sessionId) return;
  hideAiBanner(); // NOT removeAiBanner() -- that would drop the offer we just set above.

  // Colors match the extension's own dark-surface convention exactly (see
  // overlay.ts: .menu's #0f172a/teal-glow shadow, .save-btn-primary's
  // teal→emerald gradient) rather than the unrelated indigo/violet this banner
  // used before — the two UI surfaces read as two different products.
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
    background: 'linear-gradient(90deg, #0f172a, #1e293b)',
    borderBottom: '1px solid rgba(45, 212, 191, 0.3)',
    boxShadow: '0 10px 25px -5px rgba(0,0,0,0.5), 0 8px 24px rgba(45,212,191,0.15)',
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: '13px',
    color: '#e2e8f0',
  });

  // The shield mark used everywhere else in this extension (the autofill icon,
  // the save-prompt header) — not an emoji, so it reads as this product's own
  // UI rather than a generic chat-bot notice.
  const icon = document.createElement('span');
  icon.innerHTML = SHIELD_SVG;
  icon.style.display = 'inline-flex';
  icon.style.verticalAlign = 'middle';
  icon.style.marginRight = '2px';

  const label = document.createElement('span');
  label.style.display = 'inline-flex';
  label.style.alignItems = 'center';
  label.style.gap = '6px';
  label.style.flex = '1';
  label.style.minWidth = '200px';
  label.appendChild(icon);
  const text = document.createElement('span');
  text.innerHTML = `<b>${escapeHtml(offer.aiToolName)}</b> was approved to ${escapeHtml(
    offer.action
  )} on this page — fill now?`;
  label.appendChild(text);
  bar.appendChild(label);

  const mkBtn = (text: string, bg: string, color: string, shadow?: string) => {
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
      ...(shadow ? { boxShadow: shadow } : {}),
    });
    return b;
  };

  // Exactly overlay.ts's .save-btn-primary — the same "primary confirm" button
  // used for Save/Update — so Fill reads as the same action family.
  const fillBtn = mkBtn(
    'Fill',
    'linear-gradient(135deg, #0d9488, #059669)',
    '#ffffff',
    '0 2px 8px rgba(13, 148, 136, 0.24)',
  );
  fillBtn.addEventListener('click', () => void handleAiFill(offer, false));
  bar.appendChild(fillBtn);

  if (offer.grantedScopes.includes('submit')) {
    const submitBtn = mkBtn('Fill & Submit', 'rgba(45, 212, 191, 0.14)', '#5eead4');
    submitBtn.addEventListener('click', () => void handleAiFill(offer, true));
    bar.appendChild(submitBtn);
  }

  const dismissBtn = mkBtn('Not now', 'rgba(255,255,255,0.08)', '#e2e8f0');
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

/** True when this page is insecure HTTP, or looks like a deceptive variant of
 *  a site the user has saved credentials for. Used to decide whether an
 *  AI-approved fill may proceed WITHOUT a click at all (see tryShowAiBanner) --
 *  a warning condition always keeps the manual click, because that click is
 *  the thing that actually shows the warning; skipping it would mean
 *  auto-filling straight through the one check meant to catch a lookalike
 *  domain. */
function hasSecurityWarnings(): boolean {
  return isInsecureContext() || !!lookalikeWarning;
}

// Performs the actual fill for an AI-approved session.
//
// Reached two ways: a click on the banner's Fill button (the ordinary case),
// or automatically from tryShowAiBanner when hasSecurityWarnings() is false --
// an AI-approved session is a decision the user already made when they
// approved it, so on an ordinary page there is nothing further for a click to
// confirm. Either way this function still re-derives and re-checks the
// warnings below itself rather than trusting the caller's earlier check, so a
// warning that appears between that check and this call (a redirect, a DOM
// change) is never silently skipped.
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
  const usernameEl = passEl ? findUsernameField(passEl) : null;

  // The credential to fill is derived server-side from the session record --
  // this only needs to name which session is being used. The response may also
  // carry a fillId: that means an AI is blocked on use_credential waiting to
  // hear whether this actually got applied.
  const response: any = await browser.runtime
    .sendMessage({ type: 'AI_FILL_CONFIRM', payload: { sessionId: offer.sessionId } })
    .catch(() => null);

  if (!response || response.error) {
    removeAiBanner();
    return;
  }

  // Reports the outcome exactly once, and only ever for what really happened.
  // The server treats an unreported claim as failed, so staying silent is the
  // safe direction — never report "filled" on a path that did not type.
  const reportFill = (outcome: 'filled' | 'failed', reason = '') => {
    if (!response.fillId) return;
    browser.runtime
      .sendMessage({ type: 'AI_FILL_RESULT', payload: { fillId: response.fillId, outcome, reason } })
      .catch(() => {});
  };

  // Checked after the confirm call rather than before it, so that a page with
  // nowhere to type still resolves the AI's pending fill instead of leaving it
  // to time out as "no client" — which would misreport a reachable client as an
  // absent one.
  if (!passEl) {
    reportFill('failed', 'no_password_field');
    // The proactive gate in tryShowAiBanner means this should be rare -- the
    // field would have had to disappear in the moment between the banner
    // rendering and this click. Rare is not never, though, and the old
    // behaviour here was to just vanish with no explanation, which is exactly
    // the silent-failure complaint this whole banner rework exists to fix.
    flashAiBannerMessage('No login form found on this page.');
    return;
  }

  if (usernameEl && response.username) autofillField(usernameEl, response.username);
  autofillField(passEl, response.value);
  reportFill('filled');

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
 * frameworks which track the property (React, Vue) observe the change â€” a
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

  // Several filled password boxes are fine when they all hold the same value â€”
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
      // editing, not looking for a credential â€” and because focusin fires once
      // per focus, a menu they dismiss with Escape or an outside click does not
      // reopen while focus stays on the same field.
      if (el.value) return;

      activate(passInput, el);
    },
    true
  );
}

async function refreshPastePolicy(): Promise<void> {
  try {
    const response: any = await browser.runtime.sendMessage({ type: 'AI_PASTE_POLICY' });
    if (response?.policy) {
      pastePolicy = coercePolicy(response.policy);
    }
  } catch {
    pastePolicy = DEFAULT_POLICY;
  }
}


function captureCaret(target: HTMLElement): CaretSnapshot | null {
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    return {
      kind: 'text',
      start: target.selectionStart ?? target.value.length,
      end: target.selectionEnd ?? target.value.length,
    };
  }

  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return null;
  return {
    kind: 'contenteditable',
    range: selection.getRangeAt(0).cloneRange(),
  };
}

function insertTextAtCaret(target: HTMLElement, text: string, caret: CaretSnapshot | null): void {
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    target.focus();
    if (caret?.kind === 'text' && typeof caret.start === 'number' && typeof caret.end === 'number') {
      target.setRangeText(text, caret.start, caret.end, 'end');
    } else {
      const start = target.selectionStart ?? target.value.length;
      const end = target.selectionEnd ?? target.value.length;
      target.setRangeText(text, start, end, 'end');
    }
    target.dispatchEvent(new Event('input', { bubbles: true }));
    return;
  }

  if (caret?.kind === 'contenteditable' && caret.range) {
    target.focus();
    const selection = window.getSelection();
    if (selection) {
      selection.removeAllRanges();
      selection.addRange(caret.range);
      document.execCommand('insertText', false, text);
      return;
    }
  }

  target.focus();
  document.execCommand('insertText', false, text);
}

function getPasteTarget(e: Event): HTMLElement | null {
  const isEditable = (node: HTMLElement) =>
    node instanceof HTMLInputElement ||
    node instanceof HTMLTextAreaElement ||
    node.isContentEditable;

  const path = e.composedPath ? e.composedPath() : [];
  for (const node of path) {
    if (node instanceof HTMLElement) {
      if (isEditable(node)) {
        return node;
      }
    }
  }
  const active = document.activeElement;
  if (active instanceof HTMLElement && isEditable(active)) {
    return active;
  }
  return null;
}

function isEditableElement(el: HTMLElement): boolean {
  return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el.isContentEditable;
}

function resolveEditableTarget(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof HTMLElement)) return null;
  if (isEditableElement(target)) return target;
  const editableAncestor = target.closest('input, textarea, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]');
  return editableAncestor instanceof HTMLElement ? editableAncestor : null;
}

const TYPING_DEBOUNCE_MS = 650;
let typingTimer: ReturnType<typeof setTimeout> | undefined;
const acknowledgedText = new WeakMap<HTMLElement, string>();
const lastPolledText = new WeakMap<HTMLElement, string>();

function readEditableText(el: HTMLElement): string {
  if (!isEditableElement(el)) return '';
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    return el.value || '';
  }
  return el.textContent || el.innerText || '';
}

function setEditableText(el: HTMLElement, text: string): void {
  if (!isEditableElement(el)) return;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
    const setter =
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set ||
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
    if (setter) {
      setter.call(el, text);
    } else {
      el.value = text;
    }
  } else {
    el.textContent = text;
  }
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function acknowledgeCurrent(el: HTMLElement) {
  const text = readEditableText(el);
  if (text) acknowledgedText.set(el, text);
}

async function runTypingGuard(el: HTMLElement, text: string, scan: ScanResult): Promise<void> {
  const hostname = window.location.hostname;

  void browser.runtime
    .sendMessage({
      type: 'AI_PASTE_EVENT',
      payload: {
        hostname,
        types: scan.types,
        action: 'type',
        isAiSite: isAiSite(hostname),
      },
    })
    .catch(() => {});

  const labels = Array.from(new Set(scan.matches.map((m) => m.label)));
  const isBlock = pastePolicy.mode === 'block' || !pastePolicy.allowDismiss;

  if (isBlock) {
    const safeText = acknowledgedText.get(el) || '';
    setEditableText(el, safeText);
    await showConfirmDialog({
      title: 'Secret typing blocked',
      body: [
        `XoraPass detected ${labels.join(', ')} in what you entered.`,
        'Entering secrets into AI tools is blocked by policy.',
        `Preview: ${redact(text, scan.matches).slice(0, 120)}`,
      ],
      confirmLabel: 'OK',
      cancelLabel: '',
    });
    return;
  }

  const proceed = await showConfirmDialog({
    title: 'Secret typing warning',
    body: [
      `XoraPass detected ${labels.join(', ')} in what you entered.`,
      'This text is kept on-device. You can remove it, or keep it if you really want to.',
      `Preview: ${redact(text, scan.matches).slice(0, 120)}`,
    ],
    confirmLabel: 'Keep anyway',
    cancelLabel: 'Remove secret',
  });

  if (!proceed) {
    setEditableText(el, redact(text, scan.matches));
  }
  acknowledgeCurrent(el);
}

function deepActiveElement(): Element | null {
  let el: Element | null = document.activeElement;
  while (el && el.shadowRoot && el.shadowRoot.activeElement) {
    el = el.shadowRoot.activeElement;
  }
  return el;
}

function pollActiveEditable() {
  const hostname = window.location.hostname;
  if (!shouldGuard(pastePolicy, hostname)) return;
  const active = deepActiveElement();
  if (!active || !(active instanceof HTMLElement)) return;
  const el = resolveEditableTarget(active);
  if (!el) return;
  const text = readEditableText(el);
  if (!text) return;
  if (lastPolledText.get(el) === text) return;
  lastPolledText.set(el, text);
  if (acknowledgedText.get(el) === text) return;
  const scan = scanForSecrets(text);
  if (scan.matches.length === 0) return;
  void runTypingGuard(el, text, scan);
}

function onInput(e: Event) {
  const hostname = window.location.hostname;
  if (!shouldGuard(pastePolicy, hostname)) return;
  const rawTarget = (e.composedPath && e.composedPath()[0]) || e.target;
  const target = resolveEditableTarget(rawTarget);
  if (!target) return;
  if (typingTimer) clearTimeout(typingTimer);
  typingTimer = setTimeout(() => {
    const text = readEditableText(target);
    if (!text) return;
    if (acknowledgedText.get(target) === text) return;
    const scan = scanForSecrets(text);
    if (scan.matches.length === 0) return;
    void runTypingGuard(target, text, scan);
  }, TYPING_DEBOUNCE_MS);
}

async function handleSecretPaste(
  target: HTMLElement | null,
  text: string,
  caret: CaretSnapshot | null,
  action: 'paste' | 'drop',
  scan: ScanResult
): Promise<void> {
  const hostname = window.location.hostname;

  void browser.runtime
    .sendMessage({
      type: 'AI_PASTE_EVENT',
      payload: {
        hostname,
        types: scan.types,
        action,
        isAiSite: isAiSite(hostname),
      },
    })
    .catch(() => {});

  const labels = Array.from(new Set(scan.matches.map((m) => m.label)));
  const isBlock = pastePolicy.mode === 'block' || !pastePolicy.allowDismiss;

  if (isBlock) {
    await showConfirmDialog({
      title: 'Secret paste blocked',
      body: [
        `XoraPass detected ${labels.join(', ')} in what you tried to paste.`,
        'Pasting secrets into AI tools is blocked by policy.',
        `Preview: ${redact(text, scan.matches).slice(0, 120)}`,
      ],
      confirmLabel: 'OK',
      cancelLabel: '',
    });
    return;
  }

  const proceed = await showConfirmDialog({
    title: 'Secret paste warning',
    body: [
      `XoraPass detected ${labels.join(', ')} in what you pasted.`,
      'This text is kept on-device. You can cancel, or continue if you really want to paste it here.',
      `Preview: ${redact(text, scan.matches).slice(0, 120)}`,
    ],
    confirmLabel: 'Paste anyway',
    cancelLabel: 'Cancel',
  });

  if (proceed && target) {
    insertTextAtCaret(target, text, caret);
  }
}

function initPasteGuard(): void {
  if (pasteGuardInitialized) return;
  pasteGuardInitialized = true;

  void refreshPastePolicy();

  browser.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.pastePolicy?.newValue) {
      pastePolicy = coercePolicy(changes.pastePolicy.newValue);
    }
  });

  document.addEventListener(
    'paste',
    (e) => {
      const text = e.clipboardData?.getData('text/plain') || e.clipboardData?.getData('text') || '';
      if (!text) return;

      const hostname = window.location.hostname;
      if (!shouldGuard(pastePolicy, hostname)) return;

      const scan = scanForSecrets(text);
      if (scan.matches.length === 0) return;

      e.preventDefault();
      e.stopPropagation();

      const target = getPasteTarget(e);
      const caret = target ? captureCaret(target) : null;
      void handleSecretPaste(target, text, caret, 'paste', scan);
    },
    true
  );

  document.addEventListener(
    'drop',
    (e) => {
      const text = e.dataTransfer?.getData('text/plain') || e.dataTransfer?.getData('text') || '';
      if (!text) return;

      const hostname = window.location.hostname;
      if (!shouldGuard(pastePolicy, hostname)) return;

      const scan = scanForSecrets(text);
      if (scan.matches.length === 0) return;

      e.preventDefault();
      e.stopPropagation();

      const target = getPasteTarget(e);
      const caret = target ? captureCaret(target) : null;
      void handleSecretPaste(target, text, caret, 'drop', scan);
    },
    true
  );

  document.addEventListener('input', onInput, true);
  setInterval(pollActiveEditable, 700);
}

// Bootstrap
// ---------------------------------------------------------------------------

const frame = assessFrame();
if ((frame.isTop || !frame.isCrossOriginFrame) && !isOwnAppDomain()) {
  // Only run in the top frame or in a same-origin (first-party) sub-frame --
  // and never on the vault's own app (see isOwnAppDomain above).
  initPasteGuard();
  loadCredentials();
  checkAiFill();
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
    // An SPA that reveals its login form after the fact (e.g. a "Sign in"
    // click that swaps in a password field with no navigation) would
    // otherwise never get offered: the original checkAiFill() ran before the
    // field existed. This retries the held offer against the page as it is
    // now, and is a no-op whenever there is nothing pending.
    tryShowAiBanner();
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
} else if (isOwnAppDomain()) {
  console.debug('[XoraPass] Autofill disabled on the XoraPass app itself.');
} else {
  // Third-party iframe: autofill deliberately blocked, and so is AI-approved
  // fill -- the same framing attack this guard exists for applies equally.
  console.debug('[XoraPass] Autofill disabled inside third-party iframe.');
}


