// XoraPass Content Script (Manifest V3)
//
// The authoritative domain matching / lookalike detection happens in the
// background worker; this script enforces the page-context guards (frame
// origin, insecure transport) and gates sensitive fills behind explicit user
// confirmation.
import browser from 'webextension-polyfill';

interface MatchingCredential {
  id: string;
  label: string;
  username: string;
  value: string;
  category: string;
}

let activeCredentials: MatchingCredential[] = [];
let lookalikeWarning: { target: string; reason: string } | null = null;
let scannedForms: Set<HTMLInputElement> = new Set();
let overlayElements: HTMLElement[] = [];

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

// Request matching credentials for the current tab domain.
function loadCredentials() {
  const hostname = window.location.hostname;
  browser.runtime
    .sendMessage({ type: 'GET_MATCHING_CREDENTIALS', payload: { hostname } })
    .then((response: any) => {
      if (!response) return;

      // Respect the per-site disable list.
      if (response.disabled) {
        activeCredentials = [];
        removeAllOverlays();
        return;
      }

      lookalikeWarning = response.lookalike || null;

      if (response.credentials) {
        activeCredentials = response.credentials;
        if (activeCredentials.length > 0) {
          scanForLoginFields();
        }
      }
    })
    .catch(() => {
      /* background unavailable – nothing to fill */
    });
}

// An input is fillable if it's visible and user-editable.
function isFillable(el: HTMLInputElement): boolean {
  if (!el || el.type === 'hidden' || el.disabled || el.readOnly) return false;
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

// Injects autofill overlays into discovered input fields.
function scanForLoginFields() {
  if (activeCredentials.length === 0) return;

  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[];

  passwordInputs.forEach((passInput) => {
    if (scannedForms.has(passInput)) return;
    if (!isFillable(passInput)) return;

    // Locate the username/email field (may be null on unusual layouts).
    const usernameInput = findUsernameField(passInput);

    scannedForms.add(passInput);
    if (usernameInput) scannedForms.add(usernameInput);

    // Always offer autofill on the password field; add the username field too
    // when found. This keeps autofill working on pages that don't wrap inputs in
    // a <form> or place username/password in separate containers.
    injectAutofillIcon(passInput, usernameInput, passInput);
    if (usernameInput) injectAutofillIcon(usernameInput, usernameInput, passInput);
  });
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
    const type = (el.type || '').toLowerCase();
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    const hints = ((el.name || '') + ' ' + (el.id || '')).toLowerCase();
    const looksUsername =
      type === 'email' || type === 'text' || type === 'tel' ||
      ac.includes('username') || ac.includes('email') ||
      /user|email|login|phone/.test(hints);
    if (looksUsername && type !== 'password' && isFillable(el)) {
      return el;
    }
  }
  return null;
}

// Injects the XoraPass icon overlay into a given input field. `usernameEl` may
// be null when the page has no locatable username field (password-only fill).
function injectAutofillIcon(
  iconHost: HTMLInputElement,
  usernameEl: HTMLInputElement | null,
  passEl: HTMLInputElement
) {
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';
  wrapper.style.width = '100%';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'xorapass-autofill-btn';
  button.setAttribute('aria-label', 'XoraPass Autofill');
  button.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `;

  Object.assign(button.style, {
    position: 'absolute',
    right: '8px',
    top: '50%',
    transform: 'translateY(-50%)',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    zIndex: '99999',
    padding: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px',
    transition: 'background-color 0.2s',
  });

  button.addEventListener('mouseover', () => {
    button.style.backgroundColor = 'rgba(255, 255, 255, 0.1)';
  });
  button.addEventListener('mouseout', () => {
    button.style.backgroundColor = 'transparent';
  });

  iconHost.parentNode?.insertBefore(wrapper, iconHost);
  wrapper.appendChild(iconHost);
  wrapper.appendChild(button);

  button.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    openAutofillDropdown(button, usernameEl, passEl);
  });

  overlayElements.push(wrapper);
}

// Renders the auto-fill credential selection menu.
function openAutofillDropdown(
  anchor: HTMLElement,
  usernameEl: HTMLInputElement | null,
  passwordEl: HTMLInputElement
) {
  closeAllDropdowns();

  const dropdown = document.createElement('div');
  dropdown.className = 'xorapass-dropdown';

  Object.assign(dropdown.style, {
    position: 'absolute',
    top: `${anchor.offsetTop + anchor.offsetHeight + 6}px`,
    right: '0',
    width: '240px',
    backgroundColor: '#0f172a',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: '10px',
    boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 24px rgba(45, 212, 191, 0.15)',
    zIndex: '100000',
    overflow: 'hidden',
    fontFamily: 'Inter, system-ui, sans-serif',
  });

  const header = document.createElement('div');
  header.innerText = 'XoraPass Autofill';
  Object.assign(header.style, {
    padding: '8px 12px',
    fontSize: '10px',
    fontWeight: 'bold',
    color: '#2dd4bf',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
    backgroundColor: '#0a1412',
  });
  dropdown.appendChild(header);

  // Surface a lookalike-domain warning banner at the top of the menu.
  if (lookalikeWarning) {
    const banner = document.createElement('div');
    banner.innerText = `⚠ This site resembles "${lookalikeWarning.target}". Verify the address before filling.`;
    Object.assign(banner.style, {
      padding: '8px 12px',
      fontSize: '10px',
      lineHeight: '1.4',
      color: '#fca5a5',
      backgroundColor: 'rgba(220, 38, 38, 0.12)',
      borderBottom: '1px solid rgba(220, 38, 38, 0.25)',
    });
    dropdown.appendChild(banner);
  }

  activeCredentials.forEach((cred) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'xorapass-dropdown-item';
    item.innerHTML = `
      <div style="font-weight: 600; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(cred.label)}</div>
      <div style="font-size: 10px; color: #64748b; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; margin-top: 2px;">${escapeHtml(cred.username)}</div>
    `;

    Object.assign(item.style, {
      width: '100%',
      padding: '10px 12px',
      background: 'none',
      border: 'none',
      cursor: 'pointer',
      fontSize: '12px',
      color: '#e2e8f0',
      borderBottom: '1px solid rgba(255, 255, 255, 0.03)',
      transition: 'background-color 0.15s, color 0.15s',
      display: 'block',
    });

    item.addEventListener('mouseover', () => {
      item.style.backgroundColor = 'rgba(45, 212, 191, 0.08)';
      item.style.color = '#2dd4bf';
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

      if (usernameEl && cred.username) autofillField(usernameEl, cred.username);
      autofillField(passwordEl, cred.value);
    });

    dropdown.appendChild(item);
  });

  anchor.parentElement?.appendChild(dropdown);
  document.addEventListener('click', closeDropdownsOnOutsideClick);
}

// Decides whether a fill needs explicit confirmation, and if so, asks the user.
// Returns true when the fill may proceed.
async function confirmFillIfNeeded(cred: MatchingCredential): Promise<boolean> {
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

// ---------------------------------------------------------------------------
// Confirmation modal
// ---------------------------------------------------------------------------

function showConfirmDialog(opts: {
  title: string;
  body: string[];
  confirmLabel: string;
  cancelLabel: string;
}): Promise<boolean> {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    backdrop.className = 'xorapass-confirm-backdrop';
    Object.assign(backdrop.style, {
      position: 'fixed',
      inset: '0',
      backgroundColor: 'rgba(2, 6, 23, 0.6)',
      backdropFilter: 'blur(2px)',
      zIndex: '2147483646',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Inter, system-ui, sans-serif',
    });

    const modal = document.createElement('div');
    Object.assign(modal.style, {
      width: '340px',
      maxWidth: '90vw',
      backgroundColor: '#0f172a',
      border: '1px solid rgba(255, 255, 255, 0.08)',
      borderRadius: '12px',
      boxShadow: '0 20px 40px -10px rgba(0, 0, 0, 0.7)',
      overflow: 'hidden',
      color: '#e2e8f0',
    });

    const title = document.createElement('div');
    title.innerText = opts.title;
    Object.assign(title.style, {
      padding: '14px 16px',
      fontSize: '13px',
      fontWeight: '700',
      color: '#fca5a5',
      borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
      backgroundColor: '#0a1412',
    });
    modal.appendChild(title);

    const body = document.createElement('div');
    Object.assign(body.style, { padding: '14px 16px', fontSize: '12px', lineHeight: '1.5' });
    opts.body.forEach((line) => {
      const p = document.createElement('p');
      p.innerText = '• ' + line;
      p.style.margin = '0 0 8px 0';
      body.appendChild(p);
    });
    modal.appendChild(body);

    const actions = document.createElement('div');
    Object.assign(actions.style, {
      display: 'flex',
      gap: '8px',
      padding: '0 16px 16px 16px',
      justifyContent: 'flex-end',
    });

    const cleanup = (result: boolean) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };

    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.innerText = opts.cancelLabel;
    Object.assign(cancelBtn.style, {
      padding: '8px 14px',
      fontSize: '12px',
      fontWeight: '600',
      color: '#e2e8f0',
      background: 'rgba(255,255,255,0.06)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '8px',
      cursor: 'pointer',
    });
    cancelBtn.addEventListener('click', () => cleanup(false));

    const confirmBtn = document.createElement('button');
    confirmBtn.type = 'button';
    confirmBtn.innerText = opts.confirmLabel;
    Object.assign(confirmBtn.style, {
      padding: '8px 14px',
      fontSize: '12px',
      fontWeight: '700',
      color: '#04231d',
      background: 'linear-gradient(135deg, #2dd4bf, #34d399)',
      border: 'none',
      borderRadius: '8px',
      cursor: 'pointer',
    });
    confirmBtn.addEventListener('click', () => cleanup(true));

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup(false);
    });

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') cleanup(false);
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

function escapeHtml(s: string): string {
  return (s || '').replace(/[&<>"']/g, (c) => {
    switch (c) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
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

function closeDropdownsOnOutsideClick(e: MouseEvent) {
  const target = e.target as HTMLElement;
  if (!target.closest('.xorapass-dropdown') && !target.closest('.xorapass-autofill-btn')) {
    closeAllDropdowns();
  }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const frame = assessFrame();
if (frame.isTop || !frame.isCrossOriginFrame) {
  // Only run in the top frame or in a same-origin (first-party) sub-frame.
  loadCredentials();
  setInterval(scanForLoginFields, 2500);
  window.addEventListener('focus', loadCredentials);
} else {
  // Third-party iframe: autofill deliberately blocked.
  console.debug('[XoraPass] Autofill disabled inside third-party iframe.');
}
