// Shadow-DOM overlay layer for XoraPass autofill.
//
// Why a shadow root instead of injecting nodes next to the input: the previous
// implementation wrapped each password field in a <div> and re-parented the
// input into it. That mutates the page's own DOM tree, which breaks
// React-controlled inputs (the node identity changes under the reconciler),
// event delegation that depends on ancestor structure, and any CSS that
// targets a direct-child or sibling relationship.
//
// Everything here instead lives in a single closed shadow root attached to
// <html>, positioned over the page with position:fixed viewport coordinates.
// The page's DOM is never modified, page CSS cannot leak in, and page scripts
// cannot reach our nodes (closed mode leaves element.shadowRoot === null).

import {
  computeIconPosition,
  computeDropdownPosition,
  isRectVisible,
} from './fieldHeuristics';

const HOST_ID = 'xorapass-overlay-host';
const ICON_SIZE = 20;
const MENU_WIDTH = 260;

export interface OverlayCredential {
  id: string;
  label: string;
  username: string;
  category: string;
}

export interface DropdownOptions {
  credentials: OverlayCredential[];
  /** Optional phishing/lookalike banner shown above the credential list. */
  warning?: string | null;
  onPick: (credentialId: string) => void;
}

interface Registration {
  input: HTMLInputElement;
  icon: HTMLButtonElement;
  onActivate: () => void;
}

let hostEl: HTMLDivElement | null = null;
let shadow: ShadowRoot | null = null;
let layer: HTMLDivElement | null = null;
let registrations: Registration[] = [];
let openMenu: HTMLElement | null = null;
let menuAnchor: HTMLInputElement | null = null;
let rafHandle = 0;

// ---------------------------------------------------------------------------
// Host construction
// ---------------------------------------------------------------------------

const STYLES = `
:host { all: initial; }
.layer {
  position: fixed;
  inset: 0;
  /* The layer itself must not swallow page clicks; only its children opt in. */
  pointer-events: none;
  z-index: 2147483647;
  font-family: Inter, system-ui, -apple-system, sans-serif;
}
.icon {
  position: fixed;
  width: ${ICON_SIZE}px;
  height: ${ICON_SIZE}px;
  padding: 0;
  margin: 0;
  border: none;
  border-radius: 4px;
  background: transparent;
  cursor: pointer;
  pointer-events: auto;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background-color 0.15s;
}
.icon:hover { background-color: rgba(45, 212, 191, 0.15); }
.icon:focus-visible { outline: 2px solid #2dd4bf; outline-offset: 1px; }
.menu {
  position: fixed;
  width: ${MENU_WIDTH}px;
  background-color: #0f172a;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 10px;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5), 0 8px 24px rgba(45,212,191,0.15);
  overflow: hidden;
  pointer-events: auto;
  color: #e2e8f0;
}
.menu-header {
  padding: 8px 12px;
  font-size: 10px;
  font-weight: 700;
  color: #2dd4bf;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  background-color: #0a1412;
}
.menu-warning {
  padding: 8px 12px;
  font-size: 10px;
  line-height: 1.4;
  color: #fca5a5;
  background-color: rgba(220, 38, 38, 0.12);
  border-bottom: 1px solid rgba(220, 38, 38, 0.25);
}
.menu-item {
  width: 100%;
  padding: 10px 12px;
  background: none;
  border: none;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  cursor: pointer;
  display: block;
  text-align: left;
  color: #e2e8f0;
  font-family: inherit;
  transition: background-color 0.15s, color 0.15s;
}
.menu-item:hover, .menu-item:focus-visible {
  background-color: rgba(45, 212, 191, 0.08);
  color: #2dd4bf;
  outline: none;
}
.menu-item-label {
  font-weight: 600;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.menu-item-user {
  font-size: 10px;
  color: #64748b;
  font-family: ui-monospace, monospace;
  margin-top: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.save-prompt {
  position: fixed;
  top: 16px;
  right: 16px;
  width: 320px;
  max-width: calc(100vw - 32px);
  background: #ffffff;
  border: 1px solid rgba(15, 23, 42, 0.1);
  border-radius: 14px;
  box-shadow: 0 24px 48px -16px rgba(15, 23, 42, 0.28);
  pointer-events: auto;
  color: #0f172a;
  overflow: hidden;
  animation: xp-slide-in 0.22s ease-out;
}
@keyframes xp-slide-in {
  from { transform: translateY(-8px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}
.save-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 14px 0 14px;
}
.save-title { font-size: 13px; font-weight: 700; }
.save-body { padding: 6px 14px 0 14px; font-size: 12px; color: #475569; line-height: 1.5; }
.save-user {
  font-family: ui-monospace, monospace;
  font-size: 11px;
  color: #0f172a;
  background: rgba(15, 23, 42, 0.05);
  border-radius: 6px;
  padding: 6px 8px;
  margin-top: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.save-actions { display: flex; gap: 8px; padding: 12px 14px 14px 14px; }
.save-btn {
  flex: 1;
  padding: 8px 12px;
  font-size: 12px;
  font-weight: 700;
  border-radius: 8px;
  cursor: pointer;
  font-family: inherit;
}
.save-btn-primary {
  color: #ffffff;
  background: linear-gradient(135deg, #0d9488, #059669);
  border: none;
}
.save-btn-secondary {
  color: #475569;
  background: #ffffff;
  border: 1px solid rgba(15, 23, 42, 0.12);
}
.save-status { padding: 0 14px 14px 14px; font-size: 11px; color: #475569; }

.backdrop {
  position: fixed;
  inset: 0;
  background-color: rgba(2, 6, 23, 0.6);
  backdrop-filter: blur(2px);
  pointer-events: auto;
  display: flex;
  align-items: center;
  justify-content: center;
}
.modal {
  width: 340px;
  max-width: 90vw;
  background-color: #0f172a;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 12px;
  box-shadow: 0 20px 40px -10px rgba(0,0,0,0.7);
  overflow: hidden;
  color: #e2e8f0;
}
.modal-title {
  padding: 14px 16px;
  font-size: 13px;
  font-weight: 700;
  color: #fca5a5;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  background-color: #0a1412;
}
.modal-body { padding: 14px 16px; font-size: 12px; line-height: 1.5; }
.modal-body p { margin: 0 0 8px 0; }
.modal-actions {
  display: flex;
  gap: 8px;
  padding: 0 16px 16px 16px;
  justify-content: flex-end;
}
.btn {
  padding: 8px 14px;
  font-size: 12px;
  font-weight: 600;
  border-radius: 8px;
  cursor: pointer;
  font-family: inherit;
}
.btn-cancel {
  color: #e2e8f0;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.1);
}
.btn-confirm {
  color: #04231d;
  background: linear-gradient(135deg, #2dd4bf, #34d399);
  border: none;
  font-weight: 700;
}
`;

const SHIELD_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" ' +
  'fill="none" stroke="#2dd4bf" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

function ensureHost(): HTMLDivElement {
  if (layer && shadow) return layer;

  const host = document.createElement('div');
  host.id = HOST_ID;
  // Keep the host itself inert and unstyleable from the page.
  host.setAttribute('style', 'all: initial; position: static;');

  // Closed mode: page scripts get null from host.shadowRoot and cannot read
  // the credential labels we render or synthesise clicks on our buttons.
  shadow = host.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = STYLES;
  shadow.appendChild(style);

  layer = document.createElement('div');
  layer.className = 'layer';
  shadow.appendChild(layer);

  // <html> rather than <body>: survives pages that replace document.body.
  document.documentElement.appendChild(host);
  hostEl = host;
  return layer;
}

// ---------------------------------------------------------------------------
// Icon registration & positioning
// ---------------------------------------------------------------------------

/**
 * Adds an autofill icon floating over `input`. Returns true when a new icon was
 * created, false when the input already had one.
 */
export function attachIcon(input: HTMLInputElement, onActivate: () => void): boolean {
  if (registrations.some((r) => r.input === input)) return false;

  const root = ensureHost();
  const icon = document.createElement('button');
  icon.type = 'button';
  icon.className = 'icon';
  icon.setAttribute('aria-label', 'XoraPass autofill');
  icon.innerHTML = SHIELD_SVG; // static trusted markup, no interpolation

  icon.addEventListener('mousedown', (e) => {
    // Prevent the input losing focus before we read it.
    e.preventDefault();
    e.stopPropagation();
  });
  icon.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    onActivate();
  });

  root.appendChild(icon);
  registrations.push({ input, icon, onActivate });
  reposition();
  return true;
}

/** Re-syncs every icon (and any open menu) to its input's current rect. */
export function reposition(): void {
  const viewport = { width: window.innerWidth, height: window.innerHeight };

  // Drop registrations whose input left the DOM, so long-lived SPAs don't leak.
  registrations = registrations.filter((reg) => {
    if (!reg.input.isConnected) {
      reg.icon.remove();
      if (menuAnchor === reg.input) closeDropdown();
      return false;
    }
    return true;
  });

  for (const reg of registrations) {
    const rect = reg.input.getBoundingClientRect();
    const editable = !reg.input.disabled && !reg.input.readOnly;

    if (!editable || !isRectVisible(rect, viewport)) {
      reg.icon.style.display = 'none';
      continue;
    }

    const pos = computeIconPosition(rect, ICON_SIZE);
    reg.icon.style.display = 'flex';
    reg.icon.style.left = `${pos.left}px`;
    reg.icon.style.top = `${pos.top}px`;
  }

  if (openMenu && menuAnchor) {
    if (!menuAnchor.isConnected) {
      closeDropdown();
      return;
    }
    const rect = menuAnchor.getBoundingClientRect();
    const height = openMenu.offsetHeight || 0;
    const pos = computeDropdownPosition(rect, { width: MENU_WIDTH, height }, viewport);
    openMenu.style.left = `${pos.left}px`;
    openMenu.style.top = `${pos.top}px`;
  }
}

/** Coalesces bursts of scroll/resize/mutation events into one reposition. */
export function scheduleReposition(): void {
  if (rafHandle) return;
  rafHandle = requestAnimationFrame(() => {
    rafHandle = 0;
    reposition();
  });
}

// ---------------------------------------------------------------------------
// Credential dropdown
// ---------------------------------------------------------------------------

export function openDropdown(anchor: HTMLInputElement, opts: DropdownOptions): void {
  closeDropdown();
  const root = ensureHost();

  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.setAttribute('role', 'listbox');

  const header = document.createElement('div');
  header.className = 'menu-header';
  header.textContent = 'XoraPass Autofill';
  menu.appendChild(header);

  if (opts.warning) {
    const banner = document.createElement('div');
    banner.className = 'menu-warning';
    banner.textContent = `⚠ ${opts.warning}`;
    menu.appendChild(banner);
  }

  for (const cred of opts.credentials) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'menu-item';
    item.setAttribute('role', 'option');

    // textContent throughout — no innerHTML, so no escaping needed and no way
    // for a crafted vault label to inject markup into the overlay.
    const label = document.createElement('div');
    label.className = 'menu-item-label';
    label.textContent = cred.label;
    item.appendChild(label);

    const user = document.createElement('div');
    user.className = 'menu-item-user';
    user.textContent = cred.username;
    item.appendChild(user);

    item.addEventListener('mousedown', (e) => e.preventDefault());
    item.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeDropdown();
      opts.onPick(cred.id);
    });

    menu.appendChild(item);
  }

  root.appendChild(menu);
  openMenu = menu;
  menuAnchor = anchor;
  reposition();

  document.addEventListener('mousedown', onOutsideInteraction, true);
  document.addEventListener('keydown', onMenuKeydown, true);
}

export function closeDropdown(): void {
  if (openMenu) {
    openMenu.remove();
    openMenu = null;
  }
  menuAnchor = null;
  document.removeEventListener('mousedown', onOutsideInteraction, true);
  document.removeEventListener('keydown', onMenuKeydown, true);
}

export function isDropdownOpen(): boolean {
  return openMenu !== null;
}

/**
 * Closes the menu on any interaction outside it.
 *
 * The listener runs in the CAPTURE phase, which reaches document before the
 * event reaches our menu item — so a naive implementation would tear the menu
 * down before its own click handler ever fired, making every entry unclickable.
 * Because the shadow root is closed, `composedPath()` seen from out here is
 * truncated at the host element, so testing for the host is both sufficient and
 * the only thing available to distinguish our own UI.
 */
function onOutsideInteraction(e: Event): void {
  if (hostEl && e.composedPath().includes(hostEl)) return;
  closeDropdown();
}

function onMenuKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') {
    e.stopPropagation();
    closeDropdown();
  }
}

// ---------------------------------------------------------------------------
// Confirmation modal
// ---------------------------------------------------------------------------

export function showConfirmDialog(opts: {
  title: string;
  body: string[];
  confirmLabel: string;
  cancelLabel: string;
}): Promise<boolean> {
  const root = ensureHost();

  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    backdrop.className = 'backdrop';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.setAttribute('role', 'alertdialog');
    modal.setAttribute('aria-modal', 'true');

    const title = document.createElement('div');
    title.className = 'modal-title';
    title.textContent = opts.title;
    modal.appendChild(title);

    const body = document.createElement('div');
    body.className = 'modal-body';
    for (const line of opts.body) {
      const p = document.createElement('p');
      p.textContent = `• ${line}`;
      body.appendChild(p);
    }
    modal.appendChild(body);

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cleanup = (result: boolean) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey, true);
      resolve(result);
    };

    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'btn btn-cancel';
    cancelBtn.textContent = opts.cancelLabel;
    cancelBtn.addEventListener('click', () => cleanup(false));

    const confirmBtn = document.createElement('button');
    confirmBtn.type = 'button';
    confirmBtn.className = 'btn btn-confirm';
    confirmBtn.textContent = opts.confirmLabel;
    confirmBtn.addEventListener('click', () => cleanup(true));

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) cleanup(false);
    });

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        cleanup(false);
      }
    };
    document.addEventListener('keydown', onKey, true);

    root.appendChild(backdrop);
    confirmBtn.focus();
  });
}

// ---------------------------------------------------------------------------
// Save prompt
// ---------------------------------------------------------------------------

let savePrompt: HTMLElement | null = null;

export interface SavePromptOptions {
  username: string;
  hostname: string;
  mode: 'new' | 'update';
  onSave: () => Promise<{ success?: boolean; error?: string; detail?: string | null }>;
  onDismiss: () => void;
}

export function showSavePrompt(opts: SavePromptOptions): void {
  closeSavePrompt();
  const root = ensureHost();

  const card = document.createElement('div');
  card.className = 'save-prompt';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', 'Save login to XoraPass');

  const head = document.createElement('div');
  head.className = 'save-head';
  const icon = document.createElement('span');
  icon.innerHTML = SHIELD_SVG;
  const title = document.createElement('div');
  title.className = 'save-title';
  title.textContent = opts.mode === 'update' ? 'Update password?' : 'Save this login?';
  head.appendChild(icon);
  head.appendChild(title);
  card.appendChild(head);

  const body = document.createElement('div');
  body.className = 'save-body';
  body.textContent =
    opts.mode === 'update'
      ? `The password for ${opts.hostname} has changed.`
      : `Save this login to your XoraPass vault for ${opts.hostname}.`;
  card.appendChild(body);

  const user = document.createElement('div');
  user.className = 'save-user';
  user.textContent = opts.username || '(no username)';
  body.appendChild(user);

  const actions = document.createElement('div');
  actions.className = 'save-actions';

  const notNow = document.createElement('button');
  notNow.type = 'button';
  notNow.className = 'save-btn save-btn-secondary';
  notNow.textContent = 'Not now';
  notNow.addEventListener('click', () => {
    opts.onDismiss();
    closeSavePrompt();
  });

  const save = document.createElement('button');
  save.type = 'button';
  save.className = 'save-btn save-btn-primary';
  save.textContent = opts.mode === 'update' ? 'Update' : 'Save';
  save.addEventListener('click', async () => {
    save.disabled = true;
    save.textContent = 'Saving…';
    const res = await opts.onSave();
    if (res && res.success) {
      closeSavePrompt();
      return;
    }
    // Keep the card up and say what happened, rather than closing silently and
    // leaving the user believing the credential was stored.
    save.disabled = false;
    save.textContent = opts.mode === 'update' ? 'Update' : 'Save';
    const status = card.querySelector('.save-status') || document.createElement('div');
    status.className = 'save-status';
    status.textContent =
      res?.detail
        ? res.detail
        : res?.error === 'session_expired'
          ? 'Your session expired. Unlock XoraPass and try again.'
          : res?.error === 'locked'
            ? 'XoraPass is locked. Unlock it and try again.'
            : "Couldn't save. Please try again.";
    if (!status.isConnected) card.appendChild(status);
  });

  actions.appendChild(notNow);
  actions.appendChild(save);
  card.appendChild(actions);

  root.appendChild(card);
  savePrompt = card;
}

export function closeSavePrompt(): void {
  if (savePrompt) {
    savePrompt.remove();
    savePrompt = null;
  }
}

export function isSavePromptOpen(): boolean {
  return savePrompt !== null;
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

/** Removes every icon and closes any menu — used when a site becomes disabled. */
export function clearAll(): void {
  closeDropdown();
  for (const reg of registrations) reg.icon.remove();
  registrations = [];
}

/** True when the input already carries an overlay icon. */
export function hasIcon(input: HTMLInputElement): boolean {
  return registrations.some((r) => r.input === input);
}
