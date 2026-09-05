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

import browser from 'webextension-polyfill';
import {
  computeIconPosition,
  computeTrailingOffset,
  computeDropdownPosition,
  isRectVisible,
  type Rect,
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
  /** Present on sign-up fields: offers a generated password above the list. */
  suggestion?: {
    password: string;
    onUse: (password: string) => void;
    onRegenerate: () => string;
  };
}

interface Registration {
  input: HTMLInputElement;
  icon: HTMLButtonElement;
  onActivate: () => void;
  /** Cached left-shift to clear the site's own trailing controls. */
  offset?: number;
  /** Field width when `offset` was computed, so it recomputes on layout change. */
  offsetAtWidth?: number;
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
.suggest {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(45, 212, 191, 0.06);
}
.suggest-label {
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #2dd4bf;
  margin-bottom: 6px;
}
.suggest-row { display: flex; align-items: center; gap: 8px; }
.suggest-value {
  flex: 1;
  min-width: 0;
  font-family: ui-monospace, monospace;
  font-size: 12px;
  color: #e2e8f0;
  word-break: break-all;
  line-height: 1.35;
}
.suggest-refresh {
  flex: none;
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: transparent;
  color: #94a3b8;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  font-family: inherit;
}
.suggest-refresh:hover { color: #2dd4bf; border-color: rgba(45, 212, 191, 0.4); }
.suggest-use {
  width: 100%;
  margin-top: 8px;
  padding: 7px 10px;
  font-size: 11px;
  font-weight: 700;
  color: #04231d;
  background: linear-gradient(135deg, #2dd4bf, #34d399);
  border: none;
  border-radius: 7px;
  cursor: pointer;
  font-family: inherit;
}

.save-prompt {
  position: fixed;
  top: 16px;
  right: 16px;
  width: 380px;
  max-width: calc(100vw - 32px);
  background: #ffffff;
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 18px;
  box-shadow:
    0 1px 3px rgba(15, 23, 42, 0.06),
    0 8px 24px -4px rgba(15, 23, 42, 0.14),
    0 24px 48px -12px rgba(15, 23, 42, 0.18);
  pointer-events: auto;
  color: #0f172a;
  overflow: hidden;
  animation: xp-slide-in 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.save-prompt.is-update {
  border-color: rgba(217, 119, 6, 0.18);
}
@keyframes xp-slide-in {
  from { transform: translateY(-12px) scale(0.97); opacity: 0; }
  to   { transform: translateY(0) scale(1); opacity: 1; }
}
@keyframes xp-slide-out {
  from { transform: translateY(0) scale(1); opacity: 1; }
  to   { transform: translateY(-8px) scale(0.97); opacity: 0; }
}
@keyframes xp-check-draw {
  0%   { stroke-dashoffset: 24; }
  100% { stroke-dashoffset: 0; }
}
@keyframes xp-check-circle {
  0%   { stroke-dashoffset: 100; }
  100% { stroke-dashoffset: 0; }
}
.save-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 16px 0 18px;
}
.save-head-icon {
  display: flex;
  align-items: center;
  flex: none;
}
.save-title {
  font-size: 15px;
  font-weight: 700;
  flex: 1;
  letter-spacing: -0.01em;
  color: #0f172a;
}
.save-title.is-update { color: #92400e; }
.save-close {
  width: 28px;
  height: 28px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: 7px;
  color: #94a3b8;
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
  font-family: inherit;
  transition: background-color 0.15s, color 0.15s;
}
.save-close:hover { background: rgba(15, 23, 42, 0.06); color: #0f172a; }

.save-identity {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 14px 18px 0 18px;
  padding: 12px 14px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  transition: border-color 0.15s;
}
.save-prompt.is-update .save-identity {
  background: rgba(251, 191, 36, 0.06);
  border-color: rgba(217, 119, 6, 0.18);
}
/* Favicon from Google's service, with letter-avatar fallback */
.save-favicon {
  width: 36px;
  height: 36px;
  flex: none;
  border-radius: 9px;
  object-fit: contain;
  background: #f1f5f9;
  border: 1px solid rgba(15, 23, 42, 0.06);
}
.save-avatar {
  width: 36px;
  height: 36px;
  flex: none;
  border-radius: 9px;
  background: linear-gradient(135deg, #0d9488, #059669);
  color: #ffffff;
  font-size: 15px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  text-transform: uppercase;
}
.save-prompt.is-update .save-avatar {
  background: linear-gradient(135deg, #d97706, #b45309);
}
.save-identity-text { min-width: 0; flex: 1; }
.save-username {
  font-size: 14px;
  font-weight: 600;
  color: #0f172a;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.save-username.is-empty { color: #94a3b8; font-weight: 500; font-style: italic; }
.save-host {
  font-size: 12px;
  color: #64748b;
  margin-top: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Footer: brand logo left, action buttons right — mirrors LastPass layout */
.save-footer {
  display: flex;
  align-items: center;
  padding: 12px 16px 14px 18px;
  border-top: 1px solid rgba(15, 23, 42, 0.05);
  margin-top: 14px;
}
.save-brand {
  display: flex;
  align-items: center;
  gap: 0;
  flex: 1;
  min-width: 0;
}
.save-brand-logo {
  height: 22px;
  width: auto;
  object-fit: contain;
  display: block;
  user-select: none;
  -webkit-user-drag: none;
}
.save-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}
.save-btn {
  padding: 8px 18px;
  font-size: 13px;
  font-weight: 600;
  border-radius: 9px;
  cursor: pointer;
  font-family: inherit;
  transition: background-color 0.15s, box-shadow 0.15s, transform 0.1s;
}
.save-btn:active { transform: scale(0.97); }
.save-btn-primary {
  color: #ffffff;
  font-weight: 700;
  background: linear-gradient(135deg, #0d9488, #059669);
  border: none;
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.24);
}
.save-btn-primary:hover:not(:disabled) {
  box-shadow: 0 4px 14px rgba(13, 148, 136, 0.36);
  transform: translateY(-1px);
}
.save-btn-primary:disabled { opacity: 0.6; cursor: default; box-shadow: none; transform: none; }
.save-prompt.is-update .save-btn-primary {
  background: linear-gradient(135deg, #d97706, #b45309);
  box-shadow: 0 2px 8px rgba(217, 119, 6, 0.24);
}
.save-prompt.is-update .save-btn-primary:hover:not(:disabled) {
  box-shadow: 0 4px 14px rgba(217, 119, 6, 0.36);
}
.save-btn-secondary {
  color: #64748b;
  background: transparent;
  border: none;
}
.save-btn-secondary:hover { background: rgba(15, 23, 42, 0.05); color: #0f172a; }

/* "Never for this site" link — subtle, below actions (Bitwarden-inspired) */
.save-never {
  display: block;
  width: 100%;
  text-align: center;
  padding: 0 18px 12px 18px;
  font-size: 11px;
  color: #94a3b8;
  background: none;
  border: none;
  cursor: pointer;
  font-family: inherit;
  transition: color 0.15s;
}
.save-never:hover { color: #ef4444; }

/* Error status banner */
.save-status {
  margin: 10px 18px 0 18px;
  padding: 9px 12px;
  font-size: 12px;
  line-height: 1.4;
  color: #9a3412;
  background: rgba(234, 88, 12, 0.06);
  border: 1px solid rgba(234, 88, 12, 0.16);
  border-radius: 9px;
}

/* Success overlay — 1Password-style confirmation before auto-dismiss */
.save-success {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  background: #ffffff;
  border-radius: 18px;
  z-index: 1;
  animation: xp-slide-in 0.2s ease-out;
}
.save-success-icon {
  width: 48px;
  height: 48px;
}
.save-success-icon circle {
  fill: none;
  stroke: #059669;
  stroke-width: 2;
  stroke-dasharray: 100;
  stroke-dashoffset: 100;
  animation: xp-check-circle 0.4s ease-out forwards;
}
.save-success-icon polyline {
  fill: none;
  stroke: #059669;
  stroke-width: 2.5;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-dasharray: 24;
  stroke-dashoffset: 24;
  animation: xp-check-draw 0.3s 0.25s ease-out forwards;
}
.save-success-text {
  font-size: 14px;
  font-weight: 600;
  color: #059669;
}

.backdrop {
  position: fixed;
  top: 16px;
  right: 16px;
  z-index: 2147483647;
  pointer-events: auto;
}
.backdrop.is-closing {
  animation: xp-slide-out 0.2s cubic-bezier(0.4, 0, 0.2, 1) forwards;
}
.modal {
  width: 380px;
  max-width: calc(100vw - 32px);
  background-color: #ffffff;
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 18px;
  box-shadow:
    0 2px 4px rgba(15, 23, 42, 0.04),
    0 10px 28px -4px rgba(15, 23, 42, 0.16),
    0 24px 48px -12px rgba(15, 23, 42, 0.18);
  overflow: hidden;
  color: #0f172a;
  animation: xp-slide-in 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.modal-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 16px 12px 18px;
}
.modal-close {
  width: 26px;
  height: 26px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: 7px;
  color: #94a3b8;
  cursor: pointer;
  font-size: 18px;
  line-height: 1;
  font-family: inherit;
  margin-left: auto;
  transition: background-color 0.15s, color 0.15s;
}
.modal-close:hover {
  background: rgba(15, 23, 42, 0.06);
  color: #0f172a;
}
.modal-head-icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.25);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}
.modal-head-icon.is-danger {
  background: rgba(225, 29, 72, 0.12);
  border-color: rgba(225, 29, 72, 0.25);
}
.modal-title {
  font-size: 15px;
  font-weight: 700;
  color: #0f172a;
  letter-spacing: -0.01em;
  line-height: 1.3;
}
.modal-body {
  padding: 0 22px 18px 22px;
  font-size: 13px;
  line-height: 1.55;
  color: #475569;
}
.modal-body-line {
  margin: 0 0 8px 0;
  color: #334155;
  font-size: 13px;
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
.modal-body-line:last-child {
  margin-bottom: 0;
}
.modal-body-bullet {
  color: #94a3b8;
  font-size: 14px;
  line-height: 1;
  margin-top: 3px;
}
.modal-preview {
  margin-top: 10px;
  padding: 10px 14px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  font-size: 12px;
  line-height: 1.45;
  word-break: break-all;
}
.modal-preview-label {
  font-weight: 700;
  color: #64748b;
  font-family: Inter, system-ui, sans-serif;
  margin-right: 6px;
}
.modal-preview-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: #0f172a;
  font-weight: 600;
}
.modal-actions {
  display: flex;
  gap: 10px;
  padding: 14px 22px 18px 22px;
  background: #fafafa;
  border-top: 1px solid #f1f5f9;
  justify-content: flex-end;
  align-items: center;
}
.btn {
  padding: 9px 18px;
  font-size: 12.5px;
  font-weight: 600;
  border-radius: 10px;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.15s ease;
  outline: none;
}
.btn-cancel {
  color: #334155;
  background: #ffffff;
  border: 1px solid #cbd5e1;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
}
.btn-cancel:hover {
  background: #f1f5f9;
  color: #0f172a;
  border-color: #94a3b8;
}
.btn-confirm {
  color: #ffffff;
  background: linear-gradient(135deg, #0d9488, #059669);
  border: none;
  font-weight: 700;
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.25);
}
.btn-confirm:hover {
  opacity: 0.95;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(13, 148, 136, 0.35);
}
.btn-confirm:active {
  transform: translateY(0);
}

/* Proactive risk alert — appears unprompted, no click required (unlike the
   in-dropdown warning banner, which only renders once a login icon is
   clicked). Positioned like the save prompt so it reads as part of the same
   product language, but styled as an alert rather than a neutral prompt. */
.risk-alert {
  position: fixed;
  top: 16px;
  right: 16px;
  width: 380px;
  max-width: calc(100vw - 32px);
  background: #ffffff;
  border: 1px solid rgba(225, 29, 72, 0.25);
  border-radius: 18px;
  box-shadow:
    0 2px 4px rgba(15, 23, 42, 0.04),
    0 10px 28px -4px rgba(225, 29, 72, 0.22),
    0 24px 48px -12px rgba(15, 23, 42, 0.18);
  pointer-events: auto;
  color: #0f172a;
  overflow: hidden;
  z-index: 2147483647;
  animation: xp-slide-in 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.risk-alert.is-warn { border-color: rgba(13, 148, 136, 0.25); }
.risk-brand {
  display: flex;
  align-items: center;
  padding: 14px 18px 0;
}
.risk-brand-logo {
  display: block;
  width: auto;
  height: 22px;
  max-width: 126px;
  object-fit: contain;
}
.risk-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 16px 0 18px;
}
.risk-head-icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: rgba(225, 29, 72, 0.12);
  border: 1px solid rgba(225, 29, 72, 0.25);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}
.risk-alert.is-warn .risk-head-icon {
  background: rgba(13, 148, 136, 0.12);
  border-color: rgba(13, 148, 136, 0.25);
}
.risk-title {
  font-size: 15px;
  font-weight: 700;
  flex: 1;
  letter-spacing: -0.01em;
  color: #e11d48;
}
.risk-alert.is-warn .risk-title { color: #0d9488; }
.risk-close {
  width: 28px;
  height: 28px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  border: none;
  background: transparent;
  border-radius: 7px;
  color: #94a3b8;
  cursor: pointer;
  font-size: 16px;
  line-height: 1;
  font-family: inherit;
  transition: background-color 0.15s, color 0.15s;
}
.risk-close:hover { background: rgba(15, 23, 42, 0.06); color: #0f172a; }
.risk-body {
  padding: 8px 18px 4px 18px;
  font-size: 13px;
  line-height: 1.5;
  color: #334155;
}
.risk-facts {
  margin: 4px 18px 0 18px;
  padding: 8px 12px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
}
.risk-fact-row {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 3px 0;
  font-size: 11.5px;
}
.risk-fact-label {
  color: #94a3b8;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  flex: none;
}
.risk-fact-value {
  color: #334155;
  font-weight: 600;
  font-family: ui-monospace, monospace;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: right;
}
.risk-status-note {
  margin: 4px 18px 0 18px;
  padding: 8px 12px;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: 10px;
  font-size: 11.5px;
  font-weight: 600;
  color: #1d4ed8;
}
.risk-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 16px 16px 18px;
}
.risk-footer {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 0 18px 14px;
  color: #94a3b8;
  font-size: 11px;
  font-weight: 600;
}
.risk-footer-icon {
  width: 16px;
  height: 16px;
  color: #0d9488;
}
.risk-btn-dismiss,
.risk-btn-secondary,
.risk-btn-primary {
  padding: 8px 14px;
  font-size: 12.5px;
  font-weight: 600;
  border-radius: 9px;
  cursor: pointer;
  font-family: inherit;
  transition: background-color 0.15s, color 0.15s, box-shadow 0.15s;
}
.risk-btn-dismiss:disabled,
.risk-btn-secondary:disabled,
.risk-btn-primary:disabled {
  opacity: 0.65;
  cursor: default;
}
.risk-btn-dismiss {
  color: #64748b;
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
}
.risk-btn-dismiss:hover { background: #e2e8f0; color: #0f172a; }
.risk-btn-secondary {
  color: #334155;
  background: #ffffff;
  border: 1px solid #cbd5e1;
}
.risk-btn-secondary:hover:not(:disabled) { background: #f1f5f9; border-color: #94a3b8; }
.risk-btn-primary {
  color: #ffffff;
  background: linear-gradient(135deg, #0d9488, #059669);
  border: none;
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.24);
}
.risk-btn-primary:hover:not(:disabled) { box-shadow: 0 4px 14px rgba(13, 148, 136, 0.36); }
`;

const SHIELD_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" ' +
  'fill="none" stroke="#2dd4bf" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

const DANGER_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" ' +
  'stroke="#e11d48" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/>' +
  '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

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

// Elements the page has placed at or near a field's right edge that our icon
// must not sit on top of — reveal-password eyes, clear buttons, spinners. The
// search is scoped to the nearest wrapping container and to control-like tags,
// so it stays cheap; the pure geometry in computeTrailingOffset does the
// filtering by position and size.
function trailingControls(input: HTMLInputElement, fieldRect: DOMRect): Rect[] {
  const scope: Element =
    input.closest('form, label, div, span') || input.parentElement || document.body;

  const nodes = scope.querySelectorAll(
    'button, [role="button"], a, svg, img, i, span[class]'
  );

  const out: Rect[] = [];
  for (const node of nodes) {
    if (node === input || node.contains(input)) continue;
    const r = (node as Element).getBoundingClientRect();
    if (r.width === 0 || r.height === 0) continue;
    // Cheap pre-filter: keep only things overlapping the field's right half,
    // leaving the precise decision to computeTrailingOffset.
    if (r.left < fieldRect.left + fieldRect.width / 2) continue;
    out.push({ top: r.top, left: r.left, width: r.width, height: r.height });
    if (out.length >= 12) break; // never let a pathological page balloon this
  }
  return out;
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

    // Probe for the site's own trailing controls (a reveal-password eye, a
    // clear button) only when the offset is unknown or the field width changed.
    // Skipping it while the width is stable keeps scroll repositioning cheap, as
    // collisions do not move relative to the field during a scroll.
    if (reg.offset === undefined || Math.abs((reg.offsetAtWidth ?? -1) - rect.width) > 1) {
      reg.offset = computeTrailingOffset(rect, trailingControls(reg.input, rect), ICON_SIZE);
      reg.offsetAtWidth = rect.width;
    }

    const pos = computeIconPosition(rect, ICON_SIZE, 8, reg.offset);
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

  if (opts.suggestion) {
    const sug = opts.suggestion;
    const box = document.createElement('div');
    box.className = 'suggest';

    const label = document.createElement('div');
    label.className = 'suggest-label';
    label.textContent = 'Suggested password';
    box.appendChild(label);

    const row = document.createElement('div');
    row.className = 'suggest-row';

    const value = document.createElement('div');
    value.className = 'suggest-value';
    value.textContent = sug.password;
    row.appendChild(value);

    const refresh = document.createElement('button');
    refresh.type = 'button';
    refresh.className = 'suggest-refresh';
    refresh.setAttribute('aria-label', 'Generate another');
    refresh.textContent = '⟳';
    refresh.addEventListener('mousedown', (e) => e.preventDefault());
    refresh.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      value.textContent = sug.onRegenerate();
    });
    row.appendChild(refresh);
    box.appendChild(row);

    const use = document.createElement('button');
    use.type = 'button';
    use.className = 'suggest-use';
    use.textContent = 'Use this password';
    use.addEventListener('mousedown', (e) => e.preventDefault());
    use.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeDropdown();
      sug.onUse(value.textContent || sug.password);
    });
    box.appendChild(use);

    menu.appendChild(box);
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

    // Header container with Warning icon + Title
    const head = document.createElement('div');
    head.className = 'modal-head';

    const isDanger = opts.title.toLowerCase().includes('block');
    const iconWrap = document.createElement('div');
    iconWrap.className = isDanger ? 'modal-head-icon is-danger' : 'modal-head-icon';
    iconWrap.innerHTML = isDanger
      ? DANGER_SVG
      : '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    head.appendChild(iconWrap);

    const title = document.createElement('div');
    title.className = 'modal-title';
    title.textContent = opts.title;
    head.appendChild(title);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'modal-close';
    closeBtn.innerHTML = '×';
    closeBtn.title = 'Dismiss';
    closeBtn.addEventListener('click', () => cleanup(false));
    head.appendChild(closeBtn);

    modal.appendChild(head);

    const body = document.createElement('div');
    body.className = 'modal-body';
    for (const line of opts.body) {
      if (line.startsWith('Preview:')) {
        const prevBox = document.createElement('div');
        prevBox.className = 'modal-preview';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'modal-preview-label';
        labelSpan.textContent = 'Preview:';
        prevBox.appendChild(labelSpan);

        const valSpan = document.createElement('span');
        valSpan.className = 'modal-preview-value';
        valSpan.textContent = line.replace(/^Preview:\s*/, '');
        prevBox.appendChild(valSpan);

        body.appendChild(prevBox);
      } else {
        const p = document.createElement('div');
        p.className = 'modal-body-line';

        const bullet = document.createElement('span');
        bullet.className = 'modal-body-bullet';
        bullet.textContent = '•';
        p.appendChild(bullet);

        const textSpan = document.createElement('span');
        textSpan.textContent = line;
        p.appendChild(textSpan);

        body.appendChild(p);
      }
    }
    modal.appendChild(body);

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cleanup = (result: boolean) => {
      backdrop.classList.add('is-closing');
      setTimeout(() => backdrop.remove(), 150);
      document.removeEventListener('keydown', onKey, true);
      resolve(result);
    };

    if (opts.cancelLabel) {
      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn btn-cancel';
      cancelBtn.textContent = opts.cancelLabel;
      cancelBtn.addEventListener('click', () => cleanup(false));
      actions.appendChild(cancelBtn);
    }

    const confirmBtn = document.createElement('button');
    confirmBtn.type = 'button';
    confirmBtn.className = 'btn btn-confirm';
    confirmBtn.textContent = opts.confirmLabel;
    confirmBtn.addEventListener('click', () => cleanup(true));

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
  /** Optional: permanently suppress prompts for this site (Bitwarden-style). */
  onNever?: () => void;
  /** URL to the XoraPass logo image (e.g. from browser.runtime.getURL). */
  brandLogoUrl?: string;
}

// Animated checkmark SVG shown on save success (1Password-style).
const SUCCESS_SVG =
  '<svg class="save-success-icon" viewBox="0 0 40 40">' +
  '<circle cx="20" cy="20" r="18"/>' +
  '<polyline points="12,20 18,26 28,14"/>' +
  '</svg>';

export function showSavePrompt(opts: SavePromptOptions): void {
  closeSavePrompt();
  const root = ensureHost();

  const card = document.createElement('div');
  card.className = opts.mode === 'update' ? 'save-prompt is-update' : 'save-prompt';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', 'Save login to XoraPass');
  // Relative positioning for the success overlay.
  card.style.position = 'fixed';

  const dismiss = () => {
    opts.onDismiss();
    closeSavePrompt();
  };

  // ── Header ────────────────────────────────────────────────────────────────
  const head = document.createElement('div');
  head.className = 'save-head';

  const headIcon = document.createElement('span');
  headIcon.className = 'save-head-icon';
  headIcon.innerHTML = SHIELD_SVG;

  const title = document.createElement('div');
  title.className = opts.mode === 'update' ? 'save-title is-update' : 'save-title';
  title.textContent = opts.mode === 'update' ? 'Update password?' : 'Save this login?';

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'save-close';
  close.setAttribute('aria-label', 'Dismiss');
  close.textContent = '✕';
  close.addEventListener('click', dismiss);

  head.appendChild(headIcon);
  head.appendChild(title);
  head.appendChild(close);
  card.appendChild(head);

  // ── Identity row (favicon + username + hostname) ──────────────────────────
  const identity = document.createElement('div');
  identity.className = 'save-identity';

  const cleanHost = opts.hostname.replace(/^www\./, '');

  // Try the site's actual favicon first, fall back to a letter avatar.
  const favicon = document.createElement('img');
  favicon.className = 'save-favicon';
  favicon.alt = cleanHost;
  favicon.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(cleanHost)}&sz=64`;
  favicon.onerror = () => {
    // Replace the broken <img> with a letter avatar.
    const avatar = document.createElement('div');
    avatar.className = 'save-avatar';
    avatar.textContent = (cleanHost[0] || '?').toUpperCase();
    favicon.replaceWith(avatar);
  };
  identity.appendChild(favicon);

  const identityText = document.createElement('div');
  identityText.className = 'save-identity-text';

  const user = document.createElement('div');
  user.className = opts.username ? 'save-username' : 'save-username is-empty';
  user.textContent = opts.username || 'No username detected';
  identityText.appendChild(user);

  const host = document.createElement('div');
  host.className = 'save-host';
  host.textContent = cleanHost;
  identityText.appendChild(host);

  identity.appendChild(identityText);
  card.appendChild(identity);

  // ── Footer (brand + actions) ──────────────────────────────────────────────
  const footer = document.createElement('div');
  footer.className = 'save-footer';

  // Brand logo on the left — mirrors how LastPass shows its logo in the footer.
  const brand = document.createElement('div');
  brand.className = 'save-brand';
  if (opts.brandLogoUrl) {
    const logo = document.createElement('img');
    logo.className = 'save-brand-logo';
    logo.src = opts.brandLogoUrl;
    logo.alt = 'XoraPass';
    logo.draggable = false;
    brand.appendChild(logo);
  } else {
    // Fallback: shield icon + text if no logo URL provided.
    const brandIcon = document.createElement('span');
    brandIcon.className = 'save-brand-icon';
    brandIcon.innerHTML = SHIELD_SVG;
    const brandName = document.createElement('span');
    brandName.className = 'save-brand-name';
    brandName.textContent = 'XoraPass';
    brand.appendChild(brandIcon);
    brand.appendChild(brandName);
  }
  footer.appendChild(brand);

  // Action buttons on the right.
  const actions = document.createElement('div');
  actions.className = 'save-actions';

  const notNow = document.createElement('button');
  notNow.type = 'button';
  notNow.className = 'save-btn save-btn-secondary';
  notNow.textContent = 'Not now';
  notNow.addEventListener('click', dismiss);

  const save = document.createElement('button');
  save.type = 'button';
  save.className = 'save-btn save-btn-primary';
  save.textContent = opts.mode === 'update' ? 'Update' : 'Save';
  save.addEventListener('click', async () => {
    save.disabled = true;
    notNow.disabled = true;
    save.textContent = 'Saving…';
    const res = await opts.onSave();
    if (res && res.success) {
      // ── Success animation (1Password-style) ────────────────────────────
      const success = document.createElement('div');
      success.className = 'save-success';
      success.innerHTML = SUCCESS_SVG;
      const successText = document.createElement('div');
      successText.className = 'save-success-text';
      successText.textContent = opts.mode === 'update' ? 'Updated!' : 'Saved!';
      success.appendChild(successText);
      card.style.position = 'fixed'; // keep it positioned for the overlay
      card.appendChild(success);
      setTimeout(() => {
        card.style.animation = 'xp-slide-out 0.2s ease-in forwards';
        setTimeout(closeSavePrompt, 200);
      }, 800);
      return;
    }
    // Keep the card up and say what happened, rather than closing silently and
    // leaving the user believing the credential was stored.
    save.disabled = false;
    notNow.disabled = false;
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
            : res?.error === 'offline'
              ? "You're offline. Reconnect and unlock XoraPass to save this."
              : "Couldn't save. Please try again.";
    if (!status.isConnected) {
      // Insert the error above the footer rather than at the card bottom.
      card.insertBefore(status, footer);
    }
  });

  actions.appendChild(notNow);
  actions.appendChild(save);
  footer.appendChild(actions);
  card.appendChild(footer);

  // ── "Never for this site" (Bitwarden-inspired) ────────────────────────────
  if (opts.onNever) {
    const never = document.createElement('button');
    never.type = 'button';
    never.className = 'save-never';
    never.textContent = 'Never for this site';
    never.addEventListener('click', () => {
      opts.onNever!();
      closeSavePrompt();
    });
    card.appendChild(never);
  }

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
// Proactive risk alert
// ---------------------------------------------------------------------------

let riskAlertEl: HTMLElement | null = null;

export interface RiskWarningOptions {
  /** 'block' gets the strongest visual treatment; anything else reads as a caution. */
  severity: 'block' | 'warn' | 'require_approval';
  title: string;
  message: string;
  currentDomain: string;
  /** The saved/trusted domain this page was compared against, when known. */
  expectedDomain?: string | null;
  riskLevel?: string;
  onDismiss?: () => void;
  /** Present only when expectedDomain is known — navigates the tab there. */
  onGoToOfficial?: () => void;
  /** Reports the current page as phishing. Resolves once the report lands. */
  onReportPhishing?: () => Promise<{ success: boolean }>;
  /** Submits an admin-review allowlist request for the current domain. */
  onRequestAllowlist?: () => Promise<{ success: boolean; reason?: string }>;
  /**
   * Present only for a `require_approval` verdict: records the user's explicit
   * decision to fill here anyway. Never offered for `block` - a blocked verdict
   * has no user-side override by design.
   */
  onApproveAnyway?: () => Promise<{ success: boolean; reason?: string }>;
  /**
   * When a request for this exact domain already exists, shows a status
   * note instead of the "Request allowlist review" button — resubmitting
   * a request that's already pending (or already decided) would just spam
   * the admin queue with duplicates every time the user revisits the site.
   */
  allowlistRequestStatus?: 'pending' | 'approved' | 'denied' | null;
}

/**
 * Shows a phishing/domain-risk alert unprompted — unlike the warning banner
 * inside the credential dropdown (which only renders once the user clicks a
 * login field's icon), this appears the moment a risky decision comes back,
 * even on pages with no login form at all.
 */
export function showRiskWarning(opts: RiskWarningOptions): void {
  closeRiskWarning();
  const root = ensureHost();

  const card = document.createElement('div');
  card.className = opts.severity === 'block' ? 'risk-alert' : 'risk-alert is-warn';
  card.setAttribute('role', 'alert');
  card.setAttribute('aria-live', 'assertive');

  const brand = document.createElement('div');
  brand.className = 'risk-brand';
  const brandLogo = document.createElement('img');
  brandLogo.className = 'risk-brand-logo';
  brandLogo.src = browser.runtime.getURL('xorapass_logo_horizontal.png');
  brandLogo.alt = 'XoraPass';
  brandLogo.draggable = false;
  brand.appendChild(brandLogo);
  card.appendChild(brand);

  const head = document.createElement('div');
  head.className = 'risk-head';

  const iconWrap = document.createElement('div');
  iconWrap.className = 'risk-head-icon';
  iconWrap.innerHTML = DANGER_SVG; // static trusted markup

  const title = document.createElement('div');
  title.className = 'risk-title';
  title.textContent = opts.title;

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'risk-close';
  close.setAttribute('aria-label', 'Dismiss');
  close.textContent = '✕';
  close.addEventListener('click', () => {
    closeRiskWarning();
    opts.onDismiss?.();
  });

  head.appendChild(iconWrap);
  head.appendChild(title);
  head.appendChild(close);
  card.appendChild(head);

  const body = document.createElement('div');
  body.className = 'risk-body';
  // textContent only — the message may embed a domain name we don't control.
  body.textContent = opts.message;
  card.appendChild(body);

  // ── Structured facts: current domain, expected domain, risk level ────────
  const facts = document.createElement('div');
  facts.className = 'risk-facts';

  const addFact = (label: string, value: string) => {
    const row = document.createElement('div');
    row.className = 'risk-fact-row';
    const l = document.createElement('span');
    l.className = 'risk-fact-label';
    l.textContent = label;
    const v = document.createElement('span');
    v.className = 'risk-fact-value';
    v.textContent = value;
    row.appendChild(l);
    row.appendChild(v);
    facts.appendChild(row);
  };

  addFact('Current site', opts.currentDomain);
  if (opts.expectedDomain) addFact('Expected site', opts.expectedDomain);
  if (opts.riskLevel) addFact('Risk level', opts.riskLevel);
  card.appendChild(facts);

  if (opts.allowlistRequestStatus === 'pending' || opts.allowlistRequestStatus === 'denied') {
    const note = document.createElement('div');
    note.className = 'risk-status-note';
    note.textContent =
      opts.allowlistRequestStatus === 'pending'
        ? 'Allowlist request sent to admin — awaiting review.'
        : 'Allowlist request was reviewed and denied by admin.';
    card.appendChild(note);
  }

  const actions = document.createElement('div');
  actions.className = 'risk-actions';

  // Runs an async safe-action button through a consistent pending/settled
  // sequence: disable + relabel immediately, then reflect the outcome rather
  // than closing silently — the same pattern showSavePrompt uses, so a failed
  // report/request isn't mistaken for a successful one.
  const wireAsyncAction = (
    btn: HTMLButtonElement,
    pendingLabel: string,
    doneLabel: string,
    failedLabel: string | ((reason: string | undefined) => string),
    run: () => Promise<{ success: boolean; reason?: string }>
  ) => {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = pendingLabel;
      try {
        const res = await run();
        if (res?.success) {
          btn.textContent = doneLabel;
          // Stays disabled: success is a terminal state, nothing left to retry.
        } else {
          btn.textContent = typeof failedLabel === 'function' ? failedLabel(res?.reason) : failedLabel;
          btn.disabled = false; // otherwise the failure label is shown but unclickable
        }
      } catch {
        btn.textContent = typeof failedLabel === 'function' ? failedLabel(undefined) : failedLabel;
        btn.disabled = false;
      }
    });
  };

  if (opts.onGoToOfficial && opts.expectedDomain) {
    const goOfficial = document.createElement('button');
    goOfficial.type = 'button';
    goOfficial.className = 'risk-btn-primary';
    goOfficial.textContent = `Go to ${opts.expectedDomain}`;
    goOfficial.addEventListener('click', () => {
      closeRiskWarning();
      opts.onGoToOfficial!();
    });
    actions.appendChild(goOfficial);
  }

  // `require_approval` is the one verdict a human may clear. It is rendered as
  // a secondary action, never the primary one: the safe path (go to the real
  // site) stays the visually dominant button.
  if (opts.onApproveAnyway && opts.severity === 'require_approval') {
    const approve = document.createElement('button');
    approve.type = 'button';
    approve.className = 'risk-btn-secondary';
    approve.textContent = 'Fill here anyway';
    wireAsyncAction(approve, 'Approving…', 'Approved - reopen the field', 'Try again', opts.onApproveAnyway);
    actions.appendChild(approve);
  }

  if (opts.onReportPhishing) {
    const report = document.createElement('button');
    report.type = 'button';
    report.className = 'risk-btn-secondary';
    report.textContent = 'Report phishing';
    wireAsyncAction(report, 'Reporting…', 'Reported', 'Try again', opts.onReportPhishing);
    actions.appendChild(report);
  }

  if (opts.onRequestAllowlist && !opts.allowlistRequestStatus) {
    const request = document.createElement('button');
    request.type = 'button';
    request.className = 'risk-btn-secondary';
    request.textContent = 'Request allowlist review';
    wireAsyncAction(
      request,
      'Sending…',
      'Sent to admin',
      (reason) => (reason === 'not_authenticated' ? 'Log in to request' : 'Try again'),
      opts.onRequestAllowlist
    );
    actions.appendChild(request);
  }

  const dismissBtn = document.createElement('button');
  dismissBtn.type = 'button';
  dismissBtn.className = 'risk-btn-dismiss';
  dismissBtn.textContent = 'Dismiss';
  dismissBtn.addEventListener('click', () => {
    closeRiskWarning();
    opts.onDismiss?.();
  });
  actions.appendChild(dismissBtn);
  card.appendChild(actions);

  const footer = document.createElement('div');
  footer.className = 'risk-footer';
  const footerIcon = document.createElement('span');
  footerIcon.className = 'risk-footer-icon';
  footerIcon.innerHTML = SHIELD_SVG;
  const trustLabel = document.createElement('span');
  trustLabel.textContent = 'Zero-Knowledge Encrypted';
  footer.appendChild(footerIcon);
  footer.appendChild(trustLabel);
  card.appendChild(footer);

  root.appendChild(card);
  riskAlertEl = card;
}

export function closeRiskWarning(): void {
  if (riskAlertEl) {
    riskAlertEl.remove();
    riskAlertEl = null;
  }
}

export function isRiskWarningOpen(): boolean {
  return riskAlertEl !== null;
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
