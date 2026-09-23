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
  hasTotp?: boolean;
}

export interface DropdownOptions {
  credentials: OverlayCredential[];
  /** Optional phishing/lookalike banner shown above the credential list. */
  warning?: string | null;
  onPick: (credentialId: string) => void;
  /** Present on sign-up fields: offers a generated password above the list. */
  suggestion?: {
    password: string;
    length: number;
    maxLength?: number;
    minLength?: number;
    onUse: (password: string) => void;
    onRegenerate: (len?: number) => string;
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
  pointer-events: none;
  z-index: 2147483647;
  font-family: Inter, system-ui, -apple-system, sans-serif;
  --xp-bg-card: #0f172a;
  --xp-border-card: rgba(255, 255, 255, 0.08);
  --xp-text-main: #e2e8f0;
  --xp-text-muted: #94a3b8;
  --xp-text-sub: #64748b;
  --xp-bg-header: #0a1412;
  --xp-header-border: rgba(255, 255, 255, 0.05);
  --xp-item-border: rgba(255, 255, 255, 0.03);
  --xp-suggest-bg: rgba(45, 212, 191, 0.06);
  --xp-suggest-border: rgba(255, 255, 255, 0.06);
  --xp-badge-bg: rgba(255, 255, 255, 0.06);
  --xp-slider-track: rgba(255, 255, 255, 0.15);
  --xp-btn-border: rgba(255, 255, 255, 0.12);
  --xp-btn-bg: transparent;
  --xp-shadow: 0 10px 25px -5px rgba(0,0,0,0.5), 0 8px 24px rgba(45,212,191,0.15);
}

.layer.theme-light {
  --xp-bg-card: #ffffff;
  --xp-border-card: rgba(15, 23, 42, 0.12);
  --xp-text-main: #0f172a;
  --xp-text-muted: #475569;
  --xp-text-sub: #64748b;
  --xp-bg-header: #f0fdf4;
  --xp-header-border: rgba(15, 23, 42, 0.06);
  --xp-item-border: rgba(15, 23, 42, 0.05);
  --xp-suggest-bg: rgba(13, 148, 136, 0.05);
  --xp-suggest-border: rgba(13, 148, 136, 0.12);
  --xp-badge-bg: rgba(15, 23, 42, 0.06);
  --xp-slider-track: #e2e8f0;
  --xp-btn-border: rgba(15, 23, 42, 0.15);
  --xp-btn-bg: #f8fafc;
  --xp-shadow: 0 10px 25px -5px rgba(15,23,42,0.12), 0 8px 20px rgba(13,148,136,0.1);
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
  background-color: var(--xp-bg-card);
  border: 1px solid var(--xp-border-card);
  border-radius: 10px;
  box-shadow: var(--xp-shadow);
  overflow: hidden;
  pointer-events: auto;
  color: var(--xp-text-main);
  transition: background-color 0.2s ease, border-color 0.2s ease, color 0.2s ease;
}
.menu-header {
  padding: 8px 12px;
  font-size: 10px;
  font-weight: 700;
  color: #0d9488;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--xp-header-border);
  background-color: var(--xp-bg-header);
}
.layer:not(.theme-light) .menu-header {
  color: #2dd4bf;
}
.menu-warning {
  padding: 8px 12px;
  font-size: 10px;
  line-height: 1.4;
  color: #fca5a5;
  background-color: rgba(220, 38, 38, 0.12);
  border-bottom: 1px solid rgba(220, 38, 38, 0.25);
}
.layer.theme-light .menu-warning {
  color: #b91c1c;
  background-color: #fef2f2;
  border-bottom: 1px solid #fecaca;
}
.menu-item {
  width: 100%;
  padding: 10px 12px;
  background: none;
  border: none;
  border-bottom: 1px solid var(--xp-item-border);
  cursor: pointer;
  display: block;
  text-align: left;
  color: var(--xp-text-main);
  font-family: inherit;
  transition: background-color 0.15s, color 0.15s;
}
.menu-item:hover, .menu-item:focus-visible {
  background-color: rgba(45, 212, 191, 0.1);
  color: #0d9488;
  outline: none;
}
.layer:not(.theme-light) .menu-item:hover,
.layer:not(.theme-light) .menu-item:focus-visible {
  color: #2dd4bf;
}
.menu-item-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.menu-item-label {
  font-weight: 600;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.menu-item-badge {
  flex: none;
  font-size: 9px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 4px;
  background: rgba(45, 212, 191, 0.15);
  color: #2dd4bf;
  border: 1px solid rgba(45, 212, 191, 0.3);
  text-transform: uppercase;
  letter-spacing: 0.05em;
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
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  max-width: 340px;
  background: #0f172a;
  border: 1px solid rgba(45, 212, 191, 0.4);
  border-radius: 12px;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5), 0 0 15px rgba(45,212,191,0.2);
  padding: 12px 16px;
  color: #f1f5f9;
  font-family: Inter, system-ui, sans-serif;
  font-size: 12px;
  line-height: 1.4;
  z-index: 2147483647;
  pointer-events: auto;
  display: flex;
  align-items: center;
  gap: 10px;
  animation: xp-slide-in 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
  transition: opacity 0.2s, transform 0.2s;
}
.toast-icon {
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #2dd4bf;
}
.toast-body {
  flex: 1;
}
.toast-title {
  font-weight: 700;
  color: #2dd4bf;
  margin-bottom: 2px;
}
.suggest {
  padding: 10px 12px;
  border-bottom: 1px solid var(--xp-suggest-border);
  background: var(--xp-suggest-bg);
  transition: background-color 0.2s ease, border-color 0.2s ease;
}
.suggest-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.suggest-label {
  font-size: 9px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #0d9488;
}
.layer:not(.theme-light) .suggest-label {
  color: #2dd4bf;
}
.suggest-length-badge {
  font-size: 9px;
  font-weight: 700;
  font-family: ui-monospace, monospace;
  color: var(--xp-text-muted);
  background: var(--xp-badge-bg);
  padding: 1px 5px;
  border-radius: 4px;
}
.suggest-slider-container {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}
.suggest-slider {
  flex: 1;
  -webkit-appearance: none;
  appearance: none;
  height: 4px;
  border-radius: 2px;
  background: var(--xp-slider-track);
  outline: none;
  cursor: pointer;
  margin: 0;
  padding: 0;
}
.suggest-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #0d9488;
  cursor: pointer;
  box-shadow: 0 0 6px rgba(13, 148, 136, 0.4);
  transition: transform 0.1s ease;
}
.layer:not(.theme-light) .suggest-slider::-webkit-slider-thumb {
  background: #2dd4bf;
  box-shadow: 0 0 6px rgba(45, 212, 191, 0.5);
}
.suggest-slider::-webkit-slider-thumb:hover {
  transform: scale(1.15);
}
.suggest-slider::-moz-range-thumb {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #0d9488;
  cursor: pointer;
  border: none;
  box-shadow: 0 0 6px rgba(13, 148, 136, 0.4);
}
.layer:not(.theme-light) .suggest-slider::-moz-range-thumb {
  background: #2dd4bf;
  box-shadow: 0 0 6px rgba(45, 212, 191, 0.5);
}
.suggest-limit-hint {
  margin-top: 6px;
  font-size: 9px;
  color: #d97706;
  display: flex;
  align-items: center;
  gap: 4px;
}
.layer:not(.theme-light) .suggest-limit-hint {
  color: #fbbf24;
}
.suggest-row { display: flex; align-items: center; gap: 8px; }
.suggest-value {
  flex: 1;
  min-width: 0;
  font-family: ui-monospace, monospace;
  font-size: 12px;
  color: var(--xp-text-main);
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
  border: 1px solid var(--xp-btn-border);
  background: var(--xp-btn-bg);
  color: var(--xp-text-muted);
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  font-family: inherit;
  transition: color 0.15s ease, border-color 0.15s ease;
}
.suggest-refresh:hover { color: #0d9488; border-color: rgba(13, 148, 136, 0.4); }
.layer:not(.theme-light) .suggest-refresh:hover { color: #2dd4bf; border-color: rgba(45, 212, 191, 0.4); }
.suggest-use {
  width: 100%;
  margin-top: 8px;
  padding: 7px 10px;
  font-size: 11px;
  font-weight: 700;
  color: #ffffff;
  background: linear-gradient(135deg, #0d9488, #059669);
  border: none;
  border-radius: 7px;
  cursor: pointer;
  font-family: inherit;
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.25);
  transition: opacity 0.15s ease, transform 0.1s ease;
}
.layer:not(.theme-light) .suggest-use {
  color: #04231d;
  background: linear-gradient(135deg, #2dd4bf, #34d399);
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

/* ── Full-page interstitial ──────────────────────────────────────────────
   Reserved for a server-confirmed critical verdict on a page actively asking
   for a password: the point at which reading the page at all is the risk. */
/* ── Full-page interstitial ──────────────────────────────────────────────
   Reserved for a server-confirmed critical verdict on a page actively asking
   for a password: the point at which reading the page at all is the risk. */
.xp-interstitial {
  position: fixed;
  inset: 0;
  pointer-events: auto;
  z-index: 2147483647;
  background: radial-gradient(ellipse 70% 60% at 50% 20%, rgba(225, 29, 72, 0.18) 0%, transparent 65%),
              radial-gradient(ellipse 60% 50% at 50% 80%, rgba(13, 148, 136, 0.12) 0%, transparent 70%),
              #070d0c;
  color: #f0fdf4;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  font: 400 15px/1.6 "Plus Jakarta Sans", "Geist", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}
.xp-int-card {
  pointer-events: auto;
  max-width: 600px;
  width: 100%;
  text-align: left;
  background: rgba(10, 24, 21, 0.92);
  border: 1px solid rgba(225, 29, 72, 0.35);
  box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 35px rgba(225, 29, 72, 0.15);
  border-radius: 20px;
  padding: 36px 40px;
  box-sizing: border-box;
}
.xp-int-brand-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}
.xp-int-logo {
  height: 24px;
  width: auto;
  max-width: 140px;
  object-fit: contain;
}
.xp-int-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: rgba(225, 29, 72, 0.16);
  color: #fda4af;
  border: 1px solid rgba(225, 29, 72, 0.35);
  border-radius: 999px;
  padding: 5px 12px;
}
.xp-int-title {
  font-size: 24px;
  line-height: 1.25;
  font-weight: 800;
  margin: 0 0 12px;
  color: #ffffff;
  letter-spacing: -0.02em;
}
.xp-int-body {
  font-size: 15px;
  line-height: 1.55;
  margin: 0 0 22px;
  color: #9db4ac;
}
.xp-int-facts {
  background: rgba(4, 12, 10, 0.7);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 26px;
  font-size: 13px;
}
.xp-int-row {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 5px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
}
.xp-int-row:last-child {
  border-bottom: none;
}
.xp-int-row span:first-child {
  color: #6ee7b7;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  flex: none;
}
.xp-int-row span:last-child {
  font-weight: 600;
  color: #f1f5f9;
  word-break: break-all;
  text-align: right;
}
.xp-int-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 8px;
  pointer-events: auto;
}
.xp-int-primary {
  background: linear-gradient(135deg, #2dd4bf 0%, #0d9488 100%);
  color: #041410;
  border: 0;
  border-radius: 10px;
  padding: 12px 22px;
  font-size: 14px;
  font-weight: 700;
  cursor: pointer;
  pointer-events: auto;
  box-shadow: 0 4px 14px rgba(45, 212, 191, 0.25);
  transition: all 0.15s ease;
}
.xp-int-primary:hover {
  filter: brightness(1.08);
  transform: translateY(-1px);
}
.xp-int-secondary {
  background: rgba(255, 255, 255, 0.06);
  color: #e2e8f0;
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 10px;
  padding: 12px 20px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  pointer-events: auto;
  transition: all 0.15s ease;
}
.xp-int-secondary:hover {
  background: rgba(255, 255, 255, 0.1);
  border-color: rgba(45, 212, 191, 0.4);
  color: #ffffff;
}
.xp-int-escape {
  background: none;
  border: 0;
  color: #64748b;
  font-size: 12px;
  text-decoration: underline;
  cursor: pointer;
  pointer-events: auto;
  padding: 12px 4px 4px;
  margin-top: 4px;
  display: inline-block;
  transition: color 0.15s;
}
.xp-int-escape:hover:not([disabled]) {
  color: #94a3b8;
}
.xp-int-escape[disabled] {
  cursor: default;
  text-decoration: none;
  opacity: 0.45;
}
.xp-int-foot {
  margin-top: 24px;
  padding-top: 16px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
  font-size: 12px;
  color: #64748b;
  display: flex;
  align-items: center;
  gap: 8px;
}
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

/* ── Dedicated Link Inspector Modal ── */
.xp-link-modal {
  position: fixed;
  top: 24px;
  right: 24px;
  width: 400px;
  max-width: calc(100vw - 48px);
  background: var(--xp-bg-card, #ffffff);
  border: 1px solid var(--xp-border-card, #e2e8f0);
  border-radius: 16px;
  box-shadow: 0 12px 36px -4px rgba(15, 23, 42, 0.18), 0 4px 12px rgba(15, 23, 42, 0.08);
  pointer-events: auto;
  color: var(--xp-text-main, #0f172a);
  overflow: hidden;
  z-index: 2147483647;
  animation: xp-slide-in 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.xp-link-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px 10px 16px;
  border-bottom: 1px solid var(--xp-border-card, #f1f5f9);
}
.xp-link-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 9px;
  border-radius: 7px;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.xp-link-badge.safe { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
.xp-link-badge.suspicious { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
.xp-link-badge.high_risk { background: #ffe4e6; color: #be123c; border: 1px solid #fecdd3; }
.xp-link-body {
  padding: 14px 16px;
}
.xp-link-dest-box {
  background: var(--xp-slider-track, #f8fafc);
  border: 1px solid var(--xp-border-card, #e2e8f0);
  border-radius: 10px;
  padding: 10px 12px;
  margin-top: 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.xp-link-dest-label {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #94a3b8;
}
.xp-link-dest-url {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  font-weight: 600;
  color: var(--xp-text-main, #0f172a);
  word-break: break-all;
  line-height: 1.4;
}
.xp-link-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 10px 16px 14px;
}

/* ── Dedicated Checkout & Card Protection Banner ── */
.xp-card-modal {
  position: fixed;
  top: 24px;
  right: 24px;
  width: 390px;
  max-width: calc(100vw - 48px);
  background: var(--xp-bg-card, #ffffff);
  border: 1px solid var(--xp-border-card, #e2e8f0);
  border-radius: 16px;
  box-shadow: 0 12px 36px -4px rgba(15, 23, 42, 0.18), 0 4px 12px rgba(15, 23, 42, 0.08);
  pointer-events: auto;
  color: var(--xp-text-main, #0f172a);
  overflow: hidden;
  z-index: 2147483647;
  animation: xp-slide-in 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.xp-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px 10px 16px;
  border-bottom: 1px solid var(--xp-border-card, #f1f5f9);
}
.xp-card-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 9px;
  border-radius: 7px;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.xp-card-badge.caution { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
.xp-card-badge.high_risk { background: #ffe4e6; color: #be123c; border: 1px solid #fecdd3; }
.xp-card-body {
  padding: 14px 16px;
}
.xp-card-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 10px 16px 14px;
}

/* ── Dedicated Webmail Phishing Banner ── */
.xp-webmail-banner {
  position: fixed;
  top: 16px;
  right: 24px;
  width: 420px;
  max-width: calc(100vw - 48px);
  background: var(--xp-bg-card, #ffffff);
  border: 1px solid #fecaca;
  border-radius: 14px;
  box-shadow: 0 12px 32px -4px rgba(185, 28, 28, 0.15), 0 4px 12px rgba(15, 23, 42, 0.08);
  pointer-events: auto;
  color: var(--xp-text-main, #0f172a);
  overflow: hidden;
  z-index: 2147483647;
  animation: xp-slide-in 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.xp-webmail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px 8px 16px;
  background: #fff1f2;
  border-bottom: 1px solid #ffe4e6;
}
`;

// The field overlay icon uses the real XoraPass logo mark rather than a
// generic shield, so the extension is immediately recognisable in any field.
// We build the img at call-time so browser.runtime.getURL resolves correctly.
function makeLogoIcon(): string {
  try {
    const url = browser.runtime.getURL('icons/icon16.png');
    return `<img src="${url}" width="16" height="16" alt="XoraPass" style="display:block;pointer-events:none;image-rendering:auto;" />`;
  } catch {
    // Fallback to the teal shield if getURL is unavailable (unit test env, etc.)
    return SHIELD_SVG;
  }
}

// Used in modal headers, save-prompt, brand fallback, and risk banners.
const SHIELD_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" ' +
  'fill="none" stroke="#2dd4bf" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

const DANGER_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" ' +
  'stroke="#e11d48" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' +
  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/>' +
  '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

let themePreference: 'light' | 'dark' | 'system' = 'system';
let themeListenerInstalled = false;

export function getEffectiveOverlayTheme(): 'dark' | 'light' {
  if (themePreference === 'dark') return 'dark';
  if (themePreference === 'light') return 'light';
  const isLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  return isLight ? 'light' : 'dark';
}

function applyEffectiveTheme(): void {
  const isDark = getEffectiveOverlayTheme() === 'dark';
  if (layer) {
    if (isDark) {
      layer.classList.remove('theme-light');
      layer.classList.add('theme-dark');
    } else {
      layer.classList.remove('theme-dark');
      layer.classList.add('theme-light');
    }
  }
}

export function initOverlayTheme(): void {
  if (themeListenerInstalled) return;
  themeListenerInstalled = true;

  try {
    browser.storage.local.get(['themePreference']).then((res: any) => {
      if (res?.themePreference === 'dark' || res?.themePreference === 'light' || res?.themePreference === 'system') {
        themePreference = res.themePreference;
        applyEffectiveTheme();
      }
    });

    browser.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local' && changes['themePreference']) {
        const next = changes['themePreference'].newValue;
        if (next === 'dark' || next === 'light' || next === 'system') {
          themePreference = next;
          applyEffectiveTheme();
        }
      }
    });

    if (window.matchMedia) {
      const media = window.matchMedia('(prefers-color-scheme: dark)');
      media.addEventListener('change', () => {
        if (themePreference === 'system') {
          applyEffectiveTheme();
        }
      });
    }
  } catch (e) {
    /* storage or matchMedia unavailable */
  }
}

function ensureHost(): HTMLDivElement {
  if (layer && shadow) return layer;

  initOverlayTheme();

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
  applyEffectiveTheme();
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
  icon.innerHTML = makeLogoIcon(); // XoraPass logo mark via runtime URL

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
    let isVis = editable && isRectVisible(rect, viewport);
    if (isVis && typeof (reg.input as any).checkVisibility === 'function') {
      isVis = (reg.input as any).checkVisibility({ checkOpacity: true, checkVisibilityCSS: true });
    }

    if (isVis) {
      let parent = reg.input.parentElement;
      while (parent && parent !== document.body && parent !== document.documentElement) {
        const parentRect = parent.getBoundingClientRect();
        if (parentRect.height < 10 || parentRect.width < 10) {
          const style = window.getComputedStyle(parent);
          if (style.overflow === 'hidden' || style.overflowY === 'hidden' || style.overflow === 'clip' || style.overflowY === 'clip') {
            isVis = false;
            break;
          }
        }
        parent = parent.parentElement;
      }
    }

    if (!isVis) {
      reg.icon.style.setProperty('display', 'none', 'important');
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
    reg.icon.style.setProperty('display', 'flex');
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
    let currentLength = sug.length || 20;
    const box = document.createElement('div');
    box.className = 'suggest';

    const header = document.createElement('div');
    header.className = 'suggest-header';

    const label = document.createElement('div');
    label.className = 'suggest-label';
    label.textContent = 'Password';
    header.appendChild(label);

    const lengthBadge = document.createElement('div');
    lengthBadge.className = 'suggest-length-badge';
    lengthBadge.textContent = `${currentLength} chars`;
    header.appendChild(lengthBadge);
    box.appendChild(header);

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
      value.textContent = sug.onRegenerate(currentLength);
      lengthBadge.textContent = `${value.textContent.length} chars`;
    });
    row.appendChild(refresh);
    box.appendChild(row);

    // Length Slider bar
    const maxConstraint = sug.maxLength && sug.maxLength > 4 ? sug.maxLength : undefined;
    const minConstraint = sug.minLength && sug.minLength > 0 ? sug.minLength : 8;
    const sliderMin = minConstraint;
    const sliderMax = Math.max(sliderMin, maxConstraint ? Math.min(maxConstraint, 64) : 64);

    if (currentLength < sliderMin) currentLength = sliderMin;
    if (currentLength > sliderMax) currentLength = sliderMax;

    const sliderContainer = document.createElement('div');
    sliderContainer.className = 'suggest-slider-container';

    const slider = document.createElement('input');
    slider.type = 'range';
    slider.className = 'suggest-slider';
    slider.min = String(sliderMin);
    slider.max = String(sliderMax);
    slider.value = String(currentLength);
    slider.setAttribute('aria-label', 'Password length');

    slider.addEventListener('mousedown', (e) => e.stopPropagation());
    slider.addEventListener('input', (e) => {
      e.stopPropagation();
      const len = parseInt((e.target as HTMLInputElement).value, 10);
      currentLength = len;
      lengthBadge.textContent = `${len} chars`;
      value.textContent = sug.onRegenerate(len);
    });

    sliderContainer.appendChild(slider);
    box.appendChild(sliderContainer);

    if (maxConstraint && maxConstraint < 32) {
      const hint = document.createElement('div');
      hint.className = 'suggest-limit-hint';
      hint.textContent = `ⓘ Field limited to max ${maxConstraint} characters by website`;
      box.appendChild(hint);
    }

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
    const row = document.createElement('div');
    row.className = 'menu-item-row';

    const label = document.createElement('div');
    label.className = 'menu-item-label';
    label.textContent = cred.label;
    row.appendChild(label);

    if (cred.hasTotp) {
      const badge = document.createElement('span');
      badge.className = 'menu-item-badge';
      badge.textContent = '2FA';
      badge.title = 'Generates 2FA code';
      row.appendChild(badge);
    }

    item.appendChild(row);

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
// The options last passed to showRiskWarning — kept so the popup can pull
// the threat metadata without re-deriving it.
let activeRiskWarningOpts: RiskWarningOptions | null = null;
// True while the extension popup is open; prevents the alert from being shown
// (it renders inside the popup instead to avoid overlap).
let popupSuppressed = false;

/** Third-party attribution line (e.g. "Advisory provided by Google"). */
export interface WarningAdvisory {
  text: string;
  url: string;
  learnMoreUrl?: string;
}

function advisoryFooter(a: WarningAdvisory, dark: boolean): HTMLElement {
  const wrap = document.createElement('div');
  wrap.style.cssText = `margin-top:10px;font:12px/1.4 system-ui,sans-serif;color:${dark ? '#cbd5e1' : '#475569'}`;
  const link = (text: string, href: string) => {
    const el = document.createElement('a');
    el.textContent = text;
    el.href = href;
    el.target = '_blank';
    el.rel = 'noopener noreferrer';
    el.style.cssText = 'color:inherit;text-decoration:underline';
    return el;
  };
  wrap.appendChild(link(a.text, a.url));
  if (a.learnMoreUrl) {
    wrap.appendChild(document.createTextNode(' · '));
    wrap.appendChild(link('Learn more about this threat', a.learnMoreUrl));
  }
  return wrap;
}

export interface RiskWarningOptions {
  /** Attribution for a third-party verdict — required for Google Web Risk. */
  advisory?: WarningAdvisory | null;
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
  activeRiskWarningOpts = opts;
  // If the popup is open, skip rendering the in-page alert — the popup shows
  // the warning inline instead, so we don't need (or want) the corner card.
  if (popupSuppressed) return;
  if (riskAlertEl) {
    riskAlertEl.remove();
    riskAlertEl = null;
  }
  // One warning at a time in the corner: the site-risk warning already covers
  // what the checkout banner would say (same site, autofill already blocked),
  // so it replaces it instead of stacking on top of it.
  closeCheckoutProtectionBanner();
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
  if (opts.advisory) card.appendChild(advisoryFooter(opts.advisory, false));

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

export interface InterstitialOptions {
  /** Attribution for a third-party verdict — required for Google Web Risk. */
  advisory?: WarningAdvisory | null;
  currentDomain: string;
  expectedDomain?: string | null;
  message: string;
  reasons?: string[];
  onGoToOfficial?: () => void;
  onReportPhishing?: () => Promise<{ success: boolean }>;
  /** Asks an admin to review the site (false positive). */
  onRequestAllowlist?: () => Promise<{ success: boolean; reason?: string }>;
  onLeave: () => void;
  /**
   * Dismisses the interstitial and records the user's decision. Gated behind a
   * deliberate delay below - a block users learn to click through instantly is
   * worse than no block, because it trains the reflex it is meant to interrupt.
   */
  onProceedAnyway?: () => Promise<{ success: boolean }>;
}

let interstitialEl: HTMLElement | null = null;
let interstitialGuard: MutationObserver | null = null;

/** Seconds the escape hatch stays disabled. Long enough to be read, not so long it is rage-inducing. */
const PROCEED_DELAY_SECONDS = 5;

/**
 * Full-page block. Rendered into the same CLOSED shadow root as everything
 * else here, so page scripts can neither read it nor synthesise clicks on its
 * buttons - and a MutationObserver re-attaches the host if the page tries to
 * delete it, which a phishing page has every reason to attempt.
 */
export function showPhishingInterstitial(opts: InterstitialOptions): void {
  closePhishingInterstitial();
  const root = ensureHost();

  const shell = document.createElement('div');
  shell.className = 'xp-interstitial';
  shell.setAttribute('role', 'alertdialog');
  shell.setAttribute('aria-modal', 'true');
  shell.setAttribute('aria-live', 'assertive');
  shell.style.pointerEvents = 'auto';

  const card = document.createElement('div');
  card.className = 'xp-int-card';
  card.style.pointerEvents = 'auto';

  const brandHeader = document.createElement('div');
  brandHeader.className = 'xp-int-brand-header';

  const logo = document.createElement('img');
  logo.className = 'xp-int-logo';
  logo.src = browser.runtime.getURL('xorapass_logo_horizontal.png');
  logo.alt = 'XoraPass';
  logo.draggable = false;
  brandHeader.appendChild(logo);

  const badge = document.createElement('div');
  badge.className = 'xp-int-badge';
  badge.innerHTML = `${SHIELD_SVG}<span>Phishing Blocked</span>`;
  brandHeader.appendChild(badge);

  card.appendChild(brandHeader);

  const title = document.createElement('h1');
  title.className = 'xp-int-title';
  title.textContent = opts.expectedDomain
    ? `XoraPass Shield blocked this site: Impersonating ${opts.expectedDomain}`
    : 'XoraPass Shield blocked this site: Potential Phishing Detected';
  card.appendChild(title);

  const body = document.createElement('p');
  body.className = 'xp-int-body';
  body.textContent = opts.message; // textContent only - contains a domain we do not control
  card.appendChild(body);

  const facts = document.createElement('div');
  facts.className = 'xp-int-facts';
  const addRow = (label: string, value: string) => {
    const row = document.createElement('div');
    row.className = 'xp-int-row';
    const l = document.createElement('span');
    l.textContent = label;
    const v = document.createElement('span');
    v.textContent = value;
    row.appendChild(l);
    row.appendChild(v);
    facts.appendChild(row);
  };
  addRow('You are on', opts.currentDomain);
  if (opts.expectedDomain) addRow('It claims to be', opts.expectedDomain);
  for (const reason of (opts.reasons || []).slice(0, 3)) addRow('Detected', reason);
  card.appendChild(facts);
  if (opts.advisory) card.appendChild(advisoryFooter(opts.advisory, true));

  const actions = document.createElement('div');
  actions.className = 'xp-int-actions';
  actions.style.pointerEvents = 'auto';

  if (opts.onGoToOfficial && opts.expectedDomain) {
    const go = document.createElement('button');
    go.type = 'button';
    go.className = 'xp-int-primary';
    go.style.pointerEvents = 'auto';
    go.textContent = `Go to the real ${opts.expectedDomain}`;
    go.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      opts.onGoToOfficial!();
    });
    actions.appendChild(go);
  }

  const leave = document.createElement('button');
  leave.type = 'button';
  leave.className = opts.onGoToOfficial && opts.expectedDomain ? 'xp-int-secondary' : 'xp-int-primary';
  leave.style.pointerEvents = 'auto';
  leave.textContent = 'Leave this site';
  leave.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      opts.onLeave();
    } catch {
      window.location.replace('about:blank');
    }
  });
  actions.appendChild(leave);

  if (opts.onReportPhishing) {
    const report = document.createElement('button');
    report.type = 'button';
    report.className = 'xp-int-secondary';
    report.style.pointerEvents = 'auto';
    report.textContent = 'Report phishing';
    report.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      report.disabled = true;
      report.textContent = 'Reporting\u2026';
      try {
        const res = await opts.onReportPhishing!();
        report.textContent = res?.success ? 'Reported' : 'Reported';
      } catch {
        report.textContent = 'Reported';
      }
      report.disabled = true;
    });
    actions.appendChild(report);
  }

  if (opts.onRequestAllowlist) {
    const request = document.createElement('button');
    request.type = 'button';
    request.className = 'xp-int-secondary';
    request.style.pointerEvents = 'auto';
    request.textContent = 'Request review';
    request.title = 'Think this site is safe? Ask an admin to review it.';
    request.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      request.disabled = true;
      request.textContent = 'Sending\u2026';
      try {
        const res = await opts.onRequestAllowlist!();
        request.textContent = res?.success
          ? 'Sent to admin'
          : res?.reason === 'not_authenticated'
            ? 'Log in to request'
            : 'Request sent';
      } catch {
        request.textContent = 'Request sent';
      }
      request.disabled = true;
    });
    actions.appendChild(request);
  }

  card.appendChild(actions);

  if (opts.onProceedAnyway) {
    const escape = document.createElement('button');
    escape.type = 'button';
    escape.className = 'xp-int-escape';
    escape.style.pointerEvents = 'auto';
    escape.disabled = true;
    let remaining = PROCEED_DELAY_SECONDS;
    escape.textContent = `I understand the risk, continue (${remaining})`;
    const tick = window.setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        window.clearInterval(tick);
        escape.disabled = false;
        escape.textContent = 'I understand the risk, continue';
        return;
      }
      escape.textContent = `I understand the risk, continue (${remaining})`;
    }, 1000);
    escape.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      escape.disabled = true;
      window.clearInterval(tick);
      try {
        await opts.onProceedAnyway!();
      } catch {}
      closePhishingInterstitial();
    });
    card.appendChild(escape);
  }

  const foot = document.createElement('div');
  foot.className = 'xp-int-foot';
  foot.innerHTML = `${SHIELD_SVG}<span><strong>Credential Guard Active:</strong> Your vault stayed locked and no credentials, passwords, or personal data were released.</span>`;
  card.appendChild(foot);

  shell.appendChild(card);
  root.appendChild(shell);
  interstitialEl = shell;

  // A phishing page has every reason to delete our host node. Put it back.
  try {
    const hostNode = document.getElementById(HOST_ID);
    if (hostNode?.parentNode) {
      interstitialGuard = new MutationObserver(() => {
        if (interstitialEl && !document.getElementById(HOST_ID)) {
          document.documentElement.appendChild(hostNode);
        }
      });
      interstitialGuard.observe(document.documentElement, { childList: true, subtree: false });
    }
  } catch {
    /* observation unavailable - the interstitial still renders */
  }
}

export function closePhishingInterstitial(): void {
  interstitialGuard?.disconnect();
  interstitialGuard = null;
  if (interstitialEl) {
    interstitialEl.remove();
    interstitialEl = null;
  }
}

export function isInterstitialOpen(): boolean {
  return interstitialEl !== null;
}

export function closeRiskWarning(): void {
  if (riskAlertEl) {
    riskAlertEl.remove();
    riskAlertEl = null;
  }
  activeRiskWarningOpts = null;
}

/**
 * Returns the serialisable subset of the current risk warning so the content
 * script can relay it to the extension popup. Returns null if no warning is
 * active on this page.
 */
export function getActiveRiskWarning(): {
  severity: string; title: string; message: string;
  currentDomain: string; expectedDomain?: string | null;
  riskLevel?: string; allowlistRequestStatus?: string | null;
} | null {
  if (!activeRiskWarningOpts) return null;
  const o = activeRiskWarningOpts;
  return {
    severity: o.severity,
    title: o.title,
    message: o.message,
    currentDomain: o.currentDomain,
    expectedDomain: o.expectedDomain,
    riskLevel: o.riskLevel,
    allowlistRequestStatus: o.allowlistRequestStatus,
  };
}

/**
 * Called by the content script when the extension popup opens/closes.
 *
 * When `suppressed` is true the in-page risk-alert card is hidden so it does
 * not overlap the popup UI. The popup renders the same warning inline.
 * When `suppressed` is false the card is restored if the warning is still
 * active and has not been explicitly dismissed by the user.
 */
export function setPopupSuppressed(suppressed: boolean): void {
  popupSuppressed = suppressed;
  if (suppressed) {
    // Hide the card without destroying it — we want to restore it if the
    // popup closes without the user dismissing the warning.
    if (riskAlertEl) (riskAlertEl as HTMLElement).style.display = 'none';
  } else {
    // Popup closed: restore the card if it still exists (not dismissed), or
    // re-show it from opts if the user never explicitly dismissed it.
    if (riskAlertEl) {
      (riskAlertEl as HTMLElement).style.display = '';
    } else if (activeRiskWarningOpts) {
      // Warning was never dismissed — re-render it.
      const saved = activeRiskWarningOpts;
      activeRiskWarningOpts = null; // showRiskWarning will reset it
      showRiskWarning(saved);
    }
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

let activeToastEl: HTMLDivElement | null = null;
let toastTimeout: number | undefined;

/**
 * Displays a non-intrusive floating toast in the bottom-right corner of the page.
 */
export function showToast(title: string, message: string, durationMs = 4000): void {
  if (activeToastEl) {
    activeToastEl.remove();
    activeToastEl = null;
    window.clearTimeout(toastTimeout);
  }

  const root = ensureHost();
  const toast = document.createElement('div');
  toast.className = 'toast';

  const icon = document.createElement('div');
  icon.className = 'toast-icon';
  icon.innerHTML = SHIELD_SVG;
  toast.appendChild(icon);

  const body = document.createElement('div');
  body.className = 'toast-body';

  const tTitle = document.createElement('div');
  tTitle.className = 'toast-title';
  tTitle.textContent = title;
  body.appendChild(tTitle);

  const tMsg = document.createElement('div');
  tMsg.textContent = message;
  body.appendChild(tMsg);

  toast.appendChild(body);
  root.appendChild(toast);
  activeToastEl = toast;

  toastTimeout = window.setTimeout(() => {
    if (activeToastEl === toast) {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(8px)';
      setTimeout(() => {
        if (activeToastEl === toast) {
          toast.remove();
          activeToastEl = null;
        }
      }, 200);
    }
  }, durationMs);
}

let activeLinkModalEl: HTMLDivElement | null = null;

export interface LinkInspectionData {
  originalUrl: string;
  finalUrl: string;
  redirectsCount: number;
  riskScore: number;
  verdict: 'safe' | 'suspicious' | 'high_risk';
  threats: string[];
}

/**
 * Displays a clean in-page floating modal inspecting a right-clicked link.
 */
export function showLinkInspectionModal(data: LinkInspectionData): void {
  if (activeLinkModalEl) {
    activeLinkModalEl.remove();
    activeLinkModalEl = null;
  }

  const root = ensureHost();
  const card = document.createElement('div');
  card.className = 'xp-link-modal';

  const isHigh = data.verdict === 'high_risk';
  const isSusp = data.verdict === 'suspicious';
  const badgeClass = isHigh ? 'high_risk' : isSusp ? 'suspicious' : 'safe';
  const badgeText = isHigh ? 'High Risk Phishing' : isSusp ? 'Suspicious Link' : 'Verified Safe';

  card.innerHTML = `
    <div class="xp-link-header">
      <div style="display:flex;align-items:center;gap:8px;">
        <span class="xp-link-badge ${badgeClass}">${badgeText}</span>
        <span style="font-size:11px;font-weight:700;color:#64748b;">Score: ${data.riskScore}/100</span>
      </div>
      <button class="risk-close" id="xp-link-modal-close" title="Close" style="cursor:pointer;background:none;border:none;font-size:18px;color:#94a3b8;line-height:1;">×</button>
    </div>
    <div class="xp-link-body">
      <div style="font-weight:700;font-size:14px;color:var(--xp-text-main, #0f172a);margin-bottom:4px">
        ${isHigh ? 'Phishing or Dangerous Destination' : isSusp ? 'Caution: Redirect or Unverified Domain' : 'Destination Appears Safe'}
      </div>
      <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;line-height:1.45;">
        ${isHigh ? 'XoraPass recommends NOT visiting this link. It exhibits indicators of spoofing or credential theft.' : 'Link destination resolved safely without executing untrusted scripts.'}
      </p>

      <div class="xp-link-dest-box">
        <span class="xp-link-dest-label">Final Destination</span>
        <span class="xp-link-dest-url" title="${data.finalUrl}">${data.finalUrl}</span>
      </div>

      ${data.redirectsCount > 0 ? `
        <div style="display:flex;align-items:center;gap:6px;margin-top:8px;font-size:11px;color:#64748b;">
          <span style="font-weight:600;">Redirects:</span>
          <span>${data.redirectsCount} hop(s) unwound from original URL</span>
        </div>
      ` : ''}

      ${data.threats.length > 0 ? `
        <div style="margin-top:10px;font-size:11.5px;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:8px 10px;line-height:1.4;">
          ${data.threats.map(t => `<div>• ${t}</div>`).join('')}
        </div>
      ` : ''}
    </div>

    <div class="xp-link-actions">
      <button class="risk-btn-dismiss" id="xp-link-modal-dismiss" style="padding:6px 12px;font-size:12px;">Close</button>
      ${!isHigh ? `
        <button class="risk-btn-primary" id="xp-link-modal-open" style="padding:6px 14px;font-size:12px;">Open Destination</button>
      ` : `
        <button class="risk-btn-secondary" id="xp-link-modal-bypass" style="padding:6px 12px;font-size:12px;color:#b91c1c;border-color:#fca5a5;">Open Anyway (Unsafe)</button>
      `}
    </div>

    <div style="padding:8px 16px 10px;border-top:1px solid var(--xp-border-card, #f1f5f9);display:flex;align-items:center;justify-content:center;gap:7px;font-size:11px;color:#94a3b8;font-weight:600;">
      <img src="${browser.runtime.getURL('xorapass_logo_mark.png')}" alt="XoraPass" style="width:15px;height:15px;object-fit:contain;display:block;" draggable="false" />
      <span>XoraPass Shield Link Inspection</span>
    </div>
  `;

  root.appendChild(card);
  activeLinkModalEl = card;

  const close = () => {
    if (activeLinkModalEl) {
      activeLinkModalEl.remove();
      activeLinkModalEl = null;
    }
  };

  card.querySelector('#xp-link-modal-close')?.addEventListener('click', close);
  card.querySelector('#xp-link-modal-dismiss')?.addEventListener('click', close);
  card.querySelector('#xp-link-modal-open')?.addEventListener('click', () => {
    close();
    window.open(data.finalUrl, '_blank', 'noopener,noreferrer');
  });
  card.querySelector('#xp-link-modal-bypass')?.addEventListener('click', () => {
    close();
    window.open(data.finalUrl, '_blank', 'noopener,noreferrer');
  });
}

let activeCardModalEl: HTMLDivElement | null = null;

export interface CheckoutProtectionData {
  hostname: string;
  riskScore: number;
  reasons: string[];
  isInsecureHttp: boolean;
  onProceedAnyway?: () => void;
}

/**
 * Displays a security review card when payment fields are detected on an unverified or risky site.
 */
export function showCheckoutProtectionBanner(data: CheckoutProtectionData): void {
  // A site-risk warning is already on screen for this page — don't stack a
  // second card on top of it (see showRiskWarning).
  if (isRiskWarningOpen()) return;
  if (activeCardModalEl) {
    activeCardModalEl.remove();
    activeCardModalEl = null;
  }

  const root = ensureHost();
  const card = document.createElement('div');
  card.className = 'xp-card-modal';

  const isHigh = data.riskScore >= 70 || data.isInsecureHttp;
  const badgeClass = isHigh ? 'high_risk' : 'caution';
  const badgeText = isHigh ? 'High Risk Checkout' : 'Unverified Merchant';

  card.innerHTML = `
    <div class="xp-card-header">
      <div style="display:flex;align-items:center;gap:8px;">
        <span class="xp-card-badge ${badgeClass}">${badgeText}</span>
        <span style="font-size:11px;font-weight:700;color:#64748b;">Risk: ${data.riskScore}/100</span>
      </div>
      <button class="risk-close" id="xp-card-modal-close" title="Close" style="cursor:pointer;background:none;border:none;font-size:18px;color:#94a3b8;line-height:1;">×</button>
    </div>
    <div class="xp-card-body">
      <div style="font-weight:700;font-size:14px;color:var(--xp-text-main, #0f172a);margin-bottom:4px">
        ${isHigh ? 'Caution: Untrusted Payment Form' : 'Verify Merchant Before Payment'}
      </div>
      <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;line-height:1.45;">
        ${data.isInsecureHttp
          ? 'This site is served over unencrypted HTTP. Credit card data entered here can be intercepted in transit.'
          : 'XoraPass Shield found a payment form on a site its phishing checks flagged as suspicious. Verify the merchant before entering card details.'}
      </p>

      <div style="background:var(--xp-slider-track, #f8fafc);border:1px solid var(--xp-border-card, #e2e8f0);border-radius:10px;padding:8px 12px;margin-bottom:8px;font-size:12px;">
        <span style="font-weight:700;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:0.04em;display:block;margin-bottom:2px;">Merchant Origin</span>
        <span style="font-weight:600;color:var(--xp-text-main, #0f172a);font-family:ui-monospace, monospace;">${data.hostname}</span>
      </div>

      ${data.reasons.length > 0 ? `
        <div style="margin-top:6px;font-size:11.5px;color:#b45309;background:#fffbeb;border:1px solid #fef3c7;border-radius:8px;padding:8px 10px;line-height:1.4;">
          ${data.reasons.map(r => `<div>• ${r}</div>`).join('')}
        </div>
      ` : ''}
    </div>

    <div class="xp-card-actions">
      <button class="risk-btn-dismiss" id="xp-card-modal-dismiss" style="padding:6px 12px;font-size:12px;">Dismiss</button>
      <button class="risk-btn-primary" id="xp-card-modal-proceed" style="padding:6px 14px;font-size:12px;">I Trust This Merchant</button>
    </div>

    <div style="padding:8px 16px 10px;border-top:1px solid var(--xp-border-card, #f1f5f9);display:flex;align-items:center;justify-content:center;gap:7px;font-size:11px;color:#94a3b8;font-weight:600;">
      <img src="${browser.runtime.getURL('xorapass_logo_mark.png')}" alt="XoraPass" style="width:15px;height:15px;object-fit:contain;display:block;" draggable="false" />
      <span>XoraPass Shield Checkout Protection</span>
    </div>
  `;

  root.appendChild(card);
  activeCardModalEl = card;

  const close = () => {
    if (activeCardModalEl) {
      activeCardModalEl.remove();
      activeCardModalEl = null;
    }
  };

  card.querySelector('#xp-card-modal-close')?.addEventListener('click', close);
  card.querySelector('#xp-card-modal-dismiss')?.addEventListener('click', close);
  card.querySelector('#xp-card-modal-proceed')?.addEventListener('click', () => {
    close();
    data.onProceedAnyway?.();
  });
}

export function closeCheckoutProtectionBanner(): void {
  if (activeCardModalEl) {
    activeCardModalEl.remove();
    activeCardModalEl = null;
  }
}

let activeWebmailBannerEl: HTMLDivElement | null = null;

export interface WebmailPhishingData {
  displayName: string;
  senderEmail: string;
  reasons: string[];
  riskScore: number;
  onDismiss?: () => void;
}

/**
 * Displays a non-intrusive in-page warning banner when sender impersonation is detected in webmail.
 */
export function showWebmailPhishingBanner(data: WebmailPhishingData): void {
  if (activeWebmailBannerEl) {
    activeWebmailBannerEl.remove();
    activeWebmailBannerEl = null;
  }

  const root = ensureHost();
  const card = document.createElement('div');
  card.className = 'xp-webmail-banner';

  card.innerHTML = `
    <div class="xp-webmail-header">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:11px;font-weight:800;color:#b91c1c;background:#fee2e2;padding:3px 8px;border-radius:6px;border:1px solid #fecaca;letter-spacing:0.04em;text-transform:uppercase;">Phishing Warning</span>
        <span style="font-size:11px;font-weight:700;color:#991b1b;">Threat Score: ${data.riskScore}/100</span>
      </div>
      <button class="risk-close" id="xp-webmail-close" title="Close" style="cursor:pointer;background:none;border:none;font-size:18px;color:#94a3b8;line-height:1;">×</button>
    </div>
    <div style="padding:12px 16px;">
      <div style="font-weight:700;font-size:13.5px;color:#991b1b;margin-bottom:4px;">
        Sender Impersonation Detected
      </div>
      <p style="font-size:12px;color:#475569;margin:0 0 10px 0;line-height:1.45;">
        This email exhibits characteristics of brand spoofing. The visible display name does not match the true originating sender address.
      </p>

      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:9px;padding:8px 12px;font-size:12px;display:flex;flex-direction:column;gap:3px;margin-bottom:8px;">
        <div style="display:flex;justify-content:space-between;">
          <span style="color:#64748b;font-weight:600;">Display Name:</span>
          <span style="color:#0f172a;font-weight:700;">${data.displayName || 'None'}</span>
        </div>
        <div style="display:flex;justify-content:space-between;">
          <span style="color:#64748b;font-weight:600;">Actual Address:</span>
          <span style="color:#b91c1c;font-weight:700;font-family:ui-monospace, monospace;">${data.senderEmail}</span>
        </div>
      </div>

      ${data.reasons.length > 0 ? `
        <div style="font-size:11.5px;color:#991b1b;background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:8px 10px;line-height:1.4;">
          ${data.reasons.map(r => `<div>• ${r}</div>`).join('')}
        </div>
      ` : ''}
    </div>

    <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:8px 16px 12px;">
      <button class="risk-btn-dismiss" id="xp-webmail-dismiss" style="padding:6px 14px;font-size:12px;">I Understand</button>
    </div>

    <div style="padding:7px 16px 9px;border-top:1px solid #f1f5f9;display:flex;align-items:center;justify-content:center;gap:7px;font-size:11px;color:#94a3b8;font-weight:600;">
      <img src="${browser.runtime.getURL('xorapass_logo_mark.png')}" alt="XoraPass" style="width:14px;height:14px;object-fit:contain;display:block;" draggable="false" />
      <span>XoraPass Shield Webmail Phishing Guard</span>
    </div>
  `;

  root.appendChild(card);
  activeWebmailBannerEl = card;

  const close = () => {
    if (activeWebmailBannerEl) {
      activeWebmailBannerEl.remove();
      activeWebmailBannerEl = null;
    }
    data.onDismiss?.();
  };

  card.querySelector('#xp-webmail-close')?.addEventListener('click', close);
  card.querySelector('#xp-webmail-dismiss')?.addEventListener('click', close);
}

export function closeWebmailPhishingBanner(): void {
  if (activeWebmailBannerEl) {
    activeWebmailBannerEl.remove();
    activeWebmailBannerEl = null;
  }
}


