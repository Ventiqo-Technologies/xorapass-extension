// XoraPass Shield — secure-browsing checks that run in the main content
// script (document_idle, top frame). Everything here is local: no page or
// email content leaves the device.
//
//   • Email Guard: links, attachments and Reply-To inside the OPEN message of
//     a supported webmail get inline badges (utils/emailGuard.ts), and a click
//     on a dangerous link asks first.
//   • Insecure forms: a login on a plain-HTTP page, or a form that would send
//     a password over HTTP, is flagged (and the submit confirmed).
//   • Privacy signals for the popup's privacy report: known trackers the page
//     loaded and mixed (HTTP-on-HTTPS) content.
//   • The download prompt asked for by the background download guard.

import browser from 'webextension-polyfill';
import { showRiskWarning, showConfirmDialog, closeWebmailPhishingBanner } from './overlay';
import { updateEmailInsight } from './emailInsight';
import { analyzeEmailLink, analyzeAttachmentName, type EmailFinding } from '../utils/emailGuard';
import { findEmailRoots, attachmentNames } from './webmailProviders';
import { trackerFor } from '../utils/trackerList';
import { registrableDomain } from '../utils/siteTrust';

// ── Rollout gate ───────────────────────────────────────────────────────────
// Email Guard and insecure-form warnings are always-on Shield features under
// gradual rollout; the background stores the per-user result (see
// background/shield.ts). Off until known.

let rollout: Record<string, boolean> = {};
let rolloutLoaded = false;

function readRollout(e: any, cfg: any): Record<string, boolean> {
  const fresh = e && e.active === true && Date.now() - Number(e.checkedAt || 0) < 24 * 60 * 60 * 1000;
  if (!fresh || (cfg && cfg.shield_enabled === false) || e.features?.always_on !== true) return {};
  return e.features || {};
}

function loadRollout(): void {
  if (rolloutLoaded) return;
  rolloutLoaded = true;
  const load = () =>
    browser.storage.local
      .get(['shieldEntitlement', 'shieldConfig'])
      .then((r: any) => {
        rollout = readRollout(r.shieldEntitlement, r.shieldConfig);
      })
      .catch(() => undefined);
  void load().then(rerunGatedChecks);
  try {
    browser.storage.onChanged.addListener((changes: any, area: string) => {
      if (area === 'local' && (changes.shieldEntitlement || changes.shieldConfig)) void load().then(rerunGatedChecks);
    });
  } catch {
    /* ignore */
  }
}

// The first scans usually run before the rollout state has been read from
// storage; run them again once it is known (a static page may never mutate).
let lastEmailHost: string | null = null;
function rerunGatedChecks(): void {
  if (lastEmailHost && rollout.email_guard) {
    // The panel replaces the older sender banner — close it if it got there first.
    closeWebmailPhishingBanner();
    scanEmailContent(lastEmailHost);
  }
  if (rollout.insecure_forms && window === window.top) checkInsecureForms();
}

export function featureOn(name: string): boolean {
  loadRollout();
  return rollout[name] === true;
}

// ── Email Guard ────────────────────────────────────────────────────────────

const seenLinks = new WeakSet<Element>();
const seenAttachments = new WeakSet<Element>();
const linkFindings = new WeakMap<Element, EmailFinding>();

function badge(finding: EmailFinding): HTMLElement {
  const b = document.createElement('span');
  const danger = finding.level === 'danger';
  b.textContent = danger ? '⚠ Unsafe' : '⚠ Check';
  b.title = `XoraPass: ${finding.reasons.join(' · ')}`;
  b.setAttribute('data-xorapass-badge', '1');
  b.setAttribute('role', 'note');
  b.style.cssText = [
    'display:inline-block',
    'margin:0 4px',
    'padding:0 6px',
    'border-radius:9px',
    'font:600 11px/16px system-ui,sans-serif',
    'vertical-align:middle',
    'cursor:help',
    danger ? 'background:#fde8e8;color:#b42318;border:1px solid #f5b5b0' : 'background:#fff4e0;color:#8a5300;border:1px solid #f3cf8f',
  ].join(';');
  return b;
}

function onEmailLinkClick(ev: MouseEvent): void {
  const a = (ev.target as Element | null)?.closest?.('a[href]');
  if (!a) return;
  const f = linkFindings.get(a);
  if (!f || f.level !== 'danger') return;
  ev.preventDefault();
  ev.stopImmediatePropagation();
  const href = (a as HTMLAnchorElement).href;
  void showConfirmDialog({
    title: 'This email link looks dangerous',
    body: [...f.reasons, 'Phishing emails use links like this to steal passwords and payment details.'],
    confirmLabel: 'Stay safe',
    cancelLabel: 'Open anyway',
  }).then((stay) => {
    if (!stay) window.open(href, '_blank', 'noopener,noreferrer');
  });
}

let emailTimer: ReturnType<typeof setTimeout> | null = null;
let emailLastRun = 0;

/** Throttled (the webmail DOM mutates constantly): at most every 600 ms. */
export function scanEmailContent(host: string): void {
  lastEmailHost = host;
  if (!featureOn('email_guard') || emailTimer) return;
  const wait = Math.max(0, emailLastRun + 600 - Date.now());
  emailTimer = setTimeout(() => {
    emailTimer = null;
    emailLastRun = Date.now();
    try {
      scanEmailNow(host);
    } catch {
      /* never break the webmail */
    }
  }, wait);
}

const hookedDocs = new WeakSet<Document>();

function scanEmailNow(host: string): void {
  try {
    updateEmailInsight(host);
  } catch {
    /* never break the webmail */
  }
  for (const r of findEmailRoots(host)) {
    const links = Array.from(r.root.querySelectorAll('a[href]')).slice(0, 300);
    for (const a of links) {
      if (seenLinks.has(a)) continue;
      seenLinks.add(a);
      const finding = analyzeEmailLink((a.textContent || '').trim(), (a as HTMLAnchorElement).getAttribute('href') || '');
      if (!finding) continue;
      linkFindings.set(a, finding);
      a.after(badge(finding));
    }
    // Clicks inside a message iframe don't reach the top document.
    const doc = r.root.ownerDocument;
    if (doc && !hookedDocs.has(doc)) {
      hookedDocs.add(doc);
      doc.addEventListener('click', onEmailLinkClick, true);
    }
  }
  for (const { el, name } of attachmentNames(host)) {
    if (seenAttachments.has(el)) continue;
    seenAttachments.add(el);
    const finding = analyzeAttachmentName(name || (el.textContent || '').trim());
    if (finding) el.appendChild(badge(finding));
  }
  // Reply-To mismatches are shown in the email panel (emailInsight.ts).

  // Message bodies in iframes (Proton, some generic webmails) load after the
  // parent DOM settles and don't trigger its mutation observer — rescan on load.
  for (const f of Array.from(document.querySelectorAll('iframe')).slice(0, 20)) {
    if (hookedFrames.has(f)) continue;
    hookedFrames.add(f);
    f.addEventListener('load', () => scanEmailContent(host));
  }
}
const hookedFrames = new WeakSet<Element>();

// ── Login pages with no real website behind them ───────────────────────────
// HTML "smuggling": an email attachment or download builds the phishing page
// in the browser (blob:, data:) or opens it as a local file (file:), so no
// web address — and none of the address-based checks — ever applies. A
// password field on such a page is almost always phishing. Local, not rolled
// out (near-zero false positives).

let opaqueWarned = false;

export function checkOpaqueOriginLogin(): void {
  if (opaqueWarned || !/^(blob|data|file):$/.test(location.protocol)) return;
  if (!document.querySelector('input[type="password"]')) return;
  opaqueWarned = true;
  showRiskWarning({
    severity: 'block',
    title: 'Fake Login Page',
    message:
      "This login page doesn't come from a real website — it was built from a file or email attachment. Phishing attachments use this trick to steal passwords. Don't enter anything here; close this tab.",
    currentDomain: location.protocol === 'file:' ? 'Local file' : 'No real website',
    riskLevel: 'critical',
  });
}

// ── Insecure forms ─────────────────────────────────────────────────────────

let insecureWarned = false;
const hookedForms = new WeakSet<HTMLFormElement>();

function insecureAction(form: HTMLFormElement): boolean {
  const action = form.getAttribute('action');
  if (!action) return location.protocol === 'http:';
  try {
    return new URL(action, location.href).protocol === 'http:';
  } catch {
    return false;
  }
}

export function checkInsecureForms(): void {
  if (!featureOn('insecure_forms') || !/^https?:$/.test(location.protocol)) return;
  const pwFields = Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[];
  if (!pwFields.length) return;
  const isLocal = /^(localhost|127\.|10\.|192\.168\.|\[?::1)/.test(location.hostname);
  if (isLocal) return;

  if (location.protocol === 'http:' && !insecureWarned) {
    insecureWarned = true;
    showRiskWarning({
      severity: 'warn',
      title: 'Not a Secure Connection',
      message:
        'This page asks for a password over plain HTTP. Anyone on the same network can read what you type. Only continue if you trust this network and site.',
      currentDomain: location.hostname,
      riskLevel: 'medium',
    });
  }

  for (const field of pwFields) {
    const form = field.form;
    if (!form || hookedForms.has(form)) continue;
    hookedForms.add(form);
    if (location.protocol === 'https:' && insecureAction(form) && !insecureWarned) {
      insecureWarned = true;
      showRiskWarning({
        severity: 'warn',
        title: 'Password Would Be Sent Unencrypted',
        message: 'This secure page sends its login form to an unencrypted (HTTP) address. Your password could be read on the way.',
        currentDomain: location.hostname,
        riskLevel: 'medium',
      });
    }
    let confirmed = false;
    form.addEventListener(
      'submit',
      (ev) => {
        if (confirmed || location.protocol !== 'https:' || !insecureAction(form)) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();
        void showConfirmDialog({
          title: 'Send your password unencrypted?',
          body: ['This form sends your password over HTTP, where it can be intercepted.'],
          confirmLabel: "Don't send",
          cancelLabel: 'Send anyway',
        }).then((cancel) => {
          if (!cancel) {
            confirmed = true;
            form.requestSubmit ? form.requestSubmit() : form.submit();
          }
        });
      },
      true
    );
  }
}

// ── Privacy signals (for the popup privacy report) ─────────────────────────

export interface PrivacySignals {
  trackers: { company: string; category: string; domains: string[] }[];
  mixedContent: number;
  isHttps: boolean;
  thirdPartyHosts: number;
}

export function collectPrivacySignals(): PrivacySignals {
  const own = registrableDomain(location.hostname);
  const byCompany = new Map<string, { company: string; category: string; domains: Set<string> }>();
  const thirdParty = new Set<string>();
  let mixed = 0;
  const https = location.protocol === 'https:';
  let entries: PerformanceResourceTiming[] = [];
  try {
    entries = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
  } catch {
    /* ignore */
  }
  for (const e of entries.slice(0, 2000)) {
    let u: URL;
    try {
      u = new URL(e.name);
    } catch {
      continue;
    }
    if (https && u.protocol === 'http:') mixed++;
    const rd = registrableDomain(u.hostname);
    if (!rd || rd === own) continue;
    thirdParty.add(rd);
    const t = trackerFor(u.hostname);
    if (!t) continue;
    const key = `${t.company}|${t.category}`;
    const cur = byCompany.get(key) || { company: t.company, category: t.category, domains: new Set<string>() };
    cur.domains.add(u.hostname);
    byCompany.set(key, cur);
  }
  if (https) {
    mixed += document.querySelectorAll('img[src^="http:"], script[src^="http:"], iframe[src^="http:"], link[href^="http:"][rel="stylesheet"], audio[src^="http:"], video[src^="http:"]').length;
  }
  return {
    trackers: Array.from(byCompany.values()).map((t) => ({ company: t.company, category: t.category, domains: Array.from(t.domains).slice(0, 10) })),
    mixedContent: mixed,
    isHttps: https,
    thirdPartyHosts: thirdParty.size,
  };
}

// ── Download prompt (asked by the background download guard) ──────────────

export function showDownloadPrompt(p: { filename?: string; host?: string; reasons?: string[] }): Promise<{ keep: boolean }> {
  const name = String(p.filename || 'this file').split(/[\\/]/).pop()!.slice(0, 120);
  return showConfirmDialog({
    title: `XoraPass paused a risky download`,
    body: [
      `${name}${p.host ? ` from ${p.host}` : ''}`,
      ...(Array.isArray(p.reasons) ? p.reasons.map(String).slice(0, 5) : []),
      'Only keep it if you expected this file and trust where it came from.',
    ],
    confirmLabel: 'Cancel download',
    cancelLabel: 'Keep file',
  }).then((cancel) => ({ keep: !cancel }));
}

export function showDownloadBlocked(p: { filename?: string; host?: string; reasons?: string[] }): void {
  const name = String(p.filename || 'A file').split(/[\\/]/).pop()!.slice(0, 120);
  showRiskWarning({
    severity: 'block',
    title: 'Dangerous Download Blocked',
    message: `${name}${p.host ? ` from ${p.host}` : ''} was stopped. ${(p.reasons || [])[0] || ''}`.trim(),
    currentDomain: location.hostname,
    riskLevel: 'critical',
  });
}

