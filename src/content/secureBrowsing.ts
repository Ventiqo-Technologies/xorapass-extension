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

import { showRiskWarning, showConfirmDialog } from './overlay';
import { analyzeEmailLink, analyzeAttachmentName, analyzeReplyTo, findReplyTo, type EmailFinding } from '../utils/emailGuard';
import { trackerFor } from '../utils/trackerList';
import { registrableDomain } from '../utils/siteTrust';

// ── Email Guard ────────────────────────────────────────────────────────────

const MESSAGE_BODY_SELECTORS: Record<string, string> = {
  'mail.google.com': '.a3s',
  outlook: '[aria-label="Message body"], [role="document"].allowTextSelection, div[id^="UniqueMessageBody"]',
  'mail.yahoo.com': '[data-test-id="message-view-body-content"]',
  'mail.aol.com': '[data-test-id="message-view-body-content"]',
  'mail.zoho': '.zmMailContent, .zmPVContent',
};
const ATTACHMENT_SELECTORS: Record<string, string> = {
  'mail.google.com': '.aV3, .aQA span[title]',
  outlook: '[data-testid="AttachmentCard"] [title], [role="listitem"][aria-label*="."] ',
  'mail.yahoo.com': '[data-test-id="attachment-name"]',
  'mail.aol.com': '[data-test-id="attachment-name"]',
  'mail.zoho': '.zmAttName, .SC_att_name',
};

function selectorFor(map: Record<string, string>, host: string): string | null {
  for (const key of Object.keys(map)) if (host === key || host.includes(key)) return map[key];
  return null;
}

const seenLinks = new WeakSet<Element>();
const seenAttachments = new WeakSet<Element>();
const linkFindings = new WeakMap<Element, EmailFinding>();
let replyToWarnedFor = '';

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
let clickHooked = false;

let emailTimer: ReturnType<typeof setTimeout> | null = null;
let emailLastRun = 0;

/** Throttled (the webmail DOM mutates constantly): at most every 600 ms. */
export function scanEmailContent(host: string): void {
  if (emailTimer) return;
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

function scanEmailNow(host: string): void {
  const bodySel = selectorFor(MESSAGE_BODY_SELECTORS, host);
  if (!bodySel) return;
  const bodies = Array.from(document.querySelectorAll(bodySel)).slice(0, 20);
  for (const body of bodies) {
    const links = Array.from(body.querySelectorAll('a[href]')).slice(0, 300);
    for (const a of links) {
      if (seenLinks.has(a)) continue;
      seenLinks.add(a);
      const finding = analyzeEmailLink((a.textContent || '').trim(), (a as HTMLAnchorElement).getAttribute('href') || '');
      if (!finding) continue;
      linkFindings.set(a, finding);
      a.after(badge(finding));
    }
  }
  if (bodies.length && !clickHooked) {
    clickHooked = true;
    document.addEventListener('click', onEmailLinkClick, true);
  }

  const attSel = selectorFor(ATTACHMENT_SELECTORS, host);
  if (attSel) {
    for (const el of Array.from(document.querySelectorAll(attSel)).slice(0, 50)) {
      if (seenAttachments.has(el)) continue;
      seenAttachments.add(el);
      const name = (el.getAttribute('title') || el.textContent || '').trim();
      const finding = analyzeAttachmentName(name);
      if (finding) el.appendChild(badge(finding));
    }
  }

  // Reply-To: only when the webmail renders it (e.g. Gmail's details panel).
  if (bodies.length) {
    const header = bodies[0].closest('[role="main"], [role="region"], [role="article"]') || document.body;
    const headerText = (header as HTMLElement).innerText?.slice(0, 4000) || '';
    const replyTo = findReplyTo(headerText);
    const sender = (header.querySelector('[email]')?.getAttribute('email') || '').toLowerCase();
    if (replyTo && sender && replyTo !== replyToWarnedFor) {
      const f = analyzeReplyTo(sender, replyTo);
      if (f) {
        replyToWarnedFor = replyTo;
        showRiskWarning({
          severity: f.level === 'danger' ? 'block' : 'warn',
          title: 'Replies Go Somewhere Else',
          message: `${f.reasons[0]}. Scammers do this so your answer reaches them, not the real sender. Check the address before replying.`,
          currentDomain: location.hostname,
          riskLevel: f.level === 'danger' ? 'high' : 'medium',
        });
      }
    }
  }
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
  if (!/^https?:$/.test(location.protocol)) return;
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

