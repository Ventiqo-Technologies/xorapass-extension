// XoraPass Shield — navigation guard (document_start, top frame only).
//
// Runs before the page renders and asks the background for a verdict
// (SHIELD_NAV_CHECK: user allowlist → blocklist → trusted → local
// heuristics; the background uses this frame's real URL, not anything we
// send). While the verdict is pending — normally a few milliseconds — typing
// into form fields is held so nothing can be entered into a page that is
// about to be blocked. It fails OPEN: no answer within the guard window, or
// any error, releases the page.
//
// On "block" the full-page Shield warning is shown immediately; the user can
// go back, go to the real site, report it, or (after a short delay) continue.
// The main content script (document_idle) sees window.__xoraShieldNav and
// won't stack a second warning on top.
//
// Built as its own self-contained IIFE (vite --mode shieldnav).

import browser from 'webextension-polyfill';
import { showPhishingInterstitial, closePhishingInterstitial } from './overlay';

interface NavVerdict {
  action: 'allow' | 'warn' | 'block';
  layer?: string;
  reasons?: string[];
  matchedTarget?: string | null;
  threatType?: string;
  typingGuardMs?: number;
}

const MAX_GUARD_MS = 1500;

(() => {
  if (window !== window.top) return;
  if (!/^https?:$/.test(location.protocol)) return;

  const state: { host: string; action: string; shown: boolean } = {
    host: location.hostname,
    action: 'pending',
    shown: false,
  };
  (window as unknown as { __xoraShieldNav?: typeof state }).__xoraShieldNav = state;

  let guarding = true;
  const EVENTS = ['keydown', 'keypress', 'beforeinput', 'paste', 'drop'] as const;
  const hold = (e: Event) => {
    if (!guarding) return;
    const t = e.target as HTMLElement | null;
    if (!t) return;
    if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t.isContentEditable) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  };
  for (const ev of EVENTS) window.addEventListener(ev, hold, true);

  const release = () => {
    if (!guarding) return;
    guarding = false;
    for (const ev of EVENTS) window.removeEventListener(ev, hold, true);
  };
  const failOpen = setTimeout(release, MAX_GUARD_MS);

  const show = (v: NavVerdict) => {
    state.shown = true;
    const expected = v.matchedTarget || null;
    const message =
      (v.reasons && v.reasons[0]) ||
      'XoraPass Shield flagged this site as dangerous. Entering passwords or payment details here is not safe.';
    showPhishingInterstitial({
      currentDomain: location.hostname,
      expectedDomain: expected,
      message,
      reasons: v.reasons || [],
      onGoToOfficial: expected
        ? () => {
            location.href = `https://${expected}`;
          }
        : undefined,
      onLeave: () => {
        if (history.length > 1) history.back();
        else location.href = 'about:blank';
      },
      onReportPhishing: () =>
        browser.runtime
          .sendMessage({
            type: 'REPORT_PHISHING',
            payload: { hostname: location.hostname, decision: 'block', riskLevel: 'critical' },
          })
          .then((res: any) => ({ success: !!res?.success }))
          .catch(() => ({ success: false })),
      onProceedAnyway: () =>
        browser.runtime
          .sendMessage({ type: 'RISK_APPROVE_DOMAIN', payload: { hostname: location.hostname } })
          .then((res: any) => {
            if (res?.success) {
              state.action = 'allow';
              release();
              closePhishingInterstitial();
            }
            return { success: !!res?.success };
          })
          .catch(() => ({ success: false })),
    });
  };

  browser.runtime
    .sendMessage({ type: 'SHIELD_NAV_CHECK' })
    .then((v: NavVerdict | undefined) => {
      clearTimeout(failOpen);
      state.action = v?.action || 'allow';
      if (v?.action === 'block') {
        // Keep holding input until the user explicitly chooses to continue.
        show(v);
      } else {
        release();
      }
    })
    .catch(() => {
      clearTimeout(failOpen);
      state.action = 'allow';
      release();
    });
})();
