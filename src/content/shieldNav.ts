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
import { showPhishingInterstitial, closePhishingInterstitial, showRiskWarning, showConfirmDialog } from './overlay';
import { detectScamCues } from '../utils/pageContent';
import { webRiskAdvisoryFromThreatType } from '../utils/webRiskAttribution';
import { techSupportScamScore, TECH_SUPPORT_WARN, isNotificationBait, type BehaviorKind } from '../utils/scamBehavior';

interface NavVerdict {
  action: 'allow' | 'warn' | 'block';
  layer?: string;
  /** Page-behaviour protection rolled out to this user. */
  hooks?: boolean;
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
      advisory: webRiskAdvisoryFromThreatType(v.threatType),
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
      onRequestAllowlist: () =>
        browser.runtime
          .sendMessage({ type: 'REQUEST_DOMAIN_ALLOWLIST', payload: { hostname: location.hostname } })
          .then((res: any) => ({ success: !!res?.success, reason: res?.reason }))
          .catch(() => ({ success: false, reason: 'network' })),
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

  // ── Behaviour events from the MAIN-world hooks (pageHooks.ts) ───────────
  // Buffered until the navigation verdict says whether always-on Shield is
  // active for this user; everything is local, nothing leaves the device
  // except a short per-tab summary for the Site Scanner.
  let shieldActive: boolean | null = null;
  const queued: any[] = [];
  const behaviors = new Set<BehaviorKind>();
  let warnedTechSupport = false;
  let warnedClickFix = false;
  let warnedNotification = false;

  const pageText = () => {
    try {
      return [document.title, (document.body?.innerText || '').slice(0, 6000)].join('\n');
    } catch {
      return document.title || '';
    }
  };

  const tellBackground = (kind: string, detail: Record<string, unknown> = {}) => {
    browser.runtime.sendMessage({ type: 'SHIELD_BEHAVIOR', payload: { kind, ...detail } }).catch(() => undefined);
  };

  const reply = (id: string, allow: boolean) => {
    window.postMessage({ __xoraShieldReply: 'v1', id, allow }, '*');
  };

  const handle = (d: any) => {
    const kind = String(d.kind || '');
    if (kind === 'wallet_check') {
      if (!shieldActive || state.shown) return reply(String(d.id), true);
      tellBackground('wallet_check', { level: d.level });
      void showConfirmDialog({
        title: d.level === 'danger' ? 'XoraPass blocked a risky wallet request' : 'Check this wallet request',
        body: [
          String(d.summary || 'This site is asking your crypto wallet for a risky permission.'),
          'Wallet-draining scams work exactly like this. Only continue if you fully trust this site and understand the request.',
        ],
        confirmLabel: 'Block request',
        cancelLabel: 'Continue anyway',
      }).then((block) => reply(String(d.id), !block));
      return;
    }
    if (!shieldActive) return;
    tellBackground(kind, kind === 'fingerprint' ? { techniques: d.techniques } : {});

    if (kind === 'clickfix' && !warnedClickFix) {
      warnedClickFix = true;
      showRiskWarning({
        severity: 'block',
        title: "Blocked a Dangerous 'Paste This Command' Trick",
        message:
          'This page tried to copy a hidden command to your clipboard and will ask you to paste it into Run or a terminal. That command would install malware. XoraPass stopped the copy — do not follow the page\'s instructions.',
        currentDomain: location.hostname,
        riskLevel: 'critical',
      });
      return;
    }
    if (kind === 'notification_request' && !warnedNotification) {
      const text = pageText();
      if (isNotificationBait(!!d.activated, text, detectScamCues(text))) {
        warnedNotification = true;
        showRiskWarning({
          severity: 'warn',
          title: 'Notification Spam Trick',
          message:
            'This page wants permission to send you notifications, using a trick ("click Allow to continue"). Sites like this flood you with scam pop-ups. Choose Block.',
          currentDomain: location.hostname,
          riskLevel: 'medium',
        });
      }
      return;
    }
    if (['fullscreen', 'keyboard_lock', 'pointer_lock', 'beforeunload', 'history_flood', 'autoplay_audio'].includes(kind)) {
      behaviors.add(kind as BehaviorKind);
      if (warnedTechSupport) return;
      const score = techSupportScamScore(behaviors, detectScamCues(pageText()));
      if (score >= TECH_SUPPORT_WARN) {
        warnedTechSupport = true;
        try {
          if (document.fullscreenElement) void document.exitFullscreen();
          (navigator as any).keyboard?.unlock?.();
          if (document.pointerLockElement) document.exitPointerLock();
        } catch {
          /* best effort */
        }
        tellBackground('tech_support_scam', { score });
        showRiskWarning({
          severity: 'block',
          title: 'Fake Tech-Support Scam',
          message:
            "This page is trying to trap you (full screen, locked keyboard or back button) and pretends your device has a problem. It's a scam. Don't call any number or install anything. Close this tab — press and hold Esc if the page won't let go.",
          currentDomain: location.hostname,
          riskLevel: 'critical',
        });
      }
    }
  };

  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (ev.source !== window || !d || d.__xoraShield !== 'v1') return;
    if (shieldActive === null) queued.push(d);
    else handle(d);
  });

  const setActive = (active: boolean) => {
    shieldActive = active;
    for (const d of queued.splice(0)) handle(d);
  };

  browser.runtime
    .sendMessage({ type: 'SHIELD_NAV_CHECK' })
    .then((v: NavVerdict | undefined) => {
      clearTimeout(failOpen);
      setActive(!!v && v.layer !== 'disabled' && v.hooks === true);
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
      setActive(false);
      state.action = 'allow';
      release();
    });
})();
