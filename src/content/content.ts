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
import { looksLikeUsername, looksLikeNewPassword, looksLikeAwsAccountId, collectFormContext as collectSignupFormContext, inferFormIntent } from './fieldHeuristics';
import { generatePassword } from '../utils/passwordGenerator';
import { scanForSecrets, redact, type ScanResult, type SecretType } from '../utils/secretScan';
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
  showRiskWarning,
  closeRiskWarning,
  showPhishingInterstitial,
  closePhishingInterstitial,
  isInterstitialOpen,
  isRiskWarningOpen,
  clearAll,
  showToast,
  showLinkInspectionModal,
  showCheckoutProtectionBanner,
  closeCheckoutProtectionBanner,
  showWebmailPhishingBanner,
  closeWebmailPhishingBanner,
  initOverlayTheme,
  setPopupSuppressed,
  getActiveRiskWarning,
  type OverlayCredential,
} from './overlay';
import { looksLikeCardNumber, looksLikeCvv, looksLikeCardExpiry } from './cardGuard';
import { isSupportedWebmail, analyzeEmailSender } from '../utils/webmailGuard';
import { collectPageSignals, isWorthAssessing, primeFaviconBrand, type PageSignals } from '../utils/pageSignals';
import { collectPageText, shouldAiScan } from '../utils/pageContent';
import { WEB_APP_URL } from '../utils/config';
import { webRiskAdvisoryFromSignals } from '../utils/webRiskAttribution';
import { scanEmailContent, checkInsecureForms, checkOpaqueOriginLogin, featureOn, collectPrivacySignals, showDownloadPrompt, showDownloadBlocked } from './secureBrowsing';

let activeCredentials: OverlayCredential[] = [];
let lookalikeWarning: { target: string; reason: string; riskScore?: number; reasons?: string[] } | null = null;
let domainRisk: {
  decision: string;
  riskScore: number;
  riskLevel?: string;
  reasons: string[];
  matchedTarget: string | null;
  safeWarningMessage?: string;
  // Server-set: a full-page block rather than a corner banner.
  showInterstitial?: boolean;
  // Provider signals (for the required Google Web Risk attribution).
  threatIntelSignals?: Record<string, string>;
} | null = null;

// Tracks the last hostname+decision pair we already alerted on, so
// loadCredentials() re-running (tab focus, visibility change, SPA route
// change) doesn't re-pop the same warning repeatedly.
let lastWarnedRiskKey: string | null = null;

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
const bypassedSecrets = new Set<string>();

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

// Describes the login form on this page for the backend risk engine.
//
// These are the highest-value phishing signals the server scores
// (CROSS_ORIGIN_FORM_ACTION +25, IFRAME_LOGIN_EMBEDDING +15) and they can only
// be observed here, in the page. Metadata only - field SHAPE, never field
// contents - so this stays inside the zero-knowledge boundary.
function collectFormContext(): {
  isLoginForm: boolean;
  hasPasswordField: boolean;
  hasMfaField: boolean;
  hasLeadCaptureForm?: boolean;
  isIframe: boolean;
  actionUrl?: string;
  numInputs: number;
} {
  const passwords = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]')
  ).filter(isFillable);
  const form = passwords[0]?.closest('form') || document.querySelector('form');
  const inputs = Array.from((form || document).querySelectorAll<HTMLInputElement>('input'));

  // One-time-code fields: the autocomplete token is the reliable signal, with
  // name/id heuristics as a fallback for forms that don't set it.
  const hasMfaField = inputs.some((el) => {
    const auto = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (auto.includes('one-time-code')) return true;
    const hint = `${el.name || ''} ${el.id || ''}`.toLowerCase();
    return /\b(otp|totp|mfa|2fa|onetime|one-time|authcode|verificationcode)\b/.test(hint);
  });

  // Lead-capture / scam-entry detection: pages asking for personal details
  // (name + email or phone) even when no password field is present yet.
  const hasPhoneField = inputs.some((el) => {
    if (el.type === 'tel') return true;
    const hint = `${el.name || ''} ${el.id || ''} ${el.placeholder || ''}`.toLowerCase();
    return /\b(phone|tel|mobile|cell|telephone)\b/.test(hint);
  });
  const hasEmailField = inputs.some((el) => {
    if (el.type === 'email') return true;
    const hint = `${el.name || ''} ${el.id || ''} ${el.placeholder || ''}`.toLowerCase();
    return /\b(email|e-mail|mail)\b/.test(hint);
  });
  const hasLeadCaptureForm = (hasPhoneField && hasEmailField) || (inputs.length >= 3 && (hasPhoneField || hasEmailField));

  // Resolved against the document so a relative action is compared as the
  // absolute URL the browser would actually POST to.
  let actionUrl: string | undefined;
  const rawAction = form?.getAttribute('action');
  if (rawAction) {
    try {
      actionUrl = new URL(rawAction, window.location.href).href;
    } catch {
      /* unparseable action - send nothing rather than something misleading */
    }
  }

  return {
    isLoginForm: passwords.length > 0,
    hasPasswordField: passwords.length > 0,
    hasMfaField,
    hasLeadCaptureForm,
    isIframe: window.top !== window.self,
    actionUrl,
    numInputs: inputs.length,
  };
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
  let scamCues: string[] | undefined;
  try {
    scamCues = collectPageText(document).cues;
  } catch {
    /* ignore DOM errors */
  }
  browser.runtime
    .sendMessage({
      type: 'GET_MATCHING_CREDENTIALS',
      payload: {
        hostname,
        currentUrl: window.location.href,
        formContext: collectFormContext(),
        // Sent only for pages with something to assess - an ordinary content
        // page with no credential form and no brand claim produces no verdict
        // the server could act on, so shipping its shape is pure noise (and
        // needlessly busts the per-page verdict cache).
        pageSignals: worthAssessingSignals(),
        scamCues,
      },
    })
    .then((response: any) => {
      if (!response) return;

      // Respect the per-site disable list.
      if (response.disabled) {
        activeCredentials = [];
        clearAll();
        return;
      }

      lookalikeWarning = response.lookalike || null;
      domainRisk = response.risk || null;
      activeCredentials = response.credentials || [];

      maybeShowProactiveRiskWarning();

      // Always scan: with no saved credentials there is nothing to fill, but a
      // sign-up field still gets an icon so a password can be generated.
      clearAll();
      scanForLoginFields();
      scanForPaymentFields();
      scanWebmailMessages();
      scheduleAiScan();
    })
    .catch((err) => {
      console.warn('[XoraPass Content] Error requesting credentials:', err);
    });
}

/**
 * The page-shape vector, or undefined when the page has nothing worth
 * assessing. See the privacy contract at the top of utils/pageSignals.ts for
 * what this does and does not contain.
 */
function worthAssessingSignals(): PageSignals | undefined {
  const signals = collectPageSignals();
  return isWorthAssessing(signals) ? signals : undefined;
}

// ---------------------------------------------------------------------------
// AI scam analysis (always-on Shield, paid)
// ---------------------------------------------------------------------------
// Pages without a password field (fake tech-support, fake shops, crypto and
// prize scams, "paste this command" traps) slip past the credential-focused
// checks. For pages whose local scam cues (or risk score) justify it, a small
// redacted text extract is sent for an AI verdict — see utils/pageContent.ts
// for exactly what leaves the device. The background gates this on the
// entitlement, the kill switch and trusted/allowlisted sites; the server
// enforces a monthly quota. Warning copy comes from XoraPass, never the model.
let aiScannedHref = '';
let aiScanTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleAiScan(): void {
  if (window !== window.top) return;
  const href = window.location.href.split('#')[0];
  if (aiScannedHref === href || aiScanTimer) return;
  // Give client-rendered pages a moment to put their text on screen.
  aiScanTimer = setTimeout(() => {
    aiScanTimer = null;
    void maybeRunAiScan(href);
  }, 1500);
}

async function maybeRunAiScan(href: string): Promise<void> {
  if (aiScannedHref === href || window.location.href.split('#')[0] !== href) return;
  aiScannedHref = href;
  const nav = (window as unknown as { __xoraShieldNav?: { shown: boolean } }).__xoraShieldNav;
  if (nav?.shown || isInterstitialOpen()) return;

  let page;
  try {
    page = collectPageText(document);
  } catch {
    return;
  }
  const hasThreatAlert =
    Object.values(domainRisk?.threatIntelSignals || {}).some(
      (s) => s === 'phishing_hit' || s === 'malware_hit' || s === 'suspicious_scan'
    ) || (domainRisk?.reasons || []).some((r: string) => /threat-intel|threat intel|web risk|radar/i.test(r));

  if (!hasThreatAlert && !shouldAiScan(page.cues, domainRisk?.riskScore ?? 0)) return;

  const res: any = await browser.runtime
    .sendMessage({
      type: 'SHIELD_AI_SCAN',
      payload: {
        page,
        pageSignals: worthAssessingSignals(),
        threatIntelSignals: domainRisk?.threatIntelSignals,
        hasThreatIntelHit: hasThreatAlert,
      },
    })
    .catch(() => null);
  if (!res || typeof res.risk_score !== 'number' || res.risk_score < 45) return;
  if (window.location.href.split('#')[0] !== href || isInterstitialOpen()) return;
  // Never downgrade or replace a stronger warning that is already showing.
  if (isRiskWarningOpen() && domainRisk?.decision === 'block') return;

  const blocking = res.risk_score >= 75;
  showRiskWarning({
    severity: blocking ? 'block' : 'warn',
    title: typeof res.title === 'string' && res.title ? res.title : 'Possible Scam Detected',
    message:
      typeof res.message === 'string' && res.message
        ? res.message
        : 'XoraPass Shield found signs that this page is a scam. Don\'t enter personal or payment details.',
    currentDomain: window.location.hostname,
    riskLevel: blocking ? 'high' : 'medium',
    onReportPhishing: blocking
      ? undefined
      : async () => {
          try {
            const r: any = await browser.runtime.sendMessage({
              type: 'REPORT_PHISHING',
              payload: { hostname: window.location.hostname, decision: 'warn', riskLevel: 'medium' },
            });
            if (r?.alreadyBlocked) {
              triggerFullPageBlock({
                message: 'This domain has been confirmed as phishing or malware and is blocked by XoraPass Shield.',
                reasons: ['User phishing report confirmed domain is blocked.'],
              });
              return { success: true, alreadyBlocked: true };
            }
            if (r?.success) {
              setTimeout(async () => {
                try {
                  const checkRes: any = await browser.runtime.sendMessage({
                    type: 'GET_CREDENTIALS',
                    payload: { url: window.location.href },
                  });
                  if (checkRes?.risk?.decision === 'block') {
                    domainRisk = checkRes.risk;
                    triggerFullPageBlock({
                      message: checkRes.risk.safeWarningMessage || 'This domain has been verified and blocked by XoraPass Shield.',
                      reasons: checkRes.risk.reasons,
                    });
                  }
                } catch {}
              }, 4000);
            }
            return { success: !!r?.success, alreadyBlocked: !!r?.alreadyBlocked };
          } catch {
            return { success: false };
          }
        },
  });
}

function triggerFullPageBlock(opts?: { message?: string; reasons?: string[] }): void {
  closeRiskWarning();
  const currentHostname = window.location.hostname;
  const expectedDomain = domainRisk?.matchedTarget || lookalikeWarning?.target || null;
  const message =
    opts?.message ||
    getRiskWarningMessage() ||
    'XoraPass Shield blocked this site: Confirmed phishing or malware domain.';
  const reasons = opts?.reasons || domainRisk?.reasons || ['Domain confirmed blocked by security policy.'];

  showPhishingInterstitial({
    advisory: webRiskAdvisoryFromSignals(domainRisk?.threatIntelSignals),
    currentDomain: currentHostname,
    expectedDomain,
    message,
    reasons,
    onGoToOfficial: expectedDomain
      ? () => {
          window.location.href = `https://${expectedDomain}`;
        }
      : undefined,
    onLeave: () => {
      try {
        if (window.history.length > 1) {
          window.history.back();
          setTimeout(() => {
            if (window.location.href !== 'about:blank') {
              window.location.replace('about:blank');
            }
          }, 300);
        } else {
          window.location.replace('about:blank');
        }
      } catch {
        window.location.replace('about:blank');
      }
    },
    onRequestAllowlist: () =>
      browser.runtime
        .sendMessage({ type: 'REQUEST_DOMAIN_ALLOWLIST', payload: { hostname: currentHostname } })
        .then((res: any) => ({ success: !!res?.success, reason: res?.reason }))
        .catch(() => ({ success: false, reason: 'network' })),
    onProceedAnyway: () =>
      browser.runtime
        .sendMessage({ type: 'RISK_APPROVE_DOMAIN', payload: { hostname: currentHostname } })
        .then((res: any) => ({ success: !!res?.success }))
        .catch(() => ({ success: false })),
  });
}

// Surfaces a risky decision immediately, without requiring the user to click
// a login field's icon first (which may not even exist on this page). Keyed
// on hostname+decision so repeated loadCredentials() calls (tab focus,
// visibility change, SPA route watchers) don't re-pop an already-seen alert.
async function maybeShowProactiveRiskWarning(): Promise<void> {
  // The document_start navigation guard (shieldNav.ts) may already have
  // shown the full-page warning for this page — never stack a second one,
  // and if the user chose to continue there, don't re-block them here.
  const nav = (window as unknown as { __xoraShieldNav?: { host: string; action: string; shown: boolean } })
    .__xoraShieldNav;
  const navHandled = !!nav && nav.shown && nav.host === window.location.hostname;
  if (navHandled && nav!.action === 'block') return;
  const decision = domainRisk?.decision;
  const isRisky = decision === 'block' || decision === 'warn' || decision === 'require_approval';
  const key = `${window.location.hostname}|${decision || ''}`;

  if (!isRisky) {
    lastWarnedRiskKey = null;
    closeRiskWarning();
    if (isInterstitialOpen()) closePhishingInterstitial();
    return;
  }
  if (lastWarnedRiskKey === key) return;

  const message = getRiskWarningMessage();
  if (!message) return;

  // A server-confirmed critical verdict or block decision gets the full-page
  // block instead of a corner banner: at that point letting the user read and
  // interact with the page at all is the risk being managed.
  if ((domainRisk?.showInterstitial || (domainRisk as any)?.show_interstitial || domainRisk?.decision === 'block') && !navHandled) {
    lastWarnedRiskKey = key;
    triggerFullPageBlock();
    return;
  }

  // Set before the await below so a second loadCredentials() tick firing
  // while this is still in flight doesn't start a duplicate lookup/render.
  lastWarnedRiskKey = key;
  const expectedDomain = domainRisk?.matchedTarget || lookalikeWarning?.target || null;
  const currentHostname = window.location.hostname;

  // Check whether this domain already has an allowlist request on file —
  // re-showing "Request allowlist review" every visit after one's already
  // pending would just spam the admin queue with duplicates for no reason.
  // Best-effort: any failure here just means the button renders normally.
  let allowlistRequestStatus: 'pending' | 'approved' | 'denied' | null = null;
  try {
    const res: any = await browser.runtime.sendMessage({ type: 'GET_DOMAIN_RISK_ALLOWLIST_REQUESTS' });
    const requests: Array<{ hostname: string; status: string; requested_at: string }> = Array.isArray(res?.requests)
      ? res.requests
      : [];
    const matching = requests
      .filter((r) => r.hostname === currentHostname)
      .sort((a, b) => new Date(b.requested_at).getTime() - new Date(a.requested_at).getTime());
    if (matching[0]?.status === 'pending' || matching[0]?.status === 'denied') {
      allowlistRequestStatus = matching[0].status as 'pending' | 'denied';
    }
  } catch {
    /* best-effort — fall through with allowlistRequestStatus = null */
  }

  // The risky-decision key can change (or this can go stale) while the
  // lookup above was in flight — a page navigation, or the risk clearing.
  // Bail rather than showing a warning for a state that's no longer current.
  if (lastWarnedRiskKey !== key) return;

  const isMalware = (domainRisk?.reasons || []).some((r) => /malware/i.test(r)) ||
    Object.values(domainRisk?.threatIntelSignals || {}).some((s) => s === 'malware_hit');
  const blockTitle = isMalware ? 'Dangerous Malware Site Blocked' : 'Likely Phishing Site Blocked';

  showRiskWarning({
    severity: decision === 'block' ? 'block' : decision === 'require_approval' ? 'require_approval' : 'warn',
    title: decision === 'block' ? blockTitle : 'Suspicious Site Detected',
    message,
    advisory: webRiskAdvisoryFromSignals(domainRisk?.threatIntelSignals),
    currentDomain: currentHostname,
    expectedDomain,
    riskLevel: domainRisk?.riskLevel,
    allowlistRequestStatus,
    onDismiss: () => {
      // A manual dismiss shouldn't re-fire on the very next loadCredentials()
      // tick, but should still recur if the user leaves and comes back later.
    },
    onGoToOfficial: expectedDomain
      ? () => {
          window.location.href = `https://${expectedDomain}`;
        }
      : undefined,
    onReportPhishing: decision === 'block'
      ? undefined
      : async () => {
          try {
            const res: any = await browser.runtime.sendMessage({
              type: 'REPORT_PHISHING',
              payload: { hostname: currentHostname, decision, riskLevel: domainRisk?.riskLevel },
            });
            if (res?.alreadyBlocked) {
              triggerFullPageBlock({
                message: 'This domain has been confirmed as phishing or malware and is blocked by XoraPass Shield.',
                reasons: ['User phishing report confirmed domain is blocked.'],
              });
              return { success: true, alreadyBlocked: true };
            }
            if (res?.success) {
              setTimeout(async () => {
                try {
                  const checkRes: any = await browser.runtime.sendMessage({
                    type: 'GET_CREDENTIALS',
                    payload: { url: window.location.href },
                  });
                  if (checkRes?.risk?.decision === 'block') {
                    domainRisk = checkRes.risk;
                    triggerFullPageBlock({
                      message: checkRes.risk.safeWarningMessage || 'This domain has been verified and blocked by XoraPass Shield.',
                      reasons: checkRes.risk.reasons,
                    });
                  }
                } catch {}
              }, 4000);
            }
            return { success: !!res?.success, alreadyBlocked: !!res?.alreadyBlocked };
          } catch {
            return { success: false };
          }
        },
    onRequestAllowlist: () =>
      browser.runtime
        .sendMessage({
          type: 'REQUEST_DOMAIN_ALLOWLIST',
          payload: { hostname: currentHostname },
        })
        .then((res: any) => ({ success: !!res?.success, reason: res?.reason }))
        .catch(() => ({ success: false, reason: 'network' as const })),
    // Offered only for require_approval; the overlay itself also checks the
    // severity, so a block verdict can never render this button.
    onApproveAnyway:
      decision === 'require_approval'
        ? () =>
            browser.runtime
              .sendMessage({ type: 'RISK_APPROVE_DOMAIN', payload: { hostname: currentHostname } })
              .then((res: any) => {
                if (res?.success) {
                  // Re-request the credential list: the background withheld it
                  // pending exactly this approval.
                  lastWarnedRiskKey = null;
                  loadCredentials();
                }
                return { success: !!res?.success };
              })
              .catch(() => ({ success: false }))
        : undefined,
  });
}

/**
 * Reacts to the background refusing to release a secret.
 *
 * `risk_approval_required` is not a dead end - it means the verdict was
 * require_approval and the user has not cleared it for this tab yet - so the
 * alert is re-shown with its "Fill here anyway" action rather than the click
 * appearing to do nothing.
 */
function handleFillRefusal(error: string | undefined): void {
  console.warn('[XoraPass] Fill refused:', error || 'no_response');
  if (error === 'risk_approval_required') {
    lastWarnedRiskKey = null;
    void maybeShowProactiveRiskWarning();
  }
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
  } else if (message.type === 'SHORTCUT_AUTOFILL') {
    void handleShortcutAutofill();
  } else if (message.type === 'TAB_RISK_UPDATE') {
    const risk = message.payload?.risk || message.risk;
    if (risk) {
      domainRisk = risk;
      lastWarnedRiskKey = null; // force fresh evaluation
      maybeShowProactiveRiskWarning();
    }
  } else if (message.type === 'POPUP_STATE_CHANGED') {
    setPopupSuppressed(Boolean(message.payload?.open ?? message.payload?.isOpen));
  } else if (message.type === 'GET_ACTIVE_TAB_WARNING') {
    return Promise.resolve(getActiveRiskWarning());
  } else if (message.type === 'DISMISS_TAB_RISK_WARNING') {
    closeRiskWarning();
  }
  return undefined;
});

async function handleShortcutAutofill(): Promise<void> {
  // If credentials are not loaded yet or empty, try a fast reload
  if (activeCredentials.length === 0) {
    loadCredentials();
    return;
  }

  // Look for visible password field first, or AWS resolving input
  const passwordInputs = (Array.from(
    document.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[]).filter(isFillable);

  let targetInput: HTMLInputElement | null = passwordInputs[0] || null;

  if (!targetInput && window.location.hostname.endsWith('aws.amazon.com')) {
    const awsInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    const foundAws = awsInputs.find(el => isFillable(el) && looksLikeAwsAccountId({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label')
    }));
    if (foundAws) targetInput = foundAws;
  }

  if (!targetInput) {
    // Look for any visible username input
    const allInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    const foundUser = allInputs.find(el => isFillable(el) && looksLikeUsername({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label')
    }));
    if (foundUser) targetInput = foundUser;
  }

  if (!targetInput) return;

  if (activeCredentials.length === 1) {
    if (targetInput.type === 'password') {
      await handlePick(activeCredentials[0].id, targetInput);
    } else {
      // Username or AWS account input
      const pairedPass = (Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[]).find(isFillable);
      if (pairedPass) {
        await handlePick(activeCredentials[0].id, pairedPass);
      } else {
        // Dropdown if no password input found
        activate(targetInput, targetInput);
      }
    }
  } else if (activeCredentials.length > 1) {
    // Multiple accounts: show dropdown so user can choose
    activate(targetInput, targetInput);
  }
}

// ---------------------------------------------------------------------------
// Field detection
// ---------------------------------------------------------------------------

// Checks if an element is hidden by an ancestor with overflow: hidden/clip and 0/tiny height
function isClippedByAncestor(el: HTMLElement): boolean {
  let parent = el.parentElement;
  while (parent && parent !== document.body && parent !== document.documentElement) {
    const parentRect = parent.getBoundingClientRect();
    if (parentRect.height < 10 || parentRect.width < 10) {
      const style = window.getComputedStyle(parent);
      if (style.overflow === 'hidden' || style.overflowY === 'hidden' || style.overflow === 'clip' || style.overflowY === 'clip') {
        return true;
      }
    }
    parent = parent.parentElement;
  }
  return false;
}

// An input is fillable if it's visible and user-editable.
function isFillable(el: HTMLInputElement): boolean {
  if (!el || el.type === 'hidden' || el.disabled || el.readOnly) return false;
  if (el.offsetParent === null && el.offsetWidth === 0 && el.offsetHeight === 0) return false;

  const rect = el.getBoundingClientRect();
  if (rect.width < 50 || rect.height < 20) return false;

  if (typeof (el as any).checkVisibility === 'function') {
    try {
      if (!(el as any).checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    } catch {}
  }

  try {
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  } catch {}

  if (isClippedByAncestor(el)) return false;

  return true;
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
    let isNew = looksLikeNewPassword(
      {
        autocomplete: passInput.getAttribute('autocomplete'),
        name: passInput.name,
        id: passInput.id,
        placeholder: passInput.getAttribute('placeholder'),
        ariaLabel: passInput.getAttribute('aria-label'),
      },
      hasSibling,
      window.location.href
    );

    // Last-resort: when field attrs, sibling count, and URL path all give no
    // signal, read the surrounding form's DOM context — button text, heading,
    // page title, cross-links, terms checkbox, field count — to infer intent.
    // This handles any site automatically without per-site code changes.
    if (!isNew) {
      const intent = inferFormIntent(collectSignupFormContext(passInput));
      if (intent === 'signup') isNew = true;
    }

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
    if (usernameInput && !hasIcon(usernameInput)) {
      fieldPairs.set(usernameInput, usernameInput);
      attachIcon(usernameInput, () => activate(passInput, usernameInput));
      focusActivators.set(usernameInput, passInput);
    }
  }

  // ── Multi-Step / Standalone Username Field Handling ─────────────────────────
  // When no password input is currently visible (e.g. AWS SSO, Google, Microsoft Step 1)
  // decorate any visible username/identifier input so the user can autofill their username.
  if (visible.length === 0 && activeCredentials.length > 0) {
    const allInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    const fillableInputs = allInputs.filter(isFillable);

    const standaloneUserInputs = fillableInputs.filter(el => {
      // Find associated label text if present
      let labelText = '';
      if (el.id) {
        const lbl = document.querySelector(`label[for="${el.id}"]`);
        if (lbl) labelText = lbl.textContent || '';
      }
      if (!labelText && el.closest('label')) {
        labelText = el.closest('label')?.textContent || '';
      }
      if (!labelText && el.parentElement) {
        labelText = el.parentElement.textContent || '';
      }

      // If looksLikeUsername matches
      if (looksLikeUsername({
        type: el.type,
        autocomplete: el.getAttribute('autocomplete'),
        name: el.name,
        id: el.id,
        placeholder: el.getAttribute('placeholder'),
        ariaLabel: el.getAttribute('aria-label'),
        labelText,
        role: el.getAttribute('role'),
        className: el.className,
      })) {
        return true;
      }

      // Specific AWS Sign-in fallback: only on AWS domains if the field is the primary resolving input or username
      const hostname = window.location.hostname;
      if ((hostname.includes('aws.amazon.com') || hostname.includes('signin.aws')) &&
          fillableInputs.length === 1 && (el.type === 'text' || el.type === 'email' || !el.type)) {
        return true;
      }

      return false;
    });

    for (const userInput of standaloneUserInputs) {
      if (hasIcon(userInput)) continue;

      attachIcon(userInput, () => {
        openDropdown(userInput, {
          credentials: activeCredentials,
          warning: getRiskWarningMessage(),
          onPick: async (id) => {
            const cred = activeCredentials.find((c) => c.id === id);
            if (!cred) return;
            const confirmed = await confirmFillIfNeeded(cred);
            if (!confirmed) return;

            const res = (await browser.runtime
              .sendMessage({
                type: 'GET_CREDENTIAL_SECRET',
                payload: { id, formContext: collectFormContext(), pageSignals: worthAssessingSignals() },
              })
              .catch(() => null)) as { username?: string; value?: string; accountId?: string; totpCode?: string; error?: string } | null;

            if (!res || res.error) {
              handleFillRefusal(res?.error);
              return;
            }

            if (res.username) {
              autofillField(userInput, res.username);
            }
          }
        });
      });
      focusActivators.set(userInput, userInput);
    }
  }

  // ── AWS Console Account ID Specific Handling ────────────────────────────────
  // Decorate the initial Step 1 Account ID input (#resolving_input) when active
  if ((window.location.hostname.endsWith('aws.amazon.com') || window.location.hostname.endsWith('.signin.aws')) && activeCredentials.length > 0) {
    const awsInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    const accountInput = awsInputs.find(el => isFillable(el) && looksLikeAwsAccountId({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label')
    }));

    if (accountInput && !hasIcon(accountInput)) {
      attachIcon(accountInput, () => {
        openDropdown(accountInput, {
          credentials: activeCredentials,
          warning: null,
          onPick: async (id) => {
            const cred = activeCredentials.find((c) => c.id === id);
            if (!cred) return;
            const confirmed = await confirmFillIfNeeded(cred);
            if (!confirmed) return;

            // Fetch the secret which includes the account ID / alias (stored in accountId)
            const res = (await browser.runtime
              .sendMessage({
    type: 'GET_CREDENTIAL_SECRET',
    payload: { id, formContext: collectFormContext(), pageSignals: worthAssessingSignals() },
  })
              .catch(() => null)) as { username?: string; value?: string; accountId?: string; totpCode?: string; error?: string } | null;

            if (!res || res.error) {
              handleFillRefusal(res?.error);
              return;
            }

            // Fill Account ID / alias
            const fillValue = res.accountId || '';
            if (fillValue) {
              autofillField(accountInput, fillValue);
            }

            // Also fill Username and Password if they are visible on the same page
            const awsInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
            const usernameInput = awsInputs.find(el => el !== accountInput && el.type !== 'password' && el.type !== 'hidden' && (
              el.id === 'username' || 
              el.name === 'username' ||
              el.id?.toLowerCase().includes('username') ||
              el.name?.toLowerCase().includes('username') ||
              looksLikeUsername({
                type: el.type,
                name: el.name,
                id: el.id,
                placeholder: el.getAttribute('placeholder'),
                ariaLabel: el.getAttribute('aria-label')
              })
            ));
            const passwordInput = awsInputs.find(el => el.type === 'password' && isFillable(el));

            if (usernameInput && res.username) {
              autofillField(usernameInput, res.username);
            }
            if (passwordInput && res.value) {
              autofillField(passwordInput, res.value);
            }

            // Automatically trigger the Next submission on Step 1 only if password field is not visible
            const passwordVisible = (Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[]).some(isFillable);
            if (!passwordVisible) {
              const form = accountInput.form;
              const submitter = form?.querySelector('button[type="submit"], input[type="submit"]') ||
                (form ? null : document.querySelector('button[type="submit"], input[type="submit"]'));
              if (form && typeof form.requestSubmit === 'function') {
                form.requestSubmit(submitter as HTMLElement | undefined);
              } else if (submitter instanceof HTMLElement) {
                submitter.click();
              }
            }
          }
        });
      });
      focusActivators.set(accountInput, accountInput);
    }
  }
}

// ---------------------------------------------------------------------------
// Checkout & Card Protection
// ---------------------------------------------------------------------------
let hasWarnedCheckoutOnPage = false;
let checkoutGuardEnabled = true;
let webmailGuardEnabled = true;

// Load initial Shield toggles
try {
  browser.storage.local.get(['checkoutGuardEnabled', 'webmailGuardEnabled']).then((res: any) => {
    if (typeof res?.checkoutGuardEnabled === 'boolean') checkoutGuardEnabled = res.checkoutGuardEnabled;
    if (typeof res?.webmailGuardEnabled === 'boolean') webmailGuardEnabled = res.webmailGuardEnabled;
  });
} catch {}

// Card fields inside a cross-origin payment iframe (Stripe Elements,
// Braintree, Adyen, ...) are invisible to this top-frame script; the tiny
// all-frames cardFrame.ts script detects them and the background relays a
// CARD_FIELDS_IN_FRAME notice here. Remembered so a notice that arrives
// before the risk verdict is still honoured once loadCredentials() resolves.
let paymentFieldsInSubframe = false;

function scanForPaymentFields(): void {
  if (!checkoutGuardEnabled || hasWarnedCheckoutOnPage) return;

  const isInsecure = isInsecureContext();
  const riskScore = domainRisk?.riskScore ?? 0;
  const isSuspicious = riskScore >= 25 || !!lookalikeWarning || isInsecure;

  if (!isSuspicious) return;

  const inputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
  const fillable = inputs.filter(isFillable);
  if (fillable.length === 0 && !paymentFieldsInSubframe) return;

  const hasCard = fillable.some((el) =>
    looksLikeCardNumber({
      type: el.type,
      autocomplete: el.getAttribute('autocomplete'),
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
    })
  );

  const hasCsc = fillable.some((el) =>
    looksLikeCvv({
      type: el.type,
      autocomplete: el.getAttribute('autocomplete'),
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
    })
  );

  const hasExp = fillable.some((el) =>
    looksLikeCardExpiry({
      type: el.type,
      autocomplete: el.getAttribute('autocomplete'),
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
    })
  );

  if (hasCard || (hasCsc && hasExp) || paymentFieldsInSubframe) {
    hasWarnedCheckoutOnPage = true;
    const reasons: string[] = [];
    if (isInsecure) reasons.push('Unencrypted connection (HTTP) transmits card details in plaintext.');
    if (lookalikeWarning) reasons.push(`Domain closely mimics known brand: ${lookalikeWarning.target}`);
    if (domainRisk?.reasons) reasons.push(...domainRisk.reasons);

    showCheckoutProtectionBanner({
      hostname: window.location.hostname,
      riskScore: isInsecure ? 90 : Math.max(riskScore, 50),
      reasons: reasons.slice(0, 3),
      isInsecureHttp: isInsecure,
      onProceedAnyway: () => {
        hasWarnedCheckoutOnPage = true;
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Email Webmail Phishing Guard (Gmail & Outlook)
// ---------------------------------------------------------------------------
const warnedSendersOnPage = new Set<string>();

function scanWebmailMessages(): void {
  if (window === window.top) {
    checkInsecureForms();
    checkOpaqueOriginLogin();
  }
  if (!webmailGuardEnabled || !isSupportedWebmail(window.location.hostname, window.location.pathname)) return;
  scanEmailContent(window.location.hostname);
  // With Email Guard rolled out, the email panel shows the sender check (and
  // more) above the message — don't also raise the older sender banner.
  if (featureOn('email_guard')) return;

  // Gmail: sender name usually in span[email] or .gD; email in [email] attribute
  // Outlook: sender name in .b80yQ or [data-testid="SenderDetails"]
  const candidates: { displayName: string; email: string; raw: string }[] = [];

  // Gmail parsing: Only target the open email view header (.hP, .gE, table.cf)
  // to avoid false alerts on inbox row list previews.
  if (window.location.hostname === 'mail.google.com') {
    // Check if an email conversation is actually open
    const openEmailContainer = document.querySelector('.nH.hx, [role="main"] .adn');
    if (!openEmailContainer) return;

    const senderEls = Array.from(openEmailContainer.querySelectorAll('.gD, span[email]')) as HTMLElement[];
    for (const el of senderEls) {
      const email = el.getAttribute('email') || '';
      const displayName = el.getAttribute('name') || el.textContent || '';
      if (email && email !== displayName) {
        candidates.push({ displayName: displayName.trim(), email: email.trim(), raw: `${displayName} <${email}>` });
      }
    }
  }

  // Outlook Web parsing
  if (window.location.hostname.includes('outlook.')) {
    const senderEls = Array.from(document.querySelectorAll('[data-testid="SenderDetails"], [aria-label*="@"]')) as HTMLElement[];
    for (const el of senderEls) {
      const text = el.textContent || el.getAttribute('aria-label') || '';
      if (text.includes('@')) {
        candidates.push({ displayName: text, email: text, raw: text });
      }
    }
  }

  // Yahoo & AOL Mail parsing
  // Yahoo and AOL share the same mail rendering engine (Oath/Verizon Media)
  if (window.location.hostname.includes('mail.yahoo.com') || window.location.hostname.includes('mail.aol.com')) {
    // Target message view header
    const senderContainer = document.querySelector('[data-test-id="message-view-sender"], [data-test-id="message-header-item"]');
    if (senderContainer) {
      const nameEl = senderContainer.querySelector('[data-test-id="sender-name"], .sender-name, span[role="gridcell"]');
      const emailEl = senderContainer.querySelector('[data-test-id="sender-address"], .sender-address, [role="link"][href^="mailto:"]');
      const displayName = (nameEl?.textContent || '').trim();
      const rawEmail = (emailEl?.textContent || emailEl?.getAttribute('title') || emailEl?.getAttribute('href') || '').replace(/^mailto:/i, '').trim();
      if (rawEmail && rawEmail.includes('@')) {
        candidates.push({ displayName: displayName || rawEmail, email: rawEmail, raw: displayName ? `${displayName} <${rawEmail}>` : rawEmail });
      }
    }
  }

  // Proton Mail parsing
  if (window.location.hostname.includes('proton.')) {
    const senderContainer = document.querySelector('.message-header, [data-testid="message-header"]');
    if (senderContainer) {
      const nameEl = senderContainer.querySelector('[data-testid="message-header:sender-name"], .sender-name');
      const emailEl = senderContainer.querySelector('[data-testid="message-header:sender-address"], .sender-address');
      const displayName = (nameEl?.textContent || '').trim();
      const rawEmail = (emailEl?.textContent || emailEl?.getAttribute('title') || '').replace(/[<>]/g, '').trim();
      if (rawEmail && rawEmail.includes('@')) {
        candidates.push({ displayName: displayName || rawEmail, email: rawEmail, raw: displayName ? `${displayName} <${rawEmail}>` : rawEmail });
      }
    }
  }

  // Zoho Mail parsing
  if (window.location.hostname.includes('mail.zoho.')) {
    const senderContainer = document.querySelector('.zmSender, .zmSenderDetails, .zmMailHeader');
    if (senderContainer) {
      const nameEl = senderContainer.querySelector('.zmSenderName, [data-zm-sender]');
      const emailEl = senderContainer.querySelector('.zmSenderEmail, [data-zm-email], [email]');
      const displayName = (nameEl?.textContent || '').trim();
      const rawEmail = (emailEl?.getAttribute('email') || emailEl?.textContent || '').replace(/[<>]/g, '').trim();
      if (rawEmail && rawEmail.includes('@')) {
        candidates.push({ displayName: displayName || rawEmail, email: rawEmail, raw: displayName ? `${displayName} <${rawEmail}>` : rawEmail });
      }
    }
  }

  for (const c of candidates) {
    if (warnedSendersOnPage.has(c.raw)) continue;
    const analysis = analyzeEmailSender(c.raw);
    if (analysis.isImpersonation && analysis.riskScore >= 70) {
      warnedSendersOnPage.add(c.raw);
      showWebmailPhishingBanner({
        displayName: analysis.claimedBrand ? `${analysis.claimedBrand.toUpperCase()} (Claimed)` : c.displayName,
        senderEmail: analysis.senderEmail,
        reasons: analysis.reasons,
        riskScore: analysis.riskScore,
        onDismiss: () => {
          warnedSendersOnPage.add(c.raw);
        },
      });
      break; // Show one prioritized banner at a time to prevent popup floods
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
      role: el.getAttribute('role'),
      className: el.className,
    });
    if (matches) return el;
  }
  return fallbackField;
}

// ---------------------------------------------------------------------------
// Fill flow
// ---------------------------------------------------------------------------

// True when the risk was driven by an AI agent's autofill attempt rather than
// a human's — surfaced via the free-text `reasons` array since the merged
// risk object doesn't carry structured reason codes through to the content
// script (only the backend response does, pre-merge). Matching on the fixed
// phrase domain_risk.go always appends for this case (AI_SESSION_ELEVATED_SCRUTINY).
function isAiSessionRisk(): boolean {
  return !!domainRisk?.reasons.some((r) => r.toLowerCase().includes('ai autonomous session'));
}

// Builds the human-readable risk message from current domainRisk/lookalikeWarning
// state, shared by the in-dropdown banner (activate()) and the proactive
// unprompted alert (maybeShowProactiveRiskWarning()).
function getRiskWarningMessage(): string | null {
  // Prefer the backend's explanation (static fallback table or OpenAI-
  // generated) — it's already tailored to the specific reason codes,
  // including the AI-session and org-policy cases below, so when present it
  // supersedes the local construction that follows.
  if (domainRisk?.safeWarningMessage) {
    return domainRisk.safeWarningMessage;
  }
  if (domainRisk && domainRisk.decision === 'block') {
    if (isAiSessionRisk()) {
      return 'An AI agent attempted to autofill credentials on this domain, which is not a recognized or approved match. Autofill blocked for security.';
    }
    return domainRisk.matchedTarget
      ? `Phishing / Lookalike Alert: This site mimics "${domainRisk.matchedTarget}". Autofill blocked for security.`
      : 'This site has been flagged as dangerous by threat intelligence. Autofill blocked for security.';
  }
  if (lookalikeWarning) {
    return `This site resembles "${lookalikeWarning.target}". Verify the address before filling.`;
  }
  if (domainRisk && (domainRisk.decision === 'warn' || domainRisk.decision === 'require_approval')) {
    if (isAiSessionRisk()) {
      return 'An AI agent attempted to autofill credentials here on a domain that requires explicit approval first.';
    }
    return `Security Warning: ${domainRisk.reasons[0] || 'Unfamiliar domain variation.'}`;
  }
  return null;
}

let preferredSuggestionLength = 20;

// Opens the credential menu for `passInput`, positioned at `anchor` — the field
// the user actually clicked or focused, so the menu appears where they are
// looking. On a sign-up field the menu leads with a generated password.
function activate(passInput: HTMLInputElement, anchor: HTMLInputElement): void {
  const isNew = newPasswordFields.get(passInput) === true;
  const warning = getRiskWarningMessage();

  // Inspect website password field constraints if present
  const fieldMaxLength = passInput.maxLength > 0 && passInput.maxLength < 500 ? passInput.maxLength : undefined;
  const fieldMinLength = passInput.minLength > 0 && passInput.minLength < 500 ? passInput.minLength : undefined;

  // If the site restricts maxLength below our preferred length, cap it to the site's limit
  let initialLength = preferredSuggestionLength;
  if (fieldMaxLength && initialLength > fieldMaxLength) {
    initialLength = fieldMaxLength;
  }
  if (fieldMinLength && initialLength < fieldMinLength) {
    initialLength = fieldMinLength;
  }

  // Only offer password suggestions on the actual password input itself, never on email/username fields
  const isPasswordField = anchor.type === 'password';
  const showSuggestion = isNew && isPasswordField;

  openDropdown(anchor, {
    credentials: activeCredentials,
    warning,
    onPick: (id) => void handlePick(id, passInput),
    suggestion: showSuggestion
      ? {
          password: generatePassword({ length: initialLength }),
          length: initialLength,
          maxLength: fieldMaxLength,
          minLength: fieldMinLength,
          onRegenerate: (len?: number) => {
            const targetLen = len || initialLength;
            preferredSuggestionLength = targetLen;
            return generatePassword({ length: targetLen });
          },
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
      true,
      window.location.href
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
    .sendMessage({
    type: 'GET_CREDENTIAL_SECRET',
    payload: { id, formContext: collectFormContext(), pageSignals: worthAssessingSignals() },
  })
    .catch(() => null)) as { username?: string; value?: string; accountId?: string; totpCode?: string; error?: string } | null;

  if (!res || res.error || typeof res.value !== 'string') {
    handleFillRefusal(res?.error);
    return;
  }

  // ── AWS Step 2 Multi-field Handling ────────────────────────────────────────
  if (cred.category === 'aws' || window.location.hostname.endsWith('aws.amazon.com')) {
    const awsInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    
    // 1. Find Account ID / Alias field
    const accountInput = awsInputs.find(el => looksLikeAwsAccountId({
      type: el.type,
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label')
    }));

    // 2. Find IAM Username field (any editable text field that isn't the Account ID field and isn't a password field)
    const usernameInput = awsInputs.find(el => el !== accountInput && el.type !== 'password' && el.type !== 'hidden' && (
      el.id === 'username' || 
      el.name === 'username' ||
      el.id?.toLowerCase().includes('username') ||
      el.name?.toLowerCase().includes('username') ||
      looksLikeUsername({
        type: el.type,
        autocomplete: el.getAttribute('autocomplete'),
        name: el.name,
        id: el.id,
        placeholder: el.getAttribute('placeholder'),
        ariaLabel: el.getAttribute('aria-label')
      })
    ));

    if (accountInput && res.accountId) {
      autofillField(accountInput, res.accountId);
    }
    
    const iamUser = res.username || '';
    if (usernameInput && iamUser) {
      autofillField(usernameInput, iamUser);
    }
    
    autofillField(passInput, res.value);
  } else {
    const usernameEl = fieldPairs.get(passInput) ?? null;
    if (usernameEl && usernameEl !== passInput && res.username) {
      autofillField(usernameEl, res.username);
    }
    autofillField(passInput, res.value);

    // Fill any confirm-password sibling with the same value so the user
    // doesn't have to retype it. Only fill fields that are empty, fillable,
    // and look like a "confirm / repeat" new-password box — never the primary
    // password input we just filled.
    const confirmSiblings = (Array.from(
      document.querySelectorAll('input[type="password"]')
    ) as HTMLInputElement[]).filter((p) => p !== passInput && isFillable(p) && !p.value);

    for (const sibling of confirmSiblings) {
      const isNew = looksLikeNewPassword(
        {
          autocomplete: sibling.getAttribute('autocomplete'),
          name: sibling.name,
          id: sibling.id,
          placeholder: sibling.getAttribute('placeholder'),
          ariaLabel: sibling.getAttribute('aria-label'),
        },
        true,
        window.location.href
      );
      if (isNew) autofillField(sibling, res.value);
    }
  }

  // ── 2FA TOTP Code Handling ──────────────────────────────────────────────────
  if (res.totpCode) {
    const code = res.totpCode;
    // Look for any visible one-time code field on the page
    const allInputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    const otpInput = allInputs.find((el) => {
      if (!isFillable(el) || el.type === 'password' || el.type === 'hidden') return false;
      const auto = (el.getAttribute('autocomplete') || '').toLowerCase();
      if (auto.includes('one-time-code')) return true;
      const hint = `${el.name || ''} ${el.id || ''} ${el.placeholder || ''}`.toLowerCase();
      return /\b(otp|totp|mfa|2fa|onetime|one-time|authcode|verificationcode)\b/.test(hint);
    });

    if (otpInput) {
      autofillField(otpInput, code);
      showToast('2FA Code Filled', `Filled verification code: ${code}`);
    } else {
      // Auto-copy to clipboard and notify user
      try {
        void navigator.clipboard.writeText(code);
        void browser.runtime.sendMessage({
          type: 'CLIPBOARD_COPIED',
          payload: { secret: code, id, field: 'totp' },
        }).catch(() => undefined);
        showToast('2FA Code Copied', `Verification code ${code} copied to clipboard`);
      } catch (e) {
        console.warn('[XoraPass] Could not write TOTP to clipboard:', e);
      }
    }
  }
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
  label.innerHTML = `ðŸ¤– <b>${escapeHtml(offer.aiToolName)}</b> was approved to ${escapeHtml(
    offer.action
  )} on this page â€” fill now?`;
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
 * frameworks which track the property (React, Vue) observe the change â€” a
 * plain `el.value = x` is silently reverted by React's controlled inputs.
 */
function autofillField(el: HTMLInputElement, value: string): void {
  // Use the native setter to bypass React/Vue's value tracking so the
  // internal state and the DOM value are both updated.
  const nativeSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value'
  )?.set;

  // 1. Focus — many validators (Steam, Angular, custom) only arm their
  //    change-detection after the field has been focused.
  el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));

  // 2. Set the value via the native prototype setter so React's synthetic
  //    event system sees the change (direct el.value = x is intercepted by
  //    React and won't update internal fiber state).
  if (nativeSetter) {
    nativeSetter.call(el, value);
  } else {
    el.value = value;
  }

  // 3. InputEvent with inputType='insertText' — React, Vue 3, and many
  //    plain-JS validators check event.inputType to decide whether to run
  //    validation. A generic Event('input') is ignored by those frameworks.
  el.dispatchEvent(
    new InputEvent('input', {
      bubbles: true,
      cancelable: true,
      inputType: 'insertText',
      data: value,
    })
  );

  // 4. change + blur — needed by jQuery validate, Angular, and sites that
  //    only compare confirm vs. password on blur.
  el.dispatchEvent(new Event('change', { bubbles: true }));
  el.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
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
      // editing, not looking for a credential — and because focusin fires once
      // per focus, a menu they dismiss with Escape or an outside click does not
      // reopen while focus stays on the same field.
      if (el.value) return;

      activate(passInput, el);
    },
    true
  );

  // If the user clicks the password box while the dropdown is already open, close it
  document.addEventListener(
    'click',
    (e) => {
      const el = e.target;
      if (el instanceof HTMLInputElement && focusActivators.has(el) && isDropdownOpen()) {
        closeDropdown();
      }
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
    target.dispatchEvent(new Event('change', { bubbles: true }));
    return;
  }

  target.focus();
  if (caret?.kind === 'contenteditable' && caret.range) {
    try {
      const selection = window.getSelection();
      if (selection) {
        selection.removeAllRanges();
        selection.addRange(caret.range);
        const success = document.execCommand('insertText', false, text);
        if (success) {
          target.dispatchEvent(new Event('input', { bubbles: true }));
          return;
        }
      }
    } catch {
      /* fallback below */
    }
  }

  try {
    const success = document.execCommand('insertText', false, text);
    if (!success && target.isContentEditable) {
      target.textContent = (target.textContent || '') + text;
    }
  } catch {
    if (target.isContentEditable) {
      target.textContent = (target.textContent || '') + text;
    }
  }
  target.dispatchEvent(new Event('input', { bubbles: true }));
}

function initWebBridge(): void {
  const allowedOrigins = new Set([
    'https://app.xorapass.com',
    'http://localhost:3000',
    'http://localhost:8000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:8000',
  ]);

  if (!allowedOrigins.has(window.location.origin)) {
    return;
  }

  window.addEventListener('message', async (event) => {
    if (event.source !== window || event.origin !== window.location.origin) return;
    const data = event.data;
    if (!data || data.source !== 'xorapass-web-bridge' || typeof data.type !== 'string') return;

    const { requestId, type, payload } = data;
    try {
      const response = await browser.runtime.sendMessage({ type, payload });
      window.postMessage(
        {
          source: 'xorapass-extension-bridge',
          requestId,
          response,
        },
        window.location.origin
      );
    } catch (err) {
      window.postMessage(
        {
          source: 'xorapass-extension-bridge',
          requestId,
          response: { error: 'bridge_transport_failed', detail: String(err) },
        },
        window.location.origin
      );
    }
  });
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
  let currentScan = scan;
  let matchedVaultEntryId: string | undefined = undefined;

  // Check if all matched secrets in this typing sequence have already been bypassed
  const allAlreadyBypassed = currentScan.matches.every(m => bypassedSecrets.has(m.value));
  if (allAlreadyBypassed) return;

  try {
    const copiedRes: any = await browser.runtime.sendMessage({ type: 'GET_COPIED_SECRET' });
    const copiedSecret = copiedRes?.secret;
    const copiedId = copiedRes?.id;
    const copiedField = copiedRes?.field;
    if (copiedSecret && text.includes(copiedSecret)) {
      matchedVaultEntryId = copiedId || undefined;
      const start = text.indexOf(copiedSecret);
      const end = start + copiedSecret.length;
      
      let typeVal: SecretType = 'generic_secret';
      if (copiedField === 'password') typeVal = 'password';
      else if (copiedField === 'privateKey') typeVal = 'private_key';

      const alreadyMatched = currentScan.matches.some(m => m.start === start && m.end === end);
      if (alreadyMatched) {
        for (const m of currentScan.matches) {
          if (m.start === start && m.end === end) {
            m.type = typeVal;
            m.label = copiedField === 'password' ? 'Password' : copiedField === 'privateKey' ? 'Private key' : 'Copied vault credential';
          }
        }
      } else {
        const copiedMatch = {
          type: typeVal,
          label: copiedField === 'password' ? 'Password' : copiedField === 'privateKey' ? 'Private key' : 'Copied vault credential',
          start,
          end,
          value: copiedSecret,
          preview: '••••••••',
        };
        currentScan = {
          matches: [...currentScan.matches, copiedMatch],
          types: Array.from(new Set([...currentScan.types, typeVal])),
        };
      }
      currentScan.types = Array.from(new Set(currentScan.matches.map(m => m.type)));
    }
  } catch (e) {
    console.debug("Failed to get copied secret", e);
  }

  if (currentScan.matches.length === 0) return;

  const labels = Array.from(new Set(currentScan.matches.map((m) => m.label)));
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
      `Preview: ${redact(text, currentScan.matches).slice(0, 120)}`,
    ],
    confirmLabel: 'Keep anyway',
    cancelLabel: 'Remove secret',
  });

  if (!proceed) {
    setEditableText(el, redact(text, currentScan.matches));
  } else {
    for (const m of currentScan.matches) {
      bypassedSecrets.add(m.value);
    }
    void browser.runtime
      .sendMessage({
        type: 'AI_PASTE_EVENT',
        payload: {
          hostname,
          types: currentScan.types,
          action: 'type',
          isAiSite: isAiSite(hostname),
          vaultEntryId: matchedVaultEntryId,
        },
      })
      .catch(() => {});
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
  const allBypassed = scan.matches.every(m => bypassedSecrets.has(m.value));
  if (allBypassed) return;
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
    const allBypassed = scan.matches.every(m => bypassedSecrets.has(m.value));
    if (allBypassed) return;
    void runTypingGuard(target, text, scan);
  }, TYPING_DEBOUNCE_MS);
}

async function handleSecretPaste(
  target: HTMLElement | null,
  text: string,
  caret: CaretSnapshot | null,
  action: 'paste' | 'drop'
): Promise<void> {
  const hostname = window.location.hostname;
  let currentScan = scanForSecrets(text);
  let matchedVaultEntryId: string | undefined = undefined;

  try {
    const copiedRes: any = await browser.runtime.sendMessage({ type: 'GET_COPIED_SECRET' });
    const copiedSecret = copiedRes?.secret;
    const copiedId = copiedRes?.id;
    const copiedField = copiedRes?.field;
    if (copiedSecret && text.includes(copiedSecret)) {
      matchedVaultEntryId = copiedId || undefined;
      const start = text.indexOf(copiedSecret);
      const end = start + copiedSecret.length;
      
      let typeVal: SecretType = 'generic_secret';
      if (copiedField === 'password') typeVal = 'password';
      else if (copiedField === 'privateKey') typeVal = 'private_key';

      const alreadyMatched = currentScan.matches.some(m => m.start === start && m.end === end);
      if (alreadyMatched) {
        for (const m of currentScan.matches) {
          if (m.start === start && m.end === end) {
            m.type = typeVal;
            m.label = copiedField === 'password' ? 'Password' : copiedField === 'privateKey' ? 'Private key' : 'Copied vault credential';
          }
        }
      } else {
        const copiedMatch = {
          type: typeVal,
          label: copiedField === 'password' ? 'Password' : copiedField === 'privateKey' ? 'Private key' : 'Copied vault credential',
          start,
          end,
          value: copiedSecret,
          preview: '••••••••',
        };
        currentScan = {
          matches: [...currentScan.matches, copiedMatch],
          types: Array.from(new Set([...currentScan.types, typeVal])),
        };
      }
      currentScan.types = Array.from(new Set(currentScan.matches.map(m => m.type)));
    }
  } catch (e) {
    console.debug("Failed to get copied secret", e);
  }

  // Check if all matched secrets in this pasted string have already been bypassed
  const allAlreadyBypassed = currentScan.matches.every(m => bypassedSecrets.has(m.value));
  if (allAlreadyBypassed && currentScan.matches.length > 0) {
    if (target) insertTextAtCaret(target, text, caret);
    return;
  }

  // If no secrets detected at all, proceed with the paste silently and instantly!
  if (currentScan.matches.length === 0) {
    if (target) insertTextAtCaret(target, text, caret);
    return;
  }

  const labels = Array.from(new Set(currentScan.matches.map((m) => m.label)));
  const isBlock = pastePolicy.mode === 'block' || !pastePolicy.allowDismiss;

  if (isBlock) {
    await showConfirmDialog({
      title: 'Secret paste blocked',
      body: [
        `XoraPass detected ${labels.join(', ')} in what you tried to paste.`,
        'Pasting secrets into AI tools is blocked by policy.',
        `Preview: ${redact(text, currentScan.matches).slice(0, 120)}`,
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
      `Preview: ${redact(text, currentScan.matches).slice(0, 120)}`,
    ],
    confirmLabel: 'Paste anyway',
    cancelLabel: 'Cancel',
  });

  if (proceed && target) {
    for (const m of currentScan.matches) {
      bypassedSecrets.add(m.value);
    }
    void browser.runtime
      .sendMessage({
        type: 'AI_PASTE_EVENT',
        payload: {
          hostname,
          types: currentScan.types,
          action,
          isAiSite: isAiSite(hostname),
          vaultEntryId: matchedVaultEntryId,
        },
      })
      .catch(() => {});
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
      // If the paste payload contains files/images (e.g. image/png, image/jpeg),
      // allow native browser image handling to proceed without interception.
      const types = Array.from(e.clipboardData?.types || []);
      if (types.includes('Files') || (e.clipboardData?.files && e.clipboardData.files.length > 0)) {
        return;
      }

      const text = e.clipboardData?.getData('text/plain') || e.clipboardData?.getData('text') || '';
      if (!text) return;

      const hostname = window.location.hostname;
      if (!shouldGuard(pastePolicy, hostname)) return;

      e.preventDefault();
      e.stopPropagation();

      const target = getPasteTarget(e);
      const caret = target ? captureCaret(target) : null;
      void handleSecretPaste(target, text, caret, 'paste');
    },
    true
  );

  document.addEventListener(
    'drop',
    (e) => {
      // If the dropped payload contains files/images, allow native drop handling.
      const types = Array.from(e.dataTransfer?.types || []);
      if (types.includes('Files') || (e.dataTransfer?.files && e.dataTransfer.files.length > 0)) {
        return;
      }

      const text = e.dataTransfer?.getData('text/plain') || e.dataTransfer?.getData('text') || '';
      if (!text) return;

      const hostname = window.location.hostname;
      if (!shouldGuard(pastePolicy, hostname)) return;

      e.preventDefault();
      e.stopPropagation();

      const target = getPasteTarget(e);
      const caret = target ? captureCaret(target) : null;
      void handleSecretPaste(target, text, caret, 'drop');
    },
    true
  );

  document.addEventListener('input', onInput, true);
  setInterval(pollActiveEditable, 700);
}

// Bootstrap
// ---------------------------------------------------------------------------

const frame = assessFrame();
if (frame.isTop || !frame.isCrossOriginFrame) {
  // Only run in the top frame or in a same-origin (first-party) sub-frame.
  initOverlayTheme();
  initPasteGuard();
  initWebBridge();
  if (window === window.top) setTimeout(checkOpaqueOriginLogin, 300);
  // Webmail checks shouldn't depend on the credential lookup finishing.
  if (window === window.top) setTimeout(scanWebmailMessages, 600);
  // The first risk check includes the on-device favicon match. The tab icon
  // is normally cached, so this waits a few ms (400 ms at most).
  if (window === window.top && /^https?:$/.test(location.protocol)) {
    void Promise.race([primeFaviconBrand(), new Promise((r) => setTimeout(r, 400))]).then(() => loadCredentials());
  } else {
    loadCredentials();
  }
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
    scanForPaymentFields();
    scanWebmailMessages();
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
    scanWebmailMessages();
  });

  // A tab returning from the background may have been locked in the meantime.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      loadCredentials();
      scanWebmailMessages();
    }
  });

  // Never leave a menu floating over a page the user navigated away from.
  window.addEventListener('pagehide', () => {
    closeDropdown();
    closeSavePrompt();
    closeRiskWarning();
    closeCheckoutProtectionBanner();
    closeWebmailPhishingBanner();
  });

  // Listen for link inspection results triggered via right-click context menu
  browser.runtime.onMessage.addListener((message: any) => {
    if (message?.type === 'SHOW_LINK_INSPECTION' && message.payload) {
      showLinkInspectionModal(message.payload);
    }
    // Site Scanner (popup → background → here): structural page features
    // only — see the privacy contract in utils/pageSignals.ts.
    if (message?.type === 'GET_PAGE_SIGNALS') {
      return Promise.resolve({ pageSignals: collectPageSignals() });
    }
    // Privacy report (popup): trackers + mixed content seen by this page.
    if (message?.type === 'GET_PRIVACY_SIGNALS' && window === window.top) {
      return Promise.resolve({ privacy: collectPrivacySignals() });
    }
    // Download guard (background): ask before keeping a risky file.
    if (message?.type === 'SHIELD_DOWNLOAD_PROMPT' && window === window.top) {
      return showDownloadPrompt(message.payload || {});
    }
    if (message?.type === 'SHIELD_DOWNLOAD_BLOCKED' && window === window.top) {
      showDownloadBlocked(message.payload || {});
    }
    if (message?.type === 'CARD_FIELDS_IN_FRAME') {
      paymentFieldsInSubframe = true;
      scanForPaymentFields();
    }
    if (message?.type === 'TAB_RISK_UPDATE' && window === window.top) {
      if (message.risk) {
        domainRisk = message.risk;
        lastWarnedRiskKey = null; // force re-evaluation
        maybeShowProactiveRiskWarning();
      }
      return Promise.resolve({ received: true });
    }
    return undefined;
  });

  // Listen for real-time Shield toggle changes from popup settings
  try {
    browser.storage.onChanged.addListener((changes: any, area: string) => {
      if (area === 'local') {
        if (changes?.checkoutGuardEnabled) {
          checkoutGuardEnabled = !!changes.checkoutGuardEnabled.newValue;
          if (!checkoutGuardEnabled) closeCheckoutProtectionBanner();
        }
        if (changes?.webmailGuardEnabled) {
          webmailGuardEnabled = !!changes.webmailGuardEnabled.newValue;
          if (!webmailGuardEnabled) closeWebmailPhishingBanner();
        }
      }
    });
  } catch {}
} else {
  // Third-party iframe: autofill deliberately blocked, and so is AI-approved
  // fill -- the same framing attack this guard exists for applies equally.
  console.debug('[XoraPass] Autofill disabled inside third-party iframe.');
}

// ── Firefox postMessage bridge ─────────────────────────────────────────────
// Firefox does not expose chrome.runtime.sendMessage to web pages, so the
// web app falls back to window.postMessage({source:'xorapass-web-bridge',...}).
// This content script listens for those messages, forwards them to the
// background worker via browser.runtime.sendMessage, and posts the response
// back as {source:'xorapass-extension-bridge', requestId, response}.
//
// Only WEB_BRIDGE_* message types are forwarded; all others are silently
// ignored. Origin is validated against the allowed app hostnames.
(function installWebBridge() {
  const ALLOWED_ORIGINS = new Set([
    'https://app.xorapass.com',
    WEB_APP_URL,
  ]);

  window.addEventListener('message', (event: MessageEvent) => {
    // Must be same-window, correct source tag, and allowed origin.
    const isSameWindow = event.source === window || 
      (typeof window !== 'undefined' && (window as any).wrappedJSObject && event.source === (window as any).wrappedJSObject);
    if (!isSameWindow) return;
    if (!event.data || event.data.source !== 'xorapass-web-bridge') return;
    if (!ALLOWED_ORIGINS.has(event.origin)) return;

    const { requestId, type, payload } = event.data as {
      requestId: string;
      type: string;
      payload?: unknown;
    };

    // Only bridge WEB_BRIDGE_* message types.
    if (typeof type !== 'string' || !type.startsWith('WEB_BRIDGE_')) return;

    void browser.runtime.sendMessage({ type, payload }).then(
      (response: unknown) => {
        window.postMessage(
          { source: 'xorapass-extension-bridge', requestId, response },
          event.origin,
        );
      },
      () => {
        // Background not reachable (extension disabled etc.) — send null so
        // the web app's 1500 ms timeout resolves immediately instead of waiting.
        window.postMessage(
          { source: 'xorapass-extension-bridge', requestId, response: null },
          event.origin,
        );
      },
    );
  });
})();

