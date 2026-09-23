// XoraPass Shield — secure-browsing features that live in the background:
//
//   • Per-tab behaviour log from the page hooks (SHIELD_BEHAVIOR), for the
//     popup's privacy report (fingerprinting, lock-in, wallet prompts …).
//   • Tracker blocking with declarativeNetRequest (optional permission; our
//     own curated list, THIRD-party requests only, per-site allow).
//   • Download protection (optional `downloads` permission): a new download
//     from a blocklisted / dangerous source is cancelled; a runnable file or
//     archive from a new / suspicious / HTTP source is paused and the user
//     asked. An extension can't read the file's bytes, so this checks the
//     source and the file type; file hashes are checked in "Is it Safe".
//   • The known-malicious extension list for Extension Checkup (12 h cache).
//
// Everything here is part of paid always-on Shield (isShieldActive()).

import browser from 'webextension-polyfill';
import { API_BASE_URL } from '../utils/config';
import { authHeaderValue, checkDomainRiskRemote } from '../utils/domainRiskService';
import { extractHostname, registrableDomain } from '../utils/siteTrust';
import { blockableTrackerDomains } from '../utils/trackerList';
import { decideDownload, fileExtension, RUNNABLE_EXTENSIONS } from '../utils/downloadGuard';
import { checkBlocklist, getShieldCredential, shieldFeature } from './shield';

// ── Settings ───────────────────────────────────────────────────────────────

export interface PrivacySettings {
  blockTrackers: boolean;
  trackerAllowSites: string[]; // registrable domains where trackers are allowed
  downloadGuard: boolean;
}

const SETTINGS_KEY = 'shieldPrivacySettings';
const DEFAULT_SETTINGS: PrivacySettings = { blockTrackers: false, trackerAllowSites: [], downloadGuard: false };

export async function getPrivacySettings(): Promise<PrivacySettings> {
  const r = (await browser.storage.local.get(SETTINGS_KEY)) as Record<string, Partial<PrivacySettings> | undefined>;
  const s = r[SETTINGS_KEY] || {};
  return {
    blockTrackers: typeof s.blockTrackers === 'boolean' ? s.blockTrackers : DEFAULT_SETTINGS.blockTrackers,
    trackerAllowSites: Array.isArray(s.trackerAllowSites)
      ? s.trackerAllowSites.filter((d): d is string => typeof d === 'string').slice(0, 500)
      : [],
    downloadGuard: typeof s.downloadGuard === 'boolean' ? s.downloadGuard : DEFAULT_SETTINGS.downloadGuard,
  };
}

/** Popup-only. Permissions must already be granted by the popup (user gesture). */
export async function setPrivacySettings(patch: Partial<PrivacySettings>): Promise<PrivacySettings> {
  const cur = await getPrivacySettings();
  const next: PrivacySettings = {
    blockTrackers: typeof patch.blockTrackers === 'boolean' ? patch.blockTrackers : cur.blockTrackers,
    trackerAllowSites: Array.isArray(patch.trackerAllowSites)
      ? Array.from(
          new Set(
            patch.trackerAllowSites
              .filter((d): d is string => typeof d === 'string')
              .map((d) => registrableDomain(extractHostname(d) || d))
              .filter(Boolean)
          )
        ).slice(0, 500)
      : cur.trackerAllowSites,
    downloadGuard: typeof patch.downloadGuard === 'boolean' ? patch.downloadGuard : cur.downloadGuard,
  };
  await browser.storage.local.set({ [SETTINGS_KEY]: next });
  await applyTrackerRules();
  registerDownloadListener();
  return next;
}

async function hasPermission(p: string): Promise<boolean> {
  try {
    return await browser.permissions.contains({ permissions: [p as any] });
  } catch {
    return false;
  }
}

// ── Tracker blocking (declarativeNetRequest) ─────────────────────────────

const TRACKER_RULE_ID = 9001;

export async function applyTrackerRules(): Promise<{ enabled: boolean; domains: number }> {
  const dnr = (globalThis as any).chrome?.declarativeNetRequest || (browser as any).declarativeNetRequest;
  if (!dnr?.updateDynamicRules || !(await hasPermission('declarativeNetRequest'))) return { enabled: false, domains: 0 };
  const s = await getPrivacySettings();
  const on = s.blockTrackers && (await shieldFeature('tracker_blocking'));
  const domains = blockableTrackerDomains();
  const rule = {
    id: TRACKER_RULE_ID,
    priority: 1,
    action: { type: 'block' },
    condition: {
      requestDomains: domains,
      domainType: 'thirdParty',
      // sendBeacon is "ping" in declarativeNetRequest.
      resourceTypes: ['script', 'xmlhttprequest', 'image', 'sub_frame', 'ping', 'other'],
      ...(s.trackerAllowSites.length ? { excludedInitiatorDomains: s.trackerAllowSites } : {}),
    },
  };
  try {
    await dnr.updateDynamicRules({ removeRuleIds: [TRACKER_RULE_ID], addRules: on ? [rule] : [] });
  } catch (e) {
    console.warn('[XoraPass Shield] tracker rules failed', e);
    return { enabled: false, domains: 0 };
  }
  return { enabled: on, domains: on ? domains.length : 0 };
}

// ── Per-tab behaviour log ────────────────────────────────────────────────

const BEHAVIOR_KINDS = new Set([
  'fingerprint', 'fullscreen', 'keyboard_lock', 'pointer_lock', 'beforeunload', 'history_flood', 'autoplay_audio',
  'notification_request', 'clickfix', 'wallet_check', 'tech_support_scam',
]);

interface TabBehavior {
  host: string;
  kinds: Set<string>;
  fingerprint: string[];
  at: number;
}
const tabBehaviors = new Map<number, TabBehavior>();

export function recordBehavior(sender: browser.Runtime.MessageSender, payload: any): { ok: boolean } {
  const tabId = sender.tab?.id;
  const kind = String(payload?.kind || '');
  if (tabId === undefined || sender.frameId !== 0 || !BEHAVIOR_KINDS.has(kind)) return { ok: false };
  const host = extractHostname(sender.url || sender.tab?.url || '');
  let cur = tabBehaviors.get(tabId);
  if (!cur || cur.host !== host) {
    cur = { host, kinds: new Set(), fingerprint: [], at: Date.now() };
    tabBehaviors.set(tabId, cur);
  }
  cur.kinds.add(kind);
  if (kind === 'fingerprint' && Array.isArray(payload.techniques)) {
    cur.fingerprint = Array.from(
      new Set([...cur.fingerprint, ...payload.techniques.filter((t: unknown) => typeof t === 'string' && t.length < 20)])
    ).slice(0, 8);
  }
  cur.at = Date.now();
  if (tabBehaviors.size > 300) {
    const oldest = Array.from(tabBehaviors.entries()).sort((a, b) => a[1].at - b[1].at)[0];
    if (oldest) tabBehaviors.delete(oldest[0]);
  }
  return { ok: true };
}

export function getTabBehavior(tabId: number, url: string): { kinds: string[]; fingerprint: string[] } {
  const b = tabBehaviors.get(tabId);
  if (!b || b.host !== extractHostname(url)) return { kinds: [], fingerprint: [] };
  return { kinds: Array.from(b.kinds), fingerprint: b.fingerprint };
}

// ── Download protection ──────────────────────────────────────────────────

async function domainAgeDays(host: string, cred: string): Promise<number> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 4000);
    const res = await fetch(`${API_BASE_URL}/api/shield/domain-intel?domain=${encodeURIComponent(registrableDomain(host) || host)}`, {
      headers: { Authorization: authHeaderValue(cred) },
      signal: ctl.signal,
    });
    clearTimeout(t);
    if (!res.ok) return -1;
    const d = (await res.json()) as { age_days?: number; known?: boolean };
    return d.known && typeof d.age_days === 'number' ? d.age_days : -1;
  } catch {
    return -1;
  }
}

async function activeTabId(): Promise<number | undefined> {
  try {
    const [t] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
    return t?.id;
  } catch {
    return undefined;
  }
}

async function onDownloadCreated(item: any): Promise<void> {
  const url: string = item.finalUrl || item.url || '';
  if (!/^https?:\/\//i.test(url)) return; // blob:/data: — nothing to check at the source
  const s = await getPrivacySettings();
  if (!s.downloadGuard || !(await shieldFeature('download_guard'))) return;

  const dl = (browser as any).downloads;
  const ext = fileExtension(item.filename || '') || fileExtension(url);
  const risky = RUNNABLE_EXTENSIONS.has(ext) || ['zip', 'rar', '7z', 'cab', 'tar', 'gz', 'tgz'].includes(ext) || !ext;
  // Pause while we look; resumes on every non-block path.
  let paused = false;
  if (risky && item.state === 'in_progress') {
    try {
      await dl.pause(item.id);
      paused = true;
    } catch {
      /* already finished or not pausable */
    }
  }
  const resume = async () => {
    if (paused) await dl.resume(item.id).catch(() => undefined);
  };

  try {
    const host = extractHostname(url);
    const blocklisted = !!(await checkBlocklist(url));
    type RemoteDecision = 'allow' | 'warn' | 'require_approval' | 'block' | null;
    let remoteDecision: RemoteDecision = null;
    let age = -1;
    if (!blocklisted && risky) {
      const cred = await getShieldCredential();
      const [remote, days] = await Promise.all([
        checkDomainRiskRemote(url, '', undefined, undefined, 'standard', globalThis.fetch, getShieldCredential).catch(() => null),
        cred ? domainAgeDays(host, cred) : Promise.resolve(-1),
      ]);
      remoteDecision = ((remote?.decision as string | undefined) || null) as RemoteDecision;
      age = days;
    }
    const verdict = decideDownload({
      filename: item.filename || '',
      url,
      mime: item.mime,
      blocklisted,
      remoteDecision,
      domainAgeDays: age,
      isHttp: /^http:\/\//i.test(url),
    });
    const tabId = await activeTabId();
    const payload = { filename: item.filename || url.split(/[?#]/)[0].split('/').pop(), host, reasons: verdict.reasons };

    if (verdict.action === 'block') {
      await dl.cancel(item.id).catch(() => undefined);
      await dl.erase?.({ id: item.id }).catch(() => undefined);
      if (tabId !== undefined) {
        browser.tabs.sendMessage(tabId, { type: 'SHIELD_DOWNLOAD_BLOCKED', payload }, { frameId: 0 }).catch(() => undefined);
      }
      return;
    }
    if (verdict.action === 'warn' && tabId !== undefined) {
      const answer = (await browser.tabs
        .sendMessage(tabId, { type: 'SHIELD_DOWNLOAD_PROMPT', payload }, { frameId: 0 })
        .catch(() => null)) as { keep?: boolean } | null;
      if (answer && answer.keep === false) {
        await dl.cancel(item.id).catch(() => undefined);
        return;
      }
    }
    await resume();
  } catch {
    await resume(); // fail open
  }
}

let downloadListenerOn = false;
export function registerDownloadListener(): void {
  const dl = (browser as any).downloads;
  if (downloadListenerOn || !dl?.onCreated) return;
  downloadListenerOn = true;
  dl.onCreated.addListener((item: any) => {
    void onDownloadCreated(item);
  });
}

// ── Known-malicious extension IDs ────────────────────────────────────────

const MALICIOUS_EXT_KEY = 'shieldMaliciousExtensions';
const MALICIOUS_EXT_TTL = 12 * 60 * 60 * 1000;

export async function getMaliciousExtensionIds(): Promise<Set<string>> {
  const r = (await browser.storage.local.get(MALICIOUS_EXT_KEY)) as Record<string, { ids: string[]; at: number } | undefined>;
  const cached = r[MALICIOUS_EXT_KEY];
  if (cached && Date.now() - cached.at < MALICIOUS_EXT_TTL) return new Set(cached.ids);
  try {
    const res = await fetch(`${API_BASE_URL}/api/shield/malicious-extensions`);
    if (res.ok) {
      const data = (await res.json()) as { extensions?: { id?: string }[] };
      const ids = (data.extensions || [])
        .map((e) => e.id)
        .filter((id): id is string => typeof id === 'string' && /^[a-z0-9@._{}-]{1,128}$/i.test(id))
        .slice(0, 20000);
      await browser.storage.local.set({ [MALICIOUS_EXT_KEY]: { ids, at: Date.now() } });
      return new Set(ids);
    }
  } catch {
    /* offline: fall back to the stale copy */
  }
  return new Set(cached?.ids || []);
}

// ── Init ─────────────────────────────────────────────────────────────────

export function initShieldPrivacy(): void {
  registerDownloadListener();
  void applyTrackerRules();
  // Rollout / entitlement changes turn tracker rules on or off.
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes.shieldEntitlement || changes.shieldConfig)) void applyTrackerRules();
  });
  browser.tabs.onRemoved.addListener((tabId) => tabBehaviors.delete(tabId));
  browser.permissions.onAdded?.addListener(() => {
    registerDownloadListener();
    void applyTrackerRules();
  });
  browser.permissions.onRemoved?.addListener(() => void applyTrackerRules());
}
