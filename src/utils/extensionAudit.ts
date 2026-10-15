// Extension Security Audit Service
// Scans installed extensions via browser.management / chrome.management
// and calculates risk levels based on dangerous and broad permissions.

export interface ExtensionPermissionRisk {
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  installType: string;
  icons?: { size: number; url: string }[];
  permissions: string[];
  hostPermissions: string[];
  riskLevel: 'unknown' | 'low' | 'high';
  reputation: 'known_malicious' | 'unknown';
  riskScore: number;
  threatReasons: string[];
}

export interface ExtensionAuditSummary {
  totalExtensions: number;
  enabledExtensions: number;
  highRiskCount: number;
  lowRiskCount: number;
  unknownCount: number;
  inspection: 'available' | 'unavailable';
  reputationChecked: boolean;
  reputationSource: 'current' | 'stale' | 'unavailable';
  extensions: ExtensionPermissionRisk[];
}

// Dangerous capabilities that could intercept secrets or credentials
const HIGH_RISK_PERMISSIONS = new Set([
  'webRequest',
  'webRequestBlocking',
  'webRequestAuthProvider',
  'declarativeNetRequest',
  'debugger',
  'pageCapture',
  'tabCapture',
  'proxy',
  'cookies',
]);

const ALL_URL_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
];

// Additional high/medium permission weights (score, user explanation)
const EXTRA_RISK_PERMISSIONS: Record<string, [number, string]> = {
  downloads: [15, 'Can initiate and manage file downloads'],
  management: [25, 'Can inspect, enable, disable or uninstall other browser extensions'],
  nativeMessaging: [30, 'Can communicate with native applications outside the browser'],
  geolocation: [10, 'Can access your physical location'],
  history: [15, 'Can read and modify your complete browsing history'],
  bookmarks: [10, 'Can read and modify your browser bookmarks'],
  topSites: [10, 'Can view your most frequently visited websites'],
  privacy: [20, 'Can alter core browser privacy and security settings'],
};

// Known official extension store update hosts
const STORE_UPDATE_HOSTS = [
  'clients2.google.com',
  'clients2.googleusercontent.com',
  'addons.mozilla.org',
  'extensionworkshop.com',
  'microsoftedge.microsoft.com',
];

/** Store/sideload checks for one extension (pure, unit-tested). */
export function installOriginFindings(ext: { installType?: string; updateUrl?: string; id?: string }, maliciousIds?: ReadonlySet<string>): [number, string][] {
  const out: [number, string][] = [];
  if (ext.id && maliciousIds?.has(ext.id)) out.push([100, 'Known malicious extension — remove it now']);
  if (ext.installType === 'development') out.push([35, 'Loaded in developer mode (unpacked), not from a store']);
  else if (ext.installType === 'sideload') out.push([40, 'Installed by another program, not from a store']);
  if (ext.updateUrl) {
    let host = '';
    try {
      host = new URL(ext.updateUrl).hostname;
    } catch {
      host = '';
    }
    if (host && !STORE_UPDATE_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {
      out.push([30, `Updates from outside the official store (${host})`]);
    }
  }
  return out;
}

async function getAllInstalledItems(customApi?: any): Promise<any[] | null> {
  const candidates = customApi ? [customApi] : [(globalThis as any).chrome?.management, (globalThis as any).browser?.management].filter(Boolean);
  for (const api of candidates) {
    if (typeof api?.getAll !== 'function') continue;
    try {
      const result = api.getAll();
      if (result && typeof result.then === 'function') {
        const items = await result;
        if (Array.isArray(items)) return items;
        continue;
      }
    } catch { /* callback API or rejected inspection */ }
    const items = await new Promise<any[] | null>(resolve => {
      const timer = setTimeout(() => resolve(null), 2000);
      const finish = (value: unknown) => { clearTimeout(timer); resolve(Array.isArray(value) ? value : null); };
      try {
        const pending = api.getAll((value: unknown) => {
          if ((globalThis as any).chrome?.runtime?.lastError) finish(null); else finish(value);
        });
        if (pending?.then) pending.then(finish).catch(() => finish(null));
      } catch { finish(null); }
    });
    if (items) return items;
  }
  return null;
}

export async function auditInstalledExtensions(
  maliciousIds?: ReadonlySet<string>,
  managementApi?: any, reputationSource: 'current' | 'stale' | 'unavailable' = maliciousIds ? 'current' : 'unavailable'
): Promise<ExtensionAuditSummary> {
  const allItems = await getAllInstalledItems(managementApi);

  if (!allItems || !allItems.every(item => item && typeof item.id === 'string' &&
      [item.permissions, item.hostPermissions].every(list => list === undefined || (Array.isArray(list) && list.every(p => typeof p === 'string'))))) {
    return {
      totalExtensions: 0,
      enabledExtensions: 0,
      highRiskCount: 0,
      lowRiskCount: 0,
      unknownCount: 0,
      inspection: 'unavailable',
      reputationChecked: reputationSource === 'current',
    reputationSource,
      extensions: [],
    };
  }

  // Filter for installed extensions and apps (exclude purely cosmetic themes and ourselves)
  const myId =
    (globalThis as any).browser?.runtime?.id ||
    (globalThis as any).chrome?.runtime?.id;
  const extensionsList = allItems.filter(
    (item) => item && item.type !== 'theme' && item.id !== myId
  );

  const audited: ExtensionPermissionRisk[] = extensionsList.map((ext) => {
    const permissions: string[] = ext.permissions || [];
    const hostPermissions: string[] = ext.hostPermissions || [];
    const threatReasons: string[] = [];
    let riskScore = 0;

    const hasAllUrls =
      hostPermissions.some((h) => ALL_URL_PATTERNS.some((p) => h.includes(p))) ||
      permissions.some((p) => ALL_URL_PATTERNS.some((pattern) => p.includes(pattern)));

    const hasWebRequest = permissions.some((p) => HIGH_RISK_PERMISSIONS.has(p));
    const hasCookies = permissions.includes('cookies');
    const hasClipboard = permissions.includes('clipboardRead');
    const hasTabs = permissions.includes('tabs');

    // 1. Critical intercept risk: All URLs + webRequest or cookies
    if (hasAllUrls && (hasWebRequest || hasCookies)) {
      riskScore += 50;
      threatReasons.push('Has full access to inspect network traffic or cookies across all websites');
    } else if (hasAllUrls && hasTabs) {
      riskScore += 30;
      threatReasons.push('Can monitor active browsing tabs and URLs across all websites');
    }

    // 2. Clipboard snooping risk
    if (hasClipboard) {
      riskScore += 25;
      threatReasons.push('Can read sensitive text and passwords from your clipboard');
    }

    // 3. Debugger attachment capability
    if (permissions.includes('debugger')) {
      riskScore += 45;
      threatReasons.push('Debugger access: Can manipulate pages and inspect private DOM memory');
    }

    // 4. Broad host permissions alone
    if (hasAllUrls && threatReasons.length === 0) {
      riskScore += 20;
      threatReasons.push('Has broad read/write access to all visited websites');
    }

    // 5. Other powerful permissions
    for (const p of permissions) {
      const extra = EXTRA_RISK_PERMISSIONS[p];
      if (extra) {
        riskScore += extra[0];
        threatReasons.push(extra[1]);
      }
    }

    // 6. Where it came from (store, sideload, developer mode, known-bad list)
    for (const [score, reason] of installOriginFindings(ext, maliciousIds)) {
      riskScore += score;
      threatReasons.unshift(reason);
    }

    // Classify Level
    let riskLevel: 'unknown' | 'low' | 'high' = 'unknown';
    if (riskScore >= 40) riskLevel = 'high';
    else if (riskScore > 0) riskLevel = 'low';

    return {
      id: ext.id,
      name: ext.name || 'Unnamed Extension',
      version: ext.version || '1.0',
      enabled: !!ext.enabled,
      installType: ext.installType || 'normal',
      icons: ext.icons,
      permissions,
      hostPermissions,
      riskLevel,
      reputation: maliciousIds?.has(ext.id) ? 'known_malicious' as const : 'unknown' as const,
      riskScore,
      threatReasons,
    };
  });

  // Sort highest risk first
  audited.sort((a, b) => b.riskScore - a.riskScore);

  const enabledCount = audited.filter((e) => e.enabled).length;
  const highRiskCount = audited.filter((e) => e.enabled && e.riskLevel === 'high').length;
  const lowRiskCount = audited.filter((e) => e.enabled && e.riskLevel === 'low').length;
  const unknownCount = audited.filter(e => e.enabled && e.reputation === 'unknown').length;

  return {
    totalExtensions: audited.length,
    enabledExtensions: enabledCount,
    highRiskCount,
    lowRiskCount,
    unknownCount,
    inspection: 'available',
    reputationChecked: reputationSource === 'current',
    reputationSource,
    extensions: audited,
  };
}
