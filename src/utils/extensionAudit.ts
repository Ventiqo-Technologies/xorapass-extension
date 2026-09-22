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
  riskLevel: 'safe' | 'low' | 'high';
  riskScore: number;
  threatReasons: string[];
}

export interface ExtensionAuditSummary {
  totalExtensions: number;
  enabledExtensions: number;
  highRiskCount: number;
  lowRiskCount: number;
  safeCount: number;
  overallHealthScore: number; // 0-100 (100 is best)
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

async function getAllInstalledItems(customApi?: any): Promise<any[]> {
  const candidates = [
    customApi,
    (globalThis as any).browser?.management,
    (globalThis as any).chrome?.management,
  ].filter(Boolean);

  for (const api of candidates) {
    try {
      if (typeof api.getAll === 'function') {
        let res: any;
        try {
          res = api.getAll();
        } catch {
          /* ignore */
        }
        if (res && typeof res.then === 'function') {
          const items = await res;
          if (Array.isArray(items) && items.length > 0) return items;
        }

        const cbItems: any[] = await new Promise((resolve) => {
          try {
            api.getAll((items: any[]) => resolve(Array.isArray(items) ? items : []));
          } catch {
            resolve([]);
          }
        });
        if (Array.isArray(cbItems) && cbItems.length > 0) return cbItems;
      }
    } catch (err) {
      console.warn('[XoraPass] getAll installed items failed on candidate:', err);
    }
  }

  return [];
}

export async function auditInstalledExtensions(
  maliciousIds?: ReadonlySet<string>,
  managementApi?: any
): Promise<ExtensionAuditSummary> {
  const allItems = await getAllInstalledItems(managementApi);

  if (!allItems || allItems.length === 0) {
    return {
      totalExtensions: 0,
      enabledExtensions: 0,
      highRiskCount: 0,
      lowRiskCount: 0,
      safeCount: 0,
      overallHealthScore: 100,
      extensions: [],
    };
  }

  // Filter for actual extensions (exclude themes or apps) and exclude ourselves
  const myId =
    (globalThis as any).browser?.runtime?.id ||
    (globalThis as any).chrome?.runtime?.id;
  const extensionsList = allItems.filter(
    (item) => (!item.type || item.type === 'extension') && item.id !== myId
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
    let riskLevel: 'safe' | 'low' | 'high' = 'safe';
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
      riskScore,
      threatReasons,
    };
  });

  // Sort highest risk first
  audited.sort((a, b) => b.riskScore - a.riskScore);

  const enabledCount = audited.filter((e) => e.enabled).length;
  const highRiskCount = audited.filter((e) => e.enabled && e.riskLevel === 'high').length;
  const lowRiskCount = audited.filter((e) => e.enabled && e.riskLevel === 'low').length;
  const safeCount = audited.filter((e) => e.enabled && e.riskLevel === 'safe').length;

  // Compute Overall Health (100 minus penalties for active high risks)
  const penalty = highRiskCount * 25 + lowRiskCount * 8;
  const overallHealthScore = Math.max(0, 100 - penalty);

  return {
    totalExtensions: audited.length,
    enabledExtensions: enabledCount,
    highRiskCount,
    lowRiskCount,
    safeCount,
    overallHealthScore,
    extensions: audited,
  };
}
