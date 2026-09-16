// Extension Security Audit Service
// Scans installed extensions via chrome.management / browser.management
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

export async function auditInstalledExtensions(): Promise<ExtensionAuditSummary> {
  const managementApi = (globalThis as any).chrome?.management || (globalThis as any).browser?.management;

  if (!managementApi?.getAll) {
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

  const allItems: any[] = await new Promise((resolve) => {
    try {
      managementApi.getAll((items: any[]) => resolve(items || []));
    } catch {
      resolve([]);
    }
  });

  // Filter for actual extensions (exclude themes or apps) and exclude ourselves
  const myId = (globalThis as any).chrome?.runtime?.id || (globalThis as any).browser?.runtime?.id;
  const extensionsList = allItems.filter(
    (item) => item.type === 'extension' && item.id !== myId
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
