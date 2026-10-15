// A tab's URL alone cannot distinguish a reload or a same-URL document replacement.
// The token is generated in the isolated content-script world, never by the page.
export interface PageRiskContext { url: string; documentToken: string }
export interface TabRiskContext extends PageRiskContext { tabId: number }
export interface TabRiskWarning {
  severity: string; title: string; message: string; currentDomain: string;
  expectedDomain?: string | null; riskLevel?: string; allowlistRequestStatus?: string | null;
}
export interface RiskTabs {
  get(id: number): Promise<{ id?: number; url?: string }>;
  sendMessage(id: number, message: unknown, options: { frameId: number }): Promise<unknown>;
}

// getRandomValues also works on HTTP pages, where randomUUID is unavailable.
export function createRiskDocumentToken(fill: (bytes: Uint8Array) => Uint8Array = bytes => crypto.getRandomValues(bytes)): string {
  return Array.from(fill(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
}

export function riskPageUrl(value: string): string {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return '';
    return url.href;
  } catch { return ''; }
}

export function sameRiskDocument(left: PageRiskContext | null | undefined, right: PageRiskContext | null | undefined): boolean {
  return !!left && !!right && !!left.documentToken && left.documentToken === right.documentToken &&
    !!riskPageUrl(left.url) && riskPageUrl(left.url) === riskPageUrl(right.url);
}

export function validPageRiskContext(value: unknown, url: string): value is PageRiskContext {
  if (!value || typeof value !== 'object') return false;
  const context = value as PageRiskContext;
  return typeof context.documentToken === 'string' && context.documentToken.length > 0 &&
    typeof context.url === 'string' && !!riskPageUrl(url) && riskPageUrl(context.url) === riskPageUrl(url);
}

export async function readTabRiskContext(tabs: RiskTabs, tabId: number, url: string): Promise<TabRiskContext | null> {
  try {
    if (!riskPageUrl(url)) return null;
    const context = await tabs.sendMessage(tabId, { type: 'GET_TAB_RISK_CONTEXT' }, { frameId: 0 });
    const tab = await tabs.get(tabId);
    if (riskPageUrl(tab.url || '') !== riskPageUrl(url) || !validPageRiskContext(context, url)) return null;
    return { ...context, tabId };
  } catch { return null; }
}

export async function isCurrentRiskContext(tabs: RiskTabs, context: TabRiskContext): Promise<boolean> {
  return sameRiskDocument(context, await readTabRiskContext(tabs, context.tabId, context.url));
}

export function acceptsTabRiskUpdate(isTopFrame: boolean, context: PageRiskContext, message: unknown): boolean {
  if (!isTopFrame || !message || typeof message !== 'object') return false;
  const update = message as { pageContext?: PageRiskContext; risk?: { pageHostname?: string }; payload?: { risk?: { pageHostname?: string } } };
  if (!sameRiskDocument(context, update.pageContext)) return false;
  const risk = update.payload?.risk || update.risk;
  return !!risk && typeof risk === 'object' && (!risk.pageHostname || risk.pageHostname === new URL(context.url).hostname);
}

export async function publishTabRisk(tabs: RiskTabs, context: TabRiskContext | null, risk: unknown): Promise<boolean> {
  if (!context || !acceptsTabRiskUpdate(true, context, { pageContext: context, risk }) || !await isCurrentRiskContext(tabs, context)) return false;
  try {
    await tabs.sendMessage(context.tabId, { type: 'TAB_RISK_UPDATE', pageContext: context, risk }, { frameId: 0 });
    return true;
  } catch { return false; }
}

export function validTabRiskWarning(value: unknown, context: PageRiskContext): value is TabRiskWarning {
  if (!value || typeof value !== 'object') return false;
  const warning = value as TabRiskWarning;
  return typeof warning.title === 'string' && !!warning.title && typeof warning.message === 'string' &&
    warning.currentDomain === new URL(context.url).hostname && ['warn', 'block', 'require_approval'].includes(warning.severity);
}

export function autofillRiskIndicator(disabled: boolean, ...decisions: Array<string | undefined>) {
  const decision = ['block','require_approval','warn'].find(value => decisions.includes(value));
  if (disabled) return { label: 'Autofill off', tone: 'off', detail: 'Autofill is disabled in your site preferences.' };
  if (decision === 'block') return { label: 'Autofill blocked', tone: 'block', detail: 'Shield blocks autofill on this page. Your site preference is enabled.' };
  if (decision === 'require_approval') return { label: 'Autofill guarded', tone: 'warn', detail: 'Shield requires an approval check before filling. Your site preference is enabled.' };
  if (decision === 'warn') return { label: 'Autofill caution', tone: 'warn', detail: 'Shield has flagged this page. Review the warning before filling.' };
  return { label: 'Autofill on', tone: 'on', detail: 'Your site preference is enabled. Shield checks each fill before releasing a password.' };
}
