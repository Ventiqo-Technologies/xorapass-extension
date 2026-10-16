import { sameRiskDocument, validPageRiskContext, type PageRiskContext, type RiskTabs } from './tabRiskContext';

export interface ApprovalContext extends PageRiskContext { formScope: string }

export function sameApprovalContext(a: ApprovalContext, b: unknown): boolean {
  if (!b || typeof b !== 'object') return false;
  const claimed = b as ApprovalContext;
  return validPageRiskContext(claimed, a.url) && sameRiskDocument(a, claimed) && a.formScope === claimed.formScope;
}

export class RiskApprovals {
  private entries = new Map<number, { context: ApprovalContext; expires: number }>();
  constructor(private readonly now = () => Date.now(), readonly ttl = 5 * 60 * 1000) {}
  grant(tabId: number, context: ApprovalContext): void {
    this.entries.set(tabId, { context: { ...context }, expires: this.now() + this.ttl });
  }
  has(tabId: number, context: ApprovalContext): boolean {
    const entry = this.entries.get(tabId);
    if (!entry || this.now() >= entry.expires || !sameRiskDocument(entry.context, context) || entry.context.formScope !== context.formScope) {
      this.entries.delete(tabId);
      return false;
    }
    return true;
  }
  revoke(tabId: number): void { this.entries.delete(tabId); }
  clear(): void { this.entries.clear(); }
}

export async function readApprovalContext(tabs: RiskTabs, tabId: number, url: string): Promise<ApprovalContext | null> {
  try {
    const value = await tabs.sendMessage(tabId, { type: 'GET_CREDENTIAL_APPROVAL_CONTEXT' }, { frameId: 0 });
    const tab = await tabs.get(tabId);
    const context = value as ApprovalContext | null;
    if (tab.url !== url || !validPageRiskContext(value, url) || !context ||
        typeof context.formScope !== 'string' || !context.formScope || context.formScope.length > 64000) return null;
    return { url: context.url, documentToken: context.documentToken, formScope: context.formScope };
  } catch { return null; }
}
