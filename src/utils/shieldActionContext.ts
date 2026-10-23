import { readTabRiskContext, sameRiskDocument, validPageRiskContext, type RiskTabs } from './tabRiskContext';
import type { ShieldActionReason } from './shieldActions';

export async function displayedShieldAction(tabs: RiskTabs, sender: { url?: string; frameId?: number; tab?: { id?: number } }, payload: any) {
  const url = sender.url || '', tabId = sender.tab?.id;
  if (sender.frameId !== 0 || tabId == null || !validPageRiskContext(payload?.pageContext, url)) return null;
  if (!['page_blocked','warning_shown'].includes(payload.action) || !['phishing','malware','policy','unsafe_form','risk'].includes(payload.reason)) return null;
  if (!sameRiskDocument(payload.pageContext, await readTabRiskContext(tabs, tabId, url))) return null;
  return { url, action: payload.action as 'page_blocked' | 'warning_shown', reason: payload.reason as ShieldActionReason };
}
