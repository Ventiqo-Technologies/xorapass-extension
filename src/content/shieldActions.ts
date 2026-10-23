import browser from 'webextension-polyfill';
import { currentRiskDocumentContext, sameRiskDocument, type PageRiskContext } from '../utils/tabRiskContext';
import type { ShieldActionReason } from '../utils/shieldActions';

// Called only after the actual surface was attached, never from a risk verdict.
export function reportDisplayedShieldAction(action: 'page_blocked' | 'warning_shown', reason: ShieldActionReason = 'risk', context: PageRiskContext = currentRiskDocumentContext()): void {
  if (window !== window.top || !sameRiskDocument(context, currentRiskDocumentContext())) return;
  void browser.runtime.sendMessage({ type: 'SHIELD_ACTION_PERFORMED',
    payload: { action, reason, pageContext: context } }).catch(() => {});
}
