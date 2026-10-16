import { useEffect, useState } from 'react';
import browser from 'webextension-polyfill';
import { readTabRiskContext, isCurrentRiskContext, sameRiskDocument, validTabRiskWarning, type TabRiskContext, type TabRiskWarning } from '../utils/tabRiskContext';

interface ActiveRiskTab { id: number; url: string; title: string; favIconUrl: string; context: TabRiskContext | null }

// Every asynchronous response belongs to one active tab and one document. A new
// navigation invalidates earlier requests even if its hostname has not changed.
export function useActiveTabRisk() {
  const [tab, setTab] = useState<ActiveRiskTab | null>(null);
  const [warning, setWarning] = useState<TabRiskWarning | null>(null);
  useEffect(() => {
    let sequence = 0;
    let current: ActiveRiskTab | null = null;
    let closed = false;
    const refresh = async () => {
      const request = ++sequence;
      try {
        const [active] = await browser.tabs.query({ active: true, currentWindow: true });
        if (closed || request !== sequence) return;
        if (active?.id === undefined || !active.url) { current = null; setTab(null); setWarning(null); return; }
        if (!current || current.id !== active.id || current.url !== active.url) {
          current = null; setTab(null); setWarning(null);
        }
        const context = await readTabRiskContext(browser.tabs, active.id, active.url);
        if (closed || request !== sequence) return;
        const next = { id: active.id, url: active.url, title: active.title || '', favIconUrl: active.favIconUrl || '', context };
        if (!current || current.id !== next.id || current.url !== next.url || !sameRiskDocument(current.context, context)) {
          current = next; setTab(next); setWarning(null);
        }
        if (!context) return;
        const response = await browser.tabs.sendMessage(active.id, { type: 'GET_ACTIVE_TAB_WARNING', pageContext: context }, { frameId: 0 });
        if (closed || request !== sequence || !await isCurrentRiskContext(browser.tabs, context)) return;
        if (closed || request !== sequence) return;
        setWarning(validTabRiskWarning(response, context) ? response : null);
      } catch { if (!closed && request === sequence) setWarning(null); }
    };
    const updated = (id: number, change: browser.Tabs.OnUpdatedChangeInfoType) => {
      if (id === current?.id && (change.url || change.status === 'loading')) {
        ++sequence; current = null; setTab(null); setWarning(null);
      }
      if (change.url || change.status === 'complete') void refresh();
    };
    const activated = () => { ++sequence; current = null; setTab(null); setWarning(null); void refresh(); };
    const riskChanged = (message: unknown, sender: browser.Runtime.MessageSender) => {
      if (message && typeof message === 'object' && (message as {type?: string}).type === 'TAB_RISK_CHANGED' &&
        sender.tab?.id === current?.id && sender.frameId === 0) void refresh();
    };
    browser.tabs.onActivated.addListener(activated);
    browser.tabs.onUpdated.addListener(updated);
    browser.runtime.onMessage.addListener(riskChanged);
    void refresh();
    return () => {
      closed = true; ++sequence;
      browser.tabs.onActivated.removeListener(activated);
      browser.tabs.onUpdated.removeListener(updated);
      browser.runtime.onMessage.removeListener(riskChanged);
    };
  }, []);
  return { tab, warning, clearWarning: () => setWarning(null) };
}
