import { describe, expect, it, vi } from 'vitest';
import { RiskApprovals, readApprovalContext, sameApprovalContext } from './riskApproval';

const context = { url: 'https://example.com/login', documentToken: 'document-a', formScope: 'form-a:https://id.example/submit' };
describe('credential approvals are document and form scoped', () => {
  it('rejects a stale dialog grant and missing or malformed approval context', () => {
    expect(sameApprovalContext(context, context)).toBe(true);
    for (const claimed of [null, {}, { ...context, documentToken: 'old-dialog' }, { ...context, url: 'https://example.com/previous' }, { ...context, formScope: 'old-form' }]) {
      expect(sameApprovalContext(context, claimed)).toBe(false);
    }
  });
  it('accepts the same document and form until expiry', () => {
    let now = 0; const approvals = new RiskApprovals(() => now, 100);
    approvals.grant(1, context); expect(approvals.has(1, context)).toBe(true);
    now = 100; expect(approvals.has(1, context)).toBe(false);
  });
  it.each([
    { ...context, url: 'https://example.com/other' },
    { ...context, url: 'https://example.com:444/login' },
    { ...context, url: 'http://example.com/login' },
    { ...context, url: 'https://example.com/login#route' },
    { ...context, documentToken: 'reloaded-document' },
    { ...context, formScope: 'form-a:https://evil.example/submit' },
    { ...context, formScope: 'replacement-form:https://id.example/submit' },
  ])('revokes when context changes: %j', changed => {
    const approvals = new RiskApprovals(); approvals.grant(1, context);
    expect(approvals.has(1, changed)).toBe(false);
    expect(approvals.has(1, context)).toBe(false);
  });
  it('isolates tabs and clears on navigation, tab closure and lock', () => {
    const approvals = new RiskApprovals(); approvals.grant(1, context);
    expect(approvals.has(2, context)).toBe(false);
    approvals.revoke(1); expect(approvals.has(1, context)).toBe(false);
    approvals.grant(1, context); approvals.clear(); expect(approvals.has(1, context)).toBe(false);
  });
  it('reads only the top frame and checks the browser tab URL', async () => {
    const tabs = { sendMessage: vi.fn(async () => context), get: vi.fn(async () => ({ url: context.url })) };
    expect(await readApprovalContext(tabs, 1, context.url)).toEqual(context);
    expect(tabs.sendMessage).toHaveBeenCalledWith(1, { type: 'GET_CREDENTIAL_APPROVAL_CONTEXT' }, { frameId: 0 });
    tabs.get.mockResolvedValue({ url: 'https://example.com/changed' });
    expect(await readApprovalContext(tabs, 1, context.url)).toBeNull();
  });
  it('fails closed when the content context is missing or malformed', async () => {
    for (const value of [null, {}, { ...context, formScope: '' }, { ...context, documentToken: '' }]) {
      const tabs = { sendMessage: async () => value, get: async () => ({ url: context.url }) };
      expect(await readApprovalContext(tabs, 1, context.url)).toBeNull();
    }
  });
});
