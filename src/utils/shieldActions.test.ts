import { describe, expect, it, vi } from 'vitest';
import { reportShieldAction } from './shieldActions';
import { displayedShieldAction } from './shieldActionContext';

describe('Shield action reporting is separate from risk decisions', () => {
  it('sends only hostname/action/reason and freezes the credential across retries', async () => {
    const credential = vi.fn().mockResolvedValueOnce('first-account-token').mockResolvedValue('other-account-token');
    const fetcher = vi.fn().mockResolvedValueOnce({ status: 503, ok: false }).mockResolvedValue({ status: 200, ok: true });
    expect(await reportShieldAction('https://accounts.google.com/login?token=private#secret', 'page_blocked', 'phishing', credential, fetcher, async () => {})).toBe(true);
    expect(credential).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, request] of fetcher.mock.calls) {
      expect(request.headers.Authorization).toBe('Bearer first-account-token');
      expect(JSON.parse(request.body)).toEqual({ hostname: 'accounts.google.com', action: 'page_blocked', reason: 'phishing' });
      expect(request.body).not.toMatch(/private|secret|login|user_id/);
    }
  });
  it('works with locked Shield auth and never retries forbidden/revoked/unsupported writes', async () => {
    for (const status of [400,401,403,404]) {
      const fetcher=vi.fn().mockResolvedValue({status,ok:false});
      expect(await reportShieldAction('https://example.com', 'warning_shown', 'risk', async()=> 'Shield device-token',fetcher,async()=>{})).toBe(false);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.calls[0][1].headers.Authorization).toBe('Shield device-token');
    }
  });
  it('bounds network retries and never reports private hosts or anonymous activity', async () => {
    const fetcher=vi.fn().mockRejectedValue(new Error('offline'));
    expect(await reportShieldAction('https://example.com', 'warning_shown','risk',async()=> 'synthetic',fetcher,async()=>{})).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(3);fetcher.mockClear();
    expect(await reportShieldAction('http://127.0.0.1', 'page_blocked','risk',async()=> 'synthetic',fetcher)).toBe(false);
    expect(await reportShieldAction('https://example.com', 'page_blocked','risk',async()=> '',fetcher)).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe('display receipts belong to the actual top-level document', () => {
  const context={url:'https://example.com/login',documentToken:'current-document'};
  function fixture() {
    return {get:vi.fn(async()=>({url:context.url})),sendMessage:vi.fn(async()=>context)};
  }
  const sender={url:context.url,frameId:0,tab:{id:7}};
  const payload={action:'page_blocked',reason:'phishing',pageContext:context,hostname:'forged.example.com'};
  it('derives URL from browser sender metadata, never a supplied hostname',async()=>{
    expect(await displayedShieldAction(fixture(),sender,payload)).toEqual({url:context.url,action:'page_blocked',reason:'phishing'});
  });
  it('rejects child frames, extension pages, stale reloads, SPA races and unknown actions',async()=>{
    expect(await displayedShieldAction(fixture(),{...sender,frameId:1},payload)).toBeNull();
    expect(await displayedShieldAction(fixture(),{url:'chrome-extension://own/popup.html'},payload)).toBeNull();
    expect(await displayedShieldAction(fixture(),sender,{...payload,pageContext:{...context,documentToken:'old-document'}})).toBeNull();
    const changed=fixture();changed.get.mockResolvedValue({url:'https://example.com/other'});
    expect(await displayedShieldAction(changed,sender,payload)).toBeNull();
    expect(await displayedShieldAction(fixture(),sender,{...payload,action:'autofill_blocked'})).toBeNull();
    expect(await displayedShieldAction(fixture(),sender,{...payload,reason:'private arbitrary data'})).toBeNull();
  });
});
