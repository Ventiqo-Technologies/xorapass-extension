import { describe, expect, it, vi } from 'vitest';
import { acceptsTabRiskUpdate, autofillRiskIndicator, createRiskDocumentToken, isCurrentRiskContext, publishTabRisk, readTabRiskContext, riskPageUrl, sameRiskDocument, validTabRiskWarning, type PageRiskContext } from './tabRiskContext';

const page = {url:'https://shop.example.org/login?step=1',documentToken:'document-a'};
const context = {...page,tabId:7};
const risk = {pageHostname:'shop.example.org',decision:'warn',riskScore:45,riskLevel:'medium',safeWarningMessage:'Shop caution'};
function fixture() {
  let current: PageRiskContext = {...page};
  let url = page.url;
  const sendMessage = vi.fn(async (_id:number,message:unknown,_options:{frameId:number}):Promise<unknown> => {
    return (message as {type:string}).type === 'GET_TAB_RISK_CONTEXT' ? {...current} : {received:true};
  });
  const get=vi.fn(async()=>({id:7,url}));
  return {tabs:{get,sendMessage},navigate:(next:PageRiskContext)=>{current=next;url=next.url;},setTabUrl:(next:string)=>{url=next;}};
}

describe('main-page risk warning routing',()=>{
  it('creates a 128-bit document token without requiring secure-context randomUUID',()=>{
    const fill=vi.fn((bytes:Uint8Array)=>bytes.fill(7));
    expect(createRiskDocumentToken(fill)).toBe('07'.repeat(16));
    expect(fill).toHaveBeenCalledOnce();
  });
  it('reads only frame zero and binds the response to a browser tab URL',async()=>{
    const f=fixture();
    expect(await readTabRiskContext(f.tabs,7,page.url)).toEqual(context);
    expect(f.tabs.sendMessage).toHaveBeenCalledWith(7,{type:'GET_TAB_RISK_CONTEXT'},{frameId:0});
  });
  it.each(['https://www.google.com/recaptcha/','https://shop.example.org/checkout','https://shop.example.org/login?step=2','https://shop.example.org/login?step=1#new-route'])('rejects a context for another URL: %s',async url=>{
    const f=fixture();f.navigate({...page,url});
    expect(await readTabRiskContext(f.tabs,7,page.url)).toBeNull();
  });
  it('rejects a reply after the browser tab has navigated during context lookup',async()=>{
    const f=fixture();f.setTabUrl('https://other.example.org/');
    expect(await readTabRiskContext(f.tabs,7,page.url)).toBeNull();
  });
  it('invalidates an old assessment after reloading the identical URL',async()=>{
    const f=fixture();f.navigate({...page,documentToken:'document-b'});
    expect(await isCurrentRiskContext(f.tabs,context)).toBe(false);
    expect(await publishTabRisk(f.tabs,context,risk)).toBe(false);
    expect(f.tabs.sendMessage.mock.calls.every(call=>(call[1] as {type:string}).type!=='TAB_RISK_UPDATE')).toBe(true);
  });
  it('publishes a current assessment only to its original tab and main frame',async()=>{
    const f=fixture();
    expect(await publishTabRisk(f.tabs,context,risk)).toBe(true);
    expect(f.tabs.sendMessage).toHaveBeenLastCalledWith(7,{type:'TAB_RISK_UPDATE',pageContext:context,risk},{frameId:0});
  });
  it('rejects another hostname even with a matching document envelope',async()=>{
    const f=fixture();
    expect(await publishTabRisk(f.tabs,context,{...risk,pageHostname:'www.google.com'})).toBe(false);
    expect(f.tabs.sendMessage).not.toHaveBeenCalled();
  });
  it('the receiving document rejects a navigation between validation and delivery',async()=>{
    expect(acceptsTabRiskUpdate(true,{...page,documentToken:'document-b'},{pageContext:context,risk})).toBe(false);
    expect(acceptsTabRiskUpdate(true,{...page,url:'https://shop.example.org/checkout'},{pageContext:context,risk})).toBe(false);
  });
  it('embedded frames cannot accept top-page risk, even with a copied envelope',()=>{
    expect(acceptsTabRiskUpdate(false,page,{pageContext:context,risk})).toBe(false);
    expect(acceptsTabRiskUpdate(false,{url:'https://www.google.com/recaptcha/',documentToken:'google-frame'},{pageContext:context,risk})).toBe(false);
  });
  it('rejects legacy broadcasts and malformed envelopes',()=>{
    for(const message of [null,{}, {risk}, {pageContext:page}, {pageContext:page,risk:'malformed'}]) expect(acceptsTabRiskUpdate(true,page,message)).toBe(false);
  });
  it('accepts a safe verdict to clear a previous warning for this document',()=>{
    expect(acceptsTabRiskUpdate(true,page,{pageContext:page,risk:{...risk,decision:'allow'}})).toBe(true);
  });
  it('rejects raw scanner/API responses instead of promoting them to page verdicts',()=>{
    expect(acceptsTabRiskUpdate(true,page,{pageContext:page,risk:{decision:'warn',risk_score:15,risk_level:'safe',reason_codes:['BRAND_IN_URL_PATH']}})).toBe(false);
    expect(acceptsTabRiskUpdate(true,page,{pageContext:page,risk:{...risk,riskScore:NaN}})).toBe(false);
  });
  it('does not return a context when the content script is unavailable',async()=>{
    const f=fixture();f.tabs.sendMessage.mockRejectedValueOnce(new Error('No receiver'));
    expect(await readTabRiskContext(f.tabs,7,page.url)).toBeNull();
  });
  it('does not reuse a blank, internal or invalid URL',()=>{
    for(const url of ['','about:blank','chrome://settings','not a URL']) expect(riskPageUrl(url)).toBe('');
    expect(sameRiskDocument({...page,documentToken:''},page)).toBe(false);
  });
  it('rejects the Google-frame/shop-message combination from the reported screenshot',()=>{
    const warning={severity:'warn',title:'Suspicious Site Detected',message:'Caution: shop.example.org has offscreen fields.',currentDomain:'www.google.com'};
    expect(validTabRiskWarning(warning,page)).toBe(false);
    expect(validTabRiskWarning({...warning,currentDomain:'shop.example.org'},page)).toBe(true);
  });
});

describe('autofill indicator reflects risk separately from the site preference',()=>{
  it.each([
    [false,'allow','Autofill on'],[false,'warn','Autofill caution'],
    [false,'require_approval','Autofill guarded'],[false,'block','Autofill blocked'],
    [true,'block','Autofill off'],[true,'warn','Autofill off'],
  ])('disabled=%s decision=%s displays %s',(disabled,decision,label)=>{
    expect(autofillRiskIndicator(disabled as boolean,decision as string).label).toBe(label);
  });
  it('a lower-severity page warning cannot hide a blocking assessment',()=>{
    expect(autofillRiskIndicator(false,'warn','block').label).toBe('Autofill blocked');
  });
});
