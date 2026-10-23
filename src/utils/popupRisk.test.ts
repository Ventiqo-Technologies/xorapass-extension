import { describe, expect, it, vi } from 'vitest';
import { assessWithCatalog } from './domainRisk';
import { popupThreat, readPopupRiskState, EMPTY_POPUP_RISK } from './popupRisk';
import type { TabRiskWarning } from './tabRiskContext';

const host = 'login.microsoftonline.com';
const context = {url:`https://${host}/common/oauth2/v2.0/authorize`,documentToken:'current',tabId:7};
const safe = assessWithCatalog(host, [], [], context.url);
const retained: TabRiskWarning = {source:'domain',severity:'warn',riskLevel:'safe',title:'Suspicious Site Detected',
  message:'The address puts a brand name in the path.',currentDomain:host};

describe('popup follows the current final verdict, not retained explanation text', () => {
  it('reproduces Microsoft safe verdict plus old warning without showing a false banner', () => {
    expect(safe.decision).toBe('allow');
    expect(popupThreat({...safe,reasons:[retained.message],safeWarningMessage:retained.message},retained,host)).toBeNull();
  });
  it.each(['accounts.google.com','aws.amazon.com','login.microsoftonline.com'])('does not turn benign %s reason text into a warning', hostname => {
    const risk = assessWithCatalog(hostname, [], [], `https://${hostname}/`);
    expect(popupThreat({...risk,riskScore:25,reasons:['Not flagged as phishing.']},null,hostname)).toBeNull();
  });
  it.each(['block','require_approval','warn'] as const)('preserves final %s even on a trusted/allowlisted site with zero numeric score', decision => {
    const warning = popupThreat({...safe,isAllowlisted:true,policyEnforced:true,decision},retained,host);
    expect(warning?.severity).toBe(decision);
    expect(warning?.riskLevel).not.toBe('safe');
  });
  it('a lower warning cannot hide a mandatory provider block', () => {
    expect(popupThreat({...safe,decision:'block',confirmedThreat:true}, {...retained,source:'ai'},host)?.severity).toBe('block');
  });
  it.each(['ai','behavior'] as const)('keeps independent %s warnings despite domain allow', source => {
    expect(popupThreat(safe,{...retained,source,riskLevel:'high'},host)?.source).toBe(source);
  });
  it('keeps a rendered full-screen block separate from the current domain score', () => {
    const warning = popupThreat(safe,{...retained,pageBlocked:true,severity:'block'},host);
    expect(warning?.pageBlocked).toBe(true);
    expect(warning?.riskLevel).toBe('high');
  });
  it('does not reuse warnings from another hostname or when Shield is disabled', () => {
    expect(popupThreat(safe,{...retained,source:'ai',currentDomain:'other.example.com'},host)).toBeNull();
    expect(popupThreat({...safe,decision:'block'},retained,host,true)).toBeNull();
    expect(popupThreat(null,retained,host)).toBeNull();
  });
});

describe('popup snapshot belongs to the same top-frame document', () => {
  function fixture() {
    const response = {pageContext:context,enabled:true,assessment:safe,warning:retained};
    const tabs = {get:vi.fn(async()=>({url:context.url})),sendMessage:vi.fn(async(_id:number,message:any)=>message.type==='GET_TAB_RISK_CONTEXT'?context:response)};
    return {response,tabs};
  }
  it('reads the final page snapshot without an extra network/domain-risk check', async () => {
    const {tabs} = fixture();
    expect(await readPopupRiskState(tabs,context)).toEqual({available:true,enabled:true,assessment:safe,warning:retained});
    expect(tabs.sendMessage).toHaveBeenCalledWith(7,{type:'GET_TAB_RISK_STATE',pageContext:context},{frameId:0});
    expect(tabs.sendMessage.mock.calls.every(([,message])=>!['CHECK_DOMAIN_RISK','SCAN_SITE'].includes(message.type))).toBe(true);
  });
  it('drops a response after navigation, reload, mismatched hostname or malformed decision', async () => {
    for (const mode of ['navigation','reload','hostname','decision','missing context']) {
      const {tabs,response} = fixture();
      if(mode==='navigation') tabs.get.mockResolvedValue({url:'https://example.org/'});
      if(mode==='reload') response.pageContext={...context,documentToken:'old'};
      if(mode==='hostname') response.assessment={...safe,pageHostname:'example.org'};
      if(mode==='decision') response.assessment={...safe,decision:'unrecognized' as any};
      if(mode==='missing context') response.pageContext=null as any;
      expect(await readPopupRiskState(tabs,context)).toEqual(EMPTY_POPUP_RISK);
    }
  });
  it('does not present missing/old content scripts as a fresh safe result', async () => {
    const {tabs} = fixture(); tabs.sendMessage.mockRejectedValue(new Error('No receiver'));
    expect(await readPopupRiskState(tabs,context)).toEqual(EMPTY_POPUP_RISK);
  });
  it('disabled Shield suppresses both assessments and retained warning metadata', async () => {
    const {tabs,response} = fixture(); response.enabled=false;
    expect(await readPopupRiskState(tabs,context)).toEqual({available:true,enabled:false,assessment:null,warning:null});
  });
});
