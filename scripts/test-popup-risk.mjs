// Actual popup + hook, synthetic browser APIs and loopback-only rendering.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
let playwright;
try { playwright = await import('playwright'); } catch {
  const cache = path.join(os.homedir(), '.npm', '_npx');
  const file = fs.readdirSync(cache).map(dir => path.join(cache, dir, 'node_modules/playwright/index.mjs')).find(file => fs.existsSync(file));
  if (!file) throw Error('Install the regression Playwright dependency');
  playwright = await import(pathToFileURL(file).href);
}
const output = fs.mkdtempSync(path.join(os.tmpdir(), 'xorapass-popup-risk-'));
const result = await build({
  stdin: { contents: `import React from 'react';import {createRoot} from 'react-dom/client';import {PopupApp} from './src/popup/PopupApp';import {assessWithCatalog} from './src/utils/domainRisk';
    const host='login.microsoftonline.com';const url='https://'+host+'/common/oauth2/v2.0/authorize';
    const context={url,documentToken:'fixture-document',tabId:7};const safe=assessWithCatalog(host,[],[],url);
    window.fixture.snapshot={pageContext:context,enabled:true,assessment:safe,warning:{source:'domain',severity:'warn',title:'Suspicious Site Detected',message:'The address puts a brand name in the path.',riskLevel:'safe',currentDomain:host}};
    window.fixture.context=context;
    window.fixture.setCase=kind=>{const assessment={...safe};let warning=null;
      if(kind==='provider'||kind==='policy'||kind==='full-block'){assessment.decision='block';assessment.riskScore=kind==='provider'?100:0;assessment.confirmedThreat=kind==='provider';assessment.policyEnforced=kind==='policy';assessment.reasons=['Synthetic mandatory block'];}
      if(kind==='approval'){assessment.decision='require_approval';assessment.reasons=['Synthetic unsafe form destination'];}
      if(kind==='full-block')warning={source:'domain',severity:'block',pageBlocked:true,title:'Site blocked',message:'A full-screen block is displayed.',currentDomain:host};
      if(kind==='ai'||kind==='behavior')warning={source:kind,severity:'warn',riskLevel:'high',title:kind==='ai'?'Possible scam detected':'Risky wallet request detected',message:'Independent synthetic warning',currentDomain:host};
      window.fixture.snapshot=kind==='unavailable'?null:{pageContext:context,enabled:kind!=='disabled',assessment:kind==='loading'?null:assessment,warning};
      window.fixture.messageListeners.forEach(fn=>fn({type:'TAB_RISK_CHANGED'},{tab:{id:7},frameId:0}));};
    createRoot(document.getElementById('root')).render(<PopupApp/>);`, resolveDir: process.cwd(), loader: 'tsx' },
  bundle: true, write: false, jsx: 'automatic', define: { 'import.meta.env': '{}', 'process.env.NODE_ENV': '"production"' },
  plugins: [{name:'synthetic-browser',setup(builder){
    builder.onResolve({filter:/^webextension-polyfill$/},()=>({path:'browser',namespace:'fixture'}));
    builder.onLoad({filter:/.*/,namespace:'fixture'},()=>({contents:'export default window.fixtureBrowser;'}));
  }}],
});
const css = fs.readdirSync('dist/assets').filter(file=>file.endsWith('.css')).map(file=>fs.readFileSync(path.join('dist/assets',file),'utf8')).join('\n');
const html = `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style><div id="root"></div>`;
const server = http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/fixture.js'?'text/javascript':'text/html');res.end(req.url==='/fixture.js'?result.outputFiles[0].text:html);});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser = await playwright.chromium.launch({headless:true});
try {
  for(const theme of ['light','dark']) for(const width of [380,440]) {
    const page=await browser.newPage({viewport:{width,height:650},reducedMotion:'reduce'});
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.route('**/*',route=>new URL(route.request().url()).hostname==='127.0.0.1'?route.continue():route.abort());
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.evaluate(theme=>{
      const messages=[],messageListeners=[];window.fixture={messages,messageListeners};
      const event=()=>({addListener(){},removeListener(){}});
      window.fixtureBrowser={
        runtime:{getURL:()=> 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==',getManifest:()=>({version:'1.2.10'}),
          connect:()=>({disconnect(){},onDisconnect:event()}),onMessage:{addListener:fn=>messageListeners.push(fn),removeListener:fn=>{const i=messageListeners.indexOf(fn);if(i>=0)messageListeners.splice(i,1);}},
          sendMessage:async message=>{messages.push(message);
            if(message.type==='GET_STATUS')return{unlocked:true,email:'synthetic@example.invalid'};
            if(message.type==='SHIELD_GET_STATE')return{active:true,killSwitch:false,blocklistSize:1,entitlement:{planAllows:true,userEnabled:true}};
            if(message.type==='GET_DOMAIN_ALLOWLIST')return{allowlist:[]};
            if(message.type==='GET_SITE_SETTINGS')return{disabled:false};
            if(message.type==='GET_PLAN_FEATURES')return{allowPasteGuard:true};
            if(message.type==='GET_DOMAIN_RISK_HISTORY')return{events:[]};
            if(message.type==='GET_DOMAIN_RISK_REPORTS')return{reports:[]};
            if(message.type==='GET_DOMAIN_RISK_ALLOWLIST_REQUESTS')return{requests:[]};
            if(message.type==='SHIELD_TAB_PRIVACY')return{kinds:[],fingerprint:[]};
            if(message.type==='SHIELD_AUTH_HEADER')return{active:false,features:{},config:{}};
            if(message.type==='SHIELD_GET_PRIVACY_SETTINGS')return{blockTrackers:false,trackerAllowSites:[],downloadGuard:false};
            return{};},
        },
        storage:{session:{get:async()=>({vaultItems:[]})},local:{get:async()=>({themePreference:theme}),set:async()=>{}},onChanged:event()},
        tabs:{get:async()=>({id:7,url:window.fixture.context.url}),query:async()=>[{id:7,url:window.fixture.context.url,title:'Synthetic sign-in'}],onUpdated:event(),onActivated:event(),
          sendMessage:async(_id,message)=>{messages.push(message);if(message.type==='GET_TAB_RISK_CONTEXT')return window.fixture.context;if(message.type==='GET_TAB_RISK_STATE')return structuredClone(window.fixture.snapshot);return{};}},
        permissions:{contains:async()=>false},windows:{update:async()=>{}},
      };
    },theme);
    await page.addScriptTag({url:`http://127.0.0.1:${server.address().port}/fixture.js`});
    await page.getByRole('button',{name:/^Shield$/}).waitFor();
    await page.waitForFunction(()=>window.fixture.messages.some(m=>m.type==='GET_TAB_RISK_STATE'));
    await page.getByRole('button',{name:/^Shield$/}).click();
    await page.waitForFunction(()=>window.fixture.messages.some(m=>m.type==='SCAN_SITE'));
    assert.equal(await page.getByText('Suspicious Site Detected',{exact:true}).count(),0);
    assert(!/Risk:\s*safe/i.test(await page.locator('body').innerText()));
    assert.equal(await page.evaluate(()=>window.fixture.messages.filter(m=>m.type==='CHECK_DOMAIN_RISK').length),0);
    await page.screenshot({path:path.join(output,`safe-shield-${theme}-${width}.png`)});
    for(const [kind,label] of [['provider','Threat detected'],['policy','Threat detected'],['approval','Security warning'],['ai','Possible scam detected'],['behavior','Risky wallet request detected'],['full-block','Site blocked']]){
      await page.evaluate(kind=>window.fixture.setCase(kind),kind);
      await page.getByText(label,{exact:true}).first().waitFor();
      assert(!/Risk:\s*safe/i.test(await page.locator('body').innerText()),kind);
      if(kind==='policy')assert.equal(await page.getByText('Blocked',{exact:true}).count(),0,'A policy verdict alone is not proof of a full-screen block');
    }
    await page.screenshot({path:path.join(output,`block-shield-${theme}-${width}.png`)});
    await page.evaluate(()=>window.fixture.setCase('disabled'));
    await page.getByText('Site blocked',{exact:true}).waitFor({state:'hidden'});
    assert.equal(await page.getByText('Threat detected',{exact:true}).count(),0);
    await page.getByRole('button',{name:'Vault',exact:true}).click();
    await page.evaluate(()=>window.fixture.setCase('unavailable'));
    await page.getByText('Reload tab',{exact:true}).waitFor();
    assert.equal(await page.getByText('Autofill on',{exact:true}).count(),0);
    await page.evaluate(()=>window.fixture.setCase('loading'));
    await page.getByText('Checking Shield',{exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    assert.deepEqual(errors,[]);
    await page.close();
  }
  console.log(`Real popup Shield-click regression, safe/stale warning, mandatory provider/policy blocks, unsafe-form approval, AI/behaviour warnings and disabled Shield passed; light/dark 380/440px screenshots: ${output}`);
} finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
