// Synthetic render fixtures only: no inbox, credentials or network access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

let playwright;
try { playwright = await import(process.env.PLAYWRIGHT_MODULE || 'playwright'); }
catch {
  const cache = path.join(os.homedir(), '.npm', '_npx');
  const module = fs.existsSync(cache) && fs.readdirSync(cache).map(dir => path.join(cache, dir, 'node_modules/playwright/index.mjs')).find(file => fs.existsSync(file));
  if (!module) throw Error('Install Playwright in a test environment or set PLAYWRIGHT_MODULE');
  playwright = await import(pathToFileURL(module).href);
}

const screenshots = fs.mkdtempSync(path.join(os.tmpdir(), 'xorapass-email-panel-results-'));
const bundle = await build({
  entryPoints: ['src/content/emailInsight.ts'], bundle: true, write: false, format: 'iife', globalName: 'EmailPanelFixture',
  plugins: [{ name: 'synthetic-panel', setup(builder) {
    builder.onResolve({ filter: /^webextension-polyfill$/ }, () => ({ path: 'browser', namespace: 'fixture' }));
    builder.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({ contents: 'export default {runtime:{getURL:()=>"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="}};' }));
    builder.onLoad({ filter: /[/\\]emailInsight\.ts$/ }, args => ({ loader: 'ts', contents: fs.readFileSync(args.path, 'utf8') + `
      export function fixture(ai, local) {
        document.body.innerHTML = '';
        const host = document.createElement('div'); document.body.appendChild(host);
        current = {key:'synthetic',host,root:host.attachShadow({mode:'open'})};
        const email = {key:'synthetic',anchor:host,senderName:'Synthetic Service',senderEmail:'notice@example.com',replyTo:null,subject:'Synthetic notification',links:[],attachments:[],bodyText:'Synthetic fixture only.'};
        render(email,local || {danger:false,cautions:0,findings:[],flags:[]},normalizeEmailScanResult(ai,email.senderEmail),false,true);
        return host;
      }` }));
  }}],
});

const fixtures = [
  { name: 'completed-uncertainty', ai: { verdict: 'inconclusive', risk_score: 0, reason: 'weak_indicators' }, level: 'neutral', text: 'not a safe-email verdict', button: 'Analyze again' },
  { name: 'older-discount-warning', ai: { verdict: 'scam', risk_score: 90, red_flags: ['Offer that is too good to be true'] }, level: 'neutral', text: 'couldn’t assess', button: 'Analyze again' },
  { name: 'service-unavailable', ai: { verdict: 'unavailable', reason: 'network_error' }, level: 'neutral', text: 'Analysis couldn’t finish', button: 'Retry AI analysis' },
  { name: 'grounded-warning', ai: { verdict: 'scam', risk_score: 90, red_flags: ['Threat or blackmail'] }, level: 'danger', text: 'possible scam' },
  { name: 'confirmed-threat', ai: { verdict: 'phishing', risk_score: 90, confirmed_threat: true, links: [{ index: 0, host: 'evil.example', reason: 'Known phishing site' }] }, level: 'danger', text: 'Known dangerous link' },
  { name: 'local-warning-survives', ai: { verdict: 'inconclusive', risk_score: 0 }, local: { danger: true, cautions: 0, findings: [{ level: 'danger', reasons: ['Dangerous attachment'] }], flags: ['risky_attachment'] }, level: 'danger', text: 'Dangerous attachment' },
  { name: 'unknown-diagnostic', ai: { verdict: 'unavailable', reason: 'inconsistent_evidence', validation_issue: '<img src=x onerror=alert(1)>' }, level: 'neutral', text: 'Analysis couldn’t finish', button: 'Retry AI analysis' },
  { name: 'no-indicators', ai: { verdict: 'legit', risk_score: 0 }, level: 'ok', text: 'not the sender’s identity' },
  { name: 'quote-failure', ai: { verdict: 'unavailable', reason: 'inconsistent_evidence', validation_issue: 'evidence_quote_not_found' }, level: 'neutral', text: 'Try again', button: 'Retry AI analysis' },
  { name: 'quota', ai: { verdict: 'unavailable', reason: 'quota' }, level: 'neutral', text: 'this month’s AI checks' },
  { name: 'refunded-local-warning', ai: { verdict: 'suspicious', risk_score: 45, reason: 'low_confidence', validation_issue: 'model_low_confidence' }, local: { danger: true, cautions: 0, findings: [{ level: 'danger', reasons: ['Dangerous attachment'] }], flags: ['risky_attachment'] }, level: 'danger', text: 'Dangerous attachment' },
];
const browser = await playwright.chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-background-networking'] });
try {
  const page = await browser.newPage();
  await page.route('**/*', route => route.abort());
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  for (const width of [1280, 375]) {
    await page.setViewportSize({ width, height: 800 });
    for (const fixture of fixtures) {
      const result = await page.evaluate(({ ai, local }) => {
        const root = globalThis.EmailPanelFixture.fixture(ai, local).shadowRoot;
        const details = root.querySelector('.details');
        const toggle = root.querySelector('button[aria-controls]');
        const initialHidden = details.hidden && toggle.getAttribute('aria-expanded') === 'false';
        toggle.click();
        const expanded = !details.hidden && toggle.getAttribute('aria-expanded') === 'true' && details.textContent.includes('Synthetic notification');
        toggle.click();
        return { text: root.querySelector('.bar').textContent + (root.querySelector('.overview')?.textContent || ''), allText: root.textContent,
          initialHidden, expanded, collapsed: details.hidden && toggle.getAttribute('aria-expanded') === 'false', level: root.querySelector('.summary').className,
          images: root.querySelectorAll('img').length, scroll: root.querySelector('.card').scrollWidth, width: root.querySelector('.card').clientWidth,
          buttons: [...root.querySelectorAll('button')].map(b => ({ text: b.textContent, disabled: b.disabled })) };
      }, fixture);
      assert(result.level.includes(fixture.level), fixture.name);
      assert(result.text.includes(fixture.text), fixture.name);
      assert(!result.allText.includes('<img src=x'));
      assert(!result.text.includes('notice@example.com') && !result.text.includes('Synthetic notification'), 'duplicated headers leaked into the primary panel');
      assert(!/diagnostic|evidence_quote_not_found|OpenAI|body_excerpt/.test(result.text), 'technical details leaked into the primary panel');
      assert(result.initialHidden && result.expanded && result.collapsed, 'Details disclosure did not work');
      assert.equal(result.images, 1);
      assert(result.scroll <= result.width + 1, `${fixture.name} overflow at ${width}`);
      if (fixture.button) assert(result.buttons.some(b => b.text === fixture.button && !b.disabled), fixture.name);
      if (['completed-uncertainty', 'confirmed-threat', 'quote-failure', 'no-indicators'].includes(fixture.name)) {
        await page.screenshot({ path: path.join(screenshots, `${fixture.name}-${width}.png`) });
      }
      console.log(`PASS ${fixture.name} width=${width}`);
    }
  }
  console.log(`${fixtures.length * 2} Chromium email-result fixtures passed; screenshots: ${screenshots}`);
} finally { await browser.close(); }
