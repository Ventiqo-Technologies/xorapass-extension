// Real Chromium DOM regression fixtures. No inbox, credentials or network.
// Set PLAYWRIGHT_MODULE to a local playwright/index.mjs if not installed here.
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
  if (!module) throw Error('Install Playwright in a local test environment or set PLAYWRIGHT_MODULE');
  playwright = await import(pathToFileURL(module).href);
}
const bundle = await build({ entryPoints: ['src/content/webmailProviders.ts'], bundle: true, write: false, format: 'iife', globalName: 'OutlookFixture' });
const browser = await playwright.chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-background-networking'] });
try {
  const page = await browser.newPage();
  await page.route('**/*', route => route.abort());
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  const fixtures = [
    ['visible sender before recipients', '<div>Alert Manager &lt;alerts@example.com&gt;</div><div>To: Recipient <span title="recipient@example.net">Recipient</span></div>', '', 'alerts@example.com'],
    ['sender address in title', '<span title="alerts@example.com">Alert Manager</span><div>To: <span title="recipient@example.net">Recipient</span></div>', '', 'alerts@example.com'],
    ['recipient-only header', '<div>Alert Manager</div><div>To: <span title="recipient@example.net">Recipient</span></div>', '', ''],
    ['recipient aria label', '<div>Alert Manager</div><span aria-label="To: Recipient recipient@example.net">Recipient</span>', '', ''],
    ['recipient test id', '<div>Alert Manager</div><span data-testid="recipient" title="recipient@example.net">Recipient</span>', '', ''],
    ['body cannot supply sender', '<div>Alert Manager</div><div>To: recipient@example.net</div>', '<span data-testid="sender" title="forged@example.net">From: forged@example.net</span>', ''],
    ['ambiguous sender', '<div>one@example.com two@example.com</div><div>To: recipient@example.net</div>', '', ''],
    ['explicit From', '<span aria-label="From: Alert Manager alerts@example.com">Alert Manager</span><div>To: recipient@example.net</div>', '', 'alerts@example.com'],
    ['old panel cannot supply sender', '<div data-xorapass-email-insight>From: stale@example.net</div><div>Alert Manager &lt;alerts@example.com&gt;</div><div>To: recipient@example.net</div>', '', 'alerts@example.com'],
    ['cc is not sender', '<div>Alert Manager</div><div>Cc: recipient@example.net</div>', '', ''],
    ['visible recipient test id', '<div>Alert Manager</div><span data-testid="recipient">recipient@example.net</span>', '', ''],
    ['sender marker inside recipient row', '<div>Alert Manager</div><div>To: <span data-testid="sender" title="recipient@example.net">Recipient</span></div>', '', ''],
    ['ambiguous sender attributes', '<span title="one@example.com">One</span><span title="two@example.com">Two</span><div>To: Recipient</div>', '', ''],
    ['previous message body cannot supply sender', '<div id="UniqueMessageBody-old">From: forged@example.net</div><div>Alert Manager</div><div>To: Recipient</div>', '', ''],
  ];
  for (const [name, header, body, expected] of fixtures) {
    const result = await page.evaluate(({ header, body }) => {
      document.body.innerHTML = `<main role="main">${header}<div id="message-body">${body || 'Synthetic message body.'}</div></main>`;
      return globalThis.OutlookFixture.providerHeader('outlook.cloud.microsoft', document.querySelector('main'), document.querySelector('#message-body'));
    }, { header, body });
    assert.equal(result.senderEmail, expected, name);
    assert.equal(result.senderLookupComplete, true, name);
    console.log(`PASS ${name}`);
  }
  console.log(`${fixtures.length} Chromium Outlook header fixtures passed`);
} finally { await browser.close(); }
