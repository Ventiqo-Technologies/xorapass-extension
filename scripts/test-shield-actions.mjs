// Real navigation/overlay code; inert fulfilled pages only, no live threat sites.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const cache = path.join(os.homedir(), '.npm', '_npx');
const modulePath = process.env.PLAYWRIGHT_MODULE || fs.readdirSync(cache).map(dir => path.join(cache, dir, 'node_modules/playwright/index.mjs')).find(file => fs.existsSync(file));
const { chromium } = await import(pathToFileURL(modulePath).href);
const plugins = [{ name: 'synthetic-browser', setup(builder) {
  builder.onResolve({ filter: /^webextension-polyfill$/ }, () => ({ path: 'browser', namespace: 'fixture' }));
  builder.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({ contents: 'export default window.fixtureBrowser;' }));
} }];
const bundle = async options => (await build({ ...options, bundle: true, write: false, format: 'iife', plugins })).outputFiles[0].text;
const nav = await bundle({ entryPoints: ['src/content/shieldNav.ts'] });
const overlay = await bundle({ stdin: { contents: `export {showPhishingInterstitial,closePhishingInterstitial,showRiskWarning,getActiveRiskWarning,closeRiskWarning} from './src/content/overlay';export {currentRiskDocumentContext} from './src/utils/tabRiskContext';`, resolveDir: process.cwd(), loader: 'ts' }, globalName: 'FixtureOverlay' });
const browser = await chromium.launch({ headless: true });
const screenshots = fs.mkdtempSync(path.join(os.tmpdir(), 'xorapass-shield-actions-'));
async function pageFixture() {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.route('**/*', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Inert fixture</title><input id="password" type="password">' }));
  await page.goto('https://shield-fixture.example.invalid/login');
  await page.evaluate(() => {
    window.fixtureRoots = [];
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (options) { const root = attach.call(this, options); window.fixtureRoots.push(root); return root; };
    window.fixtureMessages = []; window.fixtureListeners = []; window.fixtureStorageListeners = [];
    window.fixtureBrowser = {
      runtime: {
        getURL: () => 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==',
        onMessage: { addListener: listener => window.fixtureListeners.push(listener) },
        sendMessage: async message => {
          window.fixtureMessages.push(message);
          if (message.type === 'SHIELD_NAV_CHECK') return new Promise(resolve => { window.resolveNav = resolve; });
          return { success: true };
        },
      },
      storage: { local: { get: async () => ({ themePreference: 'dark' }) }, onChanged: { addListener: listener => window.fixtureStorageListeners.push(listener) } },
    };
  });
  return page;
}
const block = { action: 'block', layer: 'remote', hooks: true, threatType: 'SOCIAL_ENGINEERING', reasons: ['Synthetic provider finding.'] };
try {
  // Late answers must still block, even after the short typing guard fails open.
  for (const delay of [0, 1600]) {
    const page = await pageFixture();
    await page.addScriptTag({ content: nav });
    await page.waitForFunction(() => !!window.resolveNav);
    assert.equal(await page.evaluate(() => window.__xoraShieldNav.shown), false);
    if (delay) await page.waitForTimeout(delay);
    await page.evaluate(block => window.resolveNav(block), block);
    await page.waitForFunction(() => window.fixtureMessages.some(m => m.type === 'SHIELD_ACTION_PERFORMED'));
    assert.equal(await page.evaluate(() => window.__xoraShieldNav.shown), true);
    const receipt = await page.evaluate(() => window.fixtureMessages.find(m => m.type === 'SHIELD_ACTION_PERFORMED'));
    assert.equal(receipt.payload.action, 'page_blocked');
    assert.equal(receipt.payload.reason, 'phishing');
    assert.equal(await page.evaluate(() => window.fixtureRoots.some(r => r.querySelector('[role="alertdialog"]')?.getBoundingClientRect().height >= innerHeight)), true);
    // Host repair uses the actual owner, not a duplicate host ID from another bundle.
    await page.evaluate(() => document.getElementById('xorapass-overlay-host').remove());
    await page.waitForFunction(() => document.getElementById('xorapass-overlay-host')?.isConnected);
    await page.addScriptTag({ content: overlay });
    assert.equal(await page.evaluate(() => FixtureOverlay.showPhishingInterstitial({ currentDomain: location.hostname, message: 'Duplicate', onLeave() {}, onShown() { throw Error('Suppressed surface must not claim display'); } })), false);
    const context = await page.evaluate(() => FixtureOverlay.currentRiskDocumentContext());
    assert.equal(context.documentToken, receipt.payload.pageContext.documentToken, 'Both bundles identify the same document');
    assert.equal(await page.evaluate(() => window.fixtureMessages.filter(m => m.type === 'SHIELD_ACTION_PERFORMED').length), 1);
    await page.screenshot({ path: path.join(screenshots, `block-delay-${delay}.png`) });
    await page.close();
  }
  const stale = await pageFixture();
  await stale.addScriptTag({ content: nav });
  await stale.waitForFunction(() => !!window.resolveNav);
  await stale.evaluate(block => { history.pushState({}, '', '/other'); window.resolveNav(block); }, block);
  await stale.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await stale.evaluate(() => window.fixtureMessages.filter(m => m.type === 'SHIELD_ACTION_PERFORMED').length), 0);
  assert.equal(await stale.evaluate(() => window.__xoraShieldNav.shown), false);
  await stale.close();

  const warning = await pageFixture();
  await warning.addScriptTag({ content: nav });
  await warning.waitForFunction(() => !!window.resolveNav);
  await warning.evaluate(() => { window.resolveNav({ action: 'allow', layer: 'remote', hooks: true }); });
  await warning.evaluate(() => window.postMessage({ __xoraShield: 'v1', kind: 'wallet_check', summary: 'Synthetic wallet warning' }, '*'));
  await warning.waitForFunction(() => window.fixtureMessages.some(m => m.type === 'SHIELD_ACTION_PERFORMED'));
  assert.equal(await warning.evaluate(() => window.fixtureMessages.find(m => m.type === 'SHIELD_ACTION_PERFORMED').payload.action), 'warning_shown');
  assert.equal(await warning.evaluate(() => window.__xoraShieldNav.shown), false);
  await warning.addScriptTag({ content: overlay });
  assert.equal(await warning.evaluate(() => FixtureOverlay.getActiveRiskWarning()?.source), 'behavior', 'The idle bundle can read a navigation-bundle behavior warning');
  await warning.evaluate(() => FixtureOverlay.closeRiskWarning());
  assert.equal(await warning.evaluate(() => FixtureOverlay.getActiveRiskWarning()?.source), 'behavior', 'A different bundle cannot erase the owner warning');
  await warning.evaluate(() => history.pushState({}, '', '/other'));
  assert.equal(await warning.evaluate(() => FixtureOverlay.getActiveRiskWarning()), null, 'Old-route metadata is not a warning for the new route');
  await warning.close();

  const removed = await pageFixture();
  await removed.addScriptTag({ content: overlay });
  await removed.evaluate(() => {
    window.shownCount = 0;
    FixtureOverlay.showPhishingInterstitial({ currentDomain: location.hostname, message: 'Synthetic', onLeave() {}, onShown() { window.shownCount++; } });
    FixtureOverlay.closePhishingInterstitial();
  });
  await removed.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await removed.evaluate(() => window.shownCount), 0, 'Removed-before-render surfaces do not report display');
  await removed.evaluate(() => {
    document.getElementById('xorapass-overlay-host').remove();
    FixtureOverlay.showPhishingInterstitial({ currentDomain: location.hostname, message: 'Reused host', onLeave() {}, onShown() { window.shownCount++; } });
  });
  await removed.waitForFunction(() => window.shownCount === 1);
  await removed.close();
  console.log(`Shield actions: immediate/late blocks, repeat visits, actual display receipts, cross-bundle suppression, host repair, stale SPA verdicts and warning-only outcomes passed. Screenshots: ${screenshots}`);
} finally { await browser.close(); }
