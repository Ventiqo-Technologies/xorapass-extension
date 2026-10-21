// Real Chromium DOM regression fixtures for webmail reading pane mutations and SPA isolation.
// Ensures that Outlook/Gmail reading pane mutations trigger automatic scans without popup focus,
// while WhatsApp Web and other generic SPAs remain strictly protected against CPU-heavy scan storms.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-background-networking'],
});

try {
  const page = await browser.newPage();
  await page.route('**/*', (route) => route.abort());

  // Define the exact filter function and observer harness matching src/content/content.ts
  await page.evaluate(() => {
    window.createMutationFilter = (isWebmail) => {
      const relevant = isWebmail
        ? 'input, textarea, select, form, iframe, [role="region"], [role="main"], [role="document"], [aria-label*="Message" i], div[id^="UniqueMessageBody"], [data-testid*="message" i], [data-testid="SenderDetails"], .allowTextSelection'
        : 'input, textarea, select, form, iframe';

      return (record) => {
        if (record.type === 'attributes') {
          return (
            record.target instanceof HTMLInputElement ||
            record.target instanceof HTMLTextAreaElement ||
            record.target instanceof HTMLSelectElement ||
            record.target instanceof HTMLFormElement ||
            record.target instanceof HTMLIFrameElement
          );
        }

        if (
          record.target instanceof Element &&
          (record.target.matches(relevant) || (isWebmail && Boolean(record.target.closest(relevant))))
        ) {
          return true;
        }

        return Array.from(record.addedNodes).some(
          (node) => node instanceof Element && (node.matches(relevant) || Boolean(node.querySelector(relevant)))
        );
      };
    };
  });

  console.log('\n--- Running Webmail & SPA Mutation Regression Tests ---');

  // Suite 1: Webmail Reading Pane Mutations (isWebmail = true)
  const webmailCases = [
    { name: 'role="region" reading container', html: '<div role="region" aria-label="Reading Pane"><h3>Invoice</h3></div>', expected: true },
    { name: 'role="main" container', html: '<div role="main"><div>Email Content</div></div>', expected: true },
    { name: 'role="document" container', html: '<div role="document"><div>Message Body</div></div>', expected: true },
    { name: 'aria-label containing "Message"', html: '<div aria-label="Reading Message">Content</div>', expected: true },
    { name: 'div with id UniqueMessageBody', html: '<div id="UniqueMessageBody_48102">Dear Customer...</div>', expected: true },
    { name: 'data-testid containing message', html: '<div data-testid="messageContent">Email text</div>', expected: true },
    { name: 'data-testid="SenderDetails"', html: '<span data-testid="SenderDetails">Security Team &lt;sec@corp.com&gt;</span>', expected: true },
    { name: 'class allowTextSelection', html: '<div class="allowTextSelection">Selectable email text</div>', expected: true },
    { name: 'nested reading element inside generic wrapper', html: '<div class="outer"><section role="region"><span>Text</span></section></div>', expected: true },
    { name: 'standard input inside webmail', html: '<input type="text" name="quickReply" />', expected: true },
    { name: 'standard form inside webmail', html: '<form><textarea></textarea></form>', expected: true },
    { name: 'generic unrelated div on webmail', html: '<div class="ms-Button-icon"><i class="icon"></i></div>', expected: false },
    { name: 'generic span text on webmail', html: '<span class="status-indicator">Connected</span>', expected: false },
  ];

  for (const tc of webmailCases) {
    const result = await page.evaluate((tc) => {
      document.body.innerHTML = '<div id="app-root"></div>';
      const root = document.getElementById('app-root');
      const filter = window.createMutationFilter(true);

      let detected = false;
      const observer = new MutationObserver((records) => {
        detected = records.some(filter);
      });
      observer.observe(root, { childList: true, subtree: true, attributes: true });

      const temp = document.createElement('div');
      temp.innerHTML = tc.html;
      while (temp.firstChild) {
        root.appendChild(temp.firstChild);
      }

      const records = observer.takeRecords();
      observer.disconnect();
      return records.some(filter);
    }, tc);

    assert.equal(result, tc.expected, `[Webmail] Expected ${tc.expected} for ${tc.name}`);
    console.log(`  ✓ [Webmail] ${tc.name} => ${result ? 'TRIGGERED SCAN' : 'IGNORED'}`);
  }

  // Suite 2: Child mutations inside existing webmail reading container
  const childMutationResult = await page.evaluate(() => {
    document.body.innerHTML = '<div id="root"><div role="region" id="reading-pane"><p id="content">Initial</p></div></div>';
    const pane = document.getElementById('reading-pane');
    const filter = window.createMutationFilter(true);

    const observer = new MutationObserver(() => {});
    observer.observe(document.getElementById('root'), { childList: true, subtree: true });

    // Mutate child inside role="region"
    const newParagraph = document.createElement('p');
    newParagraph.textContent = 'Updated email body';
    pane.appendChild(newParagraph);

    const records = observer.takeRecords();
    observer.disconnect();
    return records.some(filter);
  });
  assert.equal(childMutationResult, true, 'Child mutation inside role="region" must trigger scan');
  console.log('  ✓ [Webmail] Child mutation inside existing reading container => TRIGGERED SCAN');

  // Suite 3: WhatsApp Web & Generic SPA Isolation (isWebmail = false)
  const nonWebmailCases = [
    { name: 'canvas QR code updates (WhatsApp Web)', html: '<canvas id="qr-canvas" width="264" height="264"></canvas>', expected: false },
    { name: 'chat list item re-render', html: '<div class="chat-list"><div class="chat-title">Mom</div></div>', expected: false },
    { name: 'timestamp and badge updates', html: '<span class="timestamp">12:35 PM</span><span class="unread-count">2</span>', expected: false },
    { name: 'SVG status icon animations', html: '<svg class="spinner"><circle cx="12" cy="12" r="10"></circle></svg>', expected: false },
    { name: 'generic role="region" on WhatsApp (not a webmail reading pane)', html: '<div role="region" aria-label="Chat List">Chat entries</div>', expected: false },
    { name: 'standard login input on non-webmail', html: '<input type="password" id="pass" />', expected: true },
    { name: 'standard form on non-webmail', html: '<form action="/login"><input type="text" /></form>', expected: true },
    { name: 'standard textarea on non-webmail', html: '<textarea name="comments"></textarea>', expected: true },
    { name: 'iframe on non-webmail', html: '<iframe src="/embed"></iframe>', expected: true },
  ];

  for (const tc of nonWebmailCases) {
    const result = await page.evaluate((tc) => {
      document.body.innerHTML = '<div id="app-root"></div>';
      const root = document.getElementById('app-root');
      const filter = window.createMutationFilter(false);

      const observer = new MutationObserver(() => {});
      observer.observe(root, { childList: true, subtree: true, attributes: true });

      const temp = document.createElement('div');
      temp.innerHTML = tc.html;
      while (temp.firstChild) {
        root.appendChild(temp.firstChild);
      }

      const records = observer.takeRecords();
      observer.disconnect();
      return records.some(filter);
    }, tc);

    assert.equal(result, tc.expected, `[SPA Isolation] Expected ${tc.expected} for ${tc.name}`);
    console.log(`  ✓ [SPA Isolation] ${tc.name} => ${result ? 'TRIGGERED FORM SCAN' : 'ISOLATED/IGNORED'}`);
  }

  // Suite 4: Attribute mutations
  const attrCases = [
    { name: 'input attribute change (e.g. value/type/disabled)', tag: 'input', attr: 'disabled', val: 'true', expected: true },
    { name: 'form attribute change', tag: 'form', attr: 'action', val: '/submit', expected: true },
    { name: 'generic div attribute change (e.g. class/style re-render)', tag: 'div', attr: 'class', val: 'active-state', expected: false },
    { name: 'canvas attribute change', tag: 'canvas', attr: 'data-frame', val: '120', expected: false },
  ];

  for (const tc of attrCases) {
    const result = await page.evaluate((tc) => {
      document.body.innerHTML = `<div id="root"><${tc.tag} id="target"></${tc.tag}></div>`;
      const target = document.getElementById('target');
      const filter = window.createMutationFilter(false);

      const observer = new MutationObserver(() => {});
      observer.observe(document.getElementById('root'), { attributes: true, subtree: true });

      target.setAttribute(tc.attr, tc.val);

      const records = observer.takeRecords();
      observer.disconnect();
      return records.some(filter);
    }, tc);

    assert.equal(result, tc.expected, `[Attribute Mutation] Expected ${tc.expected} for ${tc.name}`);
    console.log(`  ✓ [Attribute Mutation] ${tc.name} => ${result ? 'DETECTED' : 'FILTERED OUT'}`);
  }

  console.log('\n======================================================');
  console.log(`✅ ALL ${webmailCases.length + 1 + nonWebmailCases.length + attrCases.length} Webmail & SPA Mutation Regression Tests PASSED!`);
  console.log('======================================================\n');
} finally {
  await browser.close();
}
