// Regenerates src/utils/faviconBrands.ts: downloads each brand's real favicon
// and hashes it in Chromium with the SAME code the content script runs
// (src/utils/faviconHash.ts), so reference and page hashes are comparable.
//
//   npm i --no-save playwright && npx playwright install chromium
//   node scripts/gen-favicon-brands.mjs
//
// Then check the printed "nearest" distances stay well above
// FAVICON_MATCH_MAX_DISTANCE and run the tests.
import { build } from 'esbuild';
import { writeFileSync } from 'node:fs';

const BRANDS = {
 "paypal": {
  "domains": [
   "paypal.com"
  ],
  "icons": [
   "https://www.paypal.com/favicon.ico"
  ]
 },
 "microsoft": {
  "domains": [
   "microsoft.com",
   "live.com",
   "office.com",
   "microsoftonline.com",
   "outlook.com",
   "bing.com",
   "azure.com",
   "msauth.net",
   "msftauth.net",
   "microsoft365.com"
  ],
  "icons": [
   "https://www.microsoft.com/favicon.ico",
   "https://aadcdn.msftauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9sol6lg2.ico"
  ]
 },
 "outlook": {
  "domains": [
   "outlook.com",
   "live.com",
   "office.com",
   "microsoft.com",
   "microsoft365.com"
  ],
  "icons": [
   "https://outlook.live.com/favicon.ico"
  ]
 },
 "google": {
  "domains": [
   "google.com",
   "gmail.com",
   "youtube.com"
  ],
  "icons": [
   "https://www.google.com/favicon.ico"
  ]
 },
 "apple": {
  "domains": [
   "apple.com",
   "icloud.com"
  ],
  "icons": [
   "https://www.apple.com/favicon.ico"
  ]
 },
 "icloud": {
  "domains": [
   "icloud.com",
   "apple.com"
  ],
  "icons": [
   "https://www.icloud.com/favicon.ico"
  ]
 },
 "amazon": {
  "domains": [
   "amazon.com",
   "amazon.co.uk",
   "amazon.de",
   "amazon.in",
   "amazon.ca",
   "amazon.fr",
   "amazon.it",
   "amazon.es",
   "amazon.co.jp",
   "amazon.com.au"
  ],
  "icons": [
   "https://www.amazon.com/favicon.ico"
  ]
 },
 "netflix": {
  "domains": [
   "netflix.com"
  ],
  "icons": [
   "https://www.netflix.com/favicon.ico"
  ]
 },
 "facebook": {
  "domains": [
   "facebook.com",
   "meta.com",
   "messenger.com"
  ],
  "icons": [
   "https://www.facebook.com/favicon.ico"
  ]
 },
 "instagram": {
  "domains": [
   "instagram.com"
  ],
  "icons": [
   "https://www.instagram.com/favicon.ico"
  ]
 },
 "whatsapp": {
  "domains": [
   "whatsapp.com"
  ],
  "icons": [
   "https://web.whatsapp.com/favicon.ico"
  ]
 },
 "linkedin": {
  "domains": [
   "linkedin.com"
  ],
  "icons": [
   "https://www.linkedin.com/favicon.ico"
  ]
 },
 "github": {
  "domains": [
   "github.com"
  ],
  "icons": [
   "https://github.githubassets.com/favicons/favicon.png"
  ]
 },
 "dropbox": {
  "domains": [
   "dropbox.com"
  ],
  "icons": [
   "https://www.dropbox.com/static/30168/images/favicon.ico"
  ]
 },
 "docusign": {
  "domains": [
   "docusign.com",
   "docusign.net"
  ],
  "icons": [
   "https://www.docusign.com/favicon.ico"
  ]
 },
 "adobe": {
  "domains": [
   "adobe.com"
  ],
  "icons": [
   "https://www.adobe.com/favicon.ico"
  ]
 },
 "coinbase": {
  "domains": [
   "coinbase.com"
  ],
  "icons": [
   "https://www.coinbase.com/favicon.ico"
  ]
 },
 "binance": {
  "domains": [
   "binance.com"
  ],
  "icons": [
   "https://bin.bnbstatic.com/static/images/common/favicon.ico"
  ]
 },
 "metamask": {
  "domains": [
   "metamask.io"
  ],
  "icons": [
   "https://metamask.io/favicon.ico"
  ]
 },
 "chase": {
  "domains": [
   "chase.com"
  ],
  "icons": [
   "https://www.chase.com/etc/designs/chase-ux/favicon.ico",
   "https://www.chase.com/favicon.ico"
  ]
 },
 "wellsfargo": {
  "domains": [
   "wellsfargo.com"
  ],
  "icons": [
   "https://www.wellsfargo.com/favicon.ico"
  ]
 },
 "dhl": {
  "domains": [
   "dhl.com",
   "dhl.de"
  ],
  "icons": [
   "https://www.dhl.com/favicon.ico"
  ]
 },
 "ups": {
  "domains": [
   "ups.com"
  ],
  "icons": [
   "https://www.ups.com/favicon.ico"
  ]
 },
 "usps": {
  "domains": [
   "usps.com"
  ],
  "icons": [
   "https://www.usps.com/favicon.ico"
  ]
 },
 "stripe": {
  "domains": [
   "stripe.com"
  ],
  "icons": [
   "https://stripe.com/favicon.ico"
  ]
 },
 "slack": {
  "domains": [
   "slack.com"
  ],
  "icons": [
   "https://slack.com/favicon.ico"
  ]
 },
 "zoom": {
  "domains": [
   "zoom.us",
   "zoom.com"
  ],
  "icons": [
   "https://zoom.us/favicon.ico"
  ]
 },
 "twitter": {
  "domains": [
   "x.com",
   "twitter.com"
  ],
  "icons": [
   "https://x.com/favicon.ico",
   "https://abs.twimg.com/favicons/twitter.3.ico"
  ]
 },
 "revolut": {
  "domains": [
   "revolut.com"
  ],
  "icons": [
   "https://assets.revolut.com/assets/favicons/favicon.ico"
  ]
 }
};

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36';
const bundle = await build({ entryPoints: ['src/utils/faviconHash.ts'], bundle: true, format: 'iife', globalName: 'FH', write: false });
const fh = bundle.outputFiles[0].text;
const { chromium } = await import('playwright');
const browser = await chromium.launch();
const page = await browser.newPage();
const files = new Map();
await page.route('https://gen.local/**', (r) => {
  const key = new URL(r.request().url()).pathname.slice(1);
  if (!key) return r.fulfill({ contentType: 'text/html', body: '<html></html>' });
  const f = files.get(key);
  return f ? r.fulfill({ contentType: f.type, body: f.body }) : r.fulfill({ status: 404 });
});
await page.goto('https://gen.local/');
await page.addScriptTag({ content: fh });

const ham = (a, b) => { let d = 0; for (let i = 0; i < 16; i += 2) { let x = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16); while (x) { d += x & 1; x >>= 1; } } return d; };
const out = [];
for (const [brand, v] of Object.entries(BRANDS)) {
  const hashes = new Set();
  for (const [i, url] of v.icons.entries()) {
    try {
      // Some sites serve HTML to browsers and the icon to plain clients.
      let res = await fetch(url, { headers: { 'User-Agent': UA } });
      let type = res.headers.get('content-type') || '';
      if (!res.ok || type.includes('html')) {
        res = await fetch(url);
        type = res.headers.get('content-type') || '';
      }
      if (!res.ok || type.includes('html')) throw new Error(`HTTP ${res.status} ${type}`);
      const key = `${brand}_${i}`;
      files.set(key, { type: type || 'image/x-icon', body: Buffer.from(await res.arrayBuffer()) });
      const h = await page.evaluate((u) => FH.loadAndHashIcon(u), `https://gen.local/${key}`);
      if (h) hashes.add(h);
    } catch (e) {
      console.warn(`${brand}: ${url} failed (${e.message})`);
    }
  }
  if (hashes.size) out.push({ brand, domains: v.domains, hashes: [...hashes] });
  else console.warn(`${brand}: skipped (no icon)`);
}
await browser.close();

for (const a of out) {
  let m = 64, who = '';
  for (const b of out) if (b.brand !== a.brand) for (const x of a.hashes) for (const y of b.hashes) if (ham(x, y) < m) { m = ham(x, y); who = b.brand; }
  console.log(a.brand.padEnd(13), 'nearest', who, m);
}
const rows = out.map((b) => `  { brand: ${JSON.stringify(b.brand)}, domains: ${JSON.stringify(b.domains).replaceAll('","', '", "')}, hashes: ${JSON.stringify(b.hashes).replaceAll('","', '", "')} },`);
writeFileSync('src/utils/faviconBrands.ts', `// Reference favicon hashes for commonly impersonated brands (dHash, see
// faviconHash.ts). Generated ${new Date().toISOString().slice(0, 10)} from each brand's own favicon, hashed
// in Chromium with the same code the content script uses. Regenerate with
// scripts/gen-favicon-brands.mjs when a brand changes its icon.
// Brands must be tokens of the server's BrandLexicon.

import type { FaviconBrand } from './faviconHash';

export const FAVICON_BRANDS: readonly FaviconBrand[] = [
${rows.join('\n')}
];
`);
console.log(`wrote ${out.length} brands`);
