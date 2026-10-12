import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');

console.log('==============================================');
console.log('🚀 XoraPass Extension Comprehensive Smoke Test');
console.log('==============================================');

let failures = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
  } else {
    console.error(`  ✗ FAILED: ${message}`);
    failures++;
  }
}

// 1. Verify Manifest
console.log('\n[1/4] Checking manifest.json integrity...');
const manifestPath = path.join(distDir, 'manifest.json');
assert(fs.existsSync(manifestPath), 'dist/manifest.json exists');

const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
let manifest;
try {
  manifest = JSON.parse(manifestRaw);
  assert(true, 'manifest.json is valid JSON');
} catch (e) {
  assert(false, `manifest.json JSON parsing failed: ${e.message}`);
}

if (manifest) {
  assert(manifest.manifest_version === 3, 'Manifest version is 3');
  assert(manifest.name && manifest.name.toLowerCase().includes('xorapass'), 'Manifest name is XoraPass');
  assert(!JSON.stringify(manifest).includes('cloudpass'), 'Manifest contains no retired names (cloudpass)');

  // Verify background worker
  const swPath = manifest.background?.service_worker;
  assert(Boolean(swPath && fs.existsSync(path.join(distDir, swPath))), `Service worker exists: ${swPath}`);

  // Verify popup
  const popupHtml = manifest.action?.default_popup;
  assert(Boolean(popupHtml && fs.existsSync(path.join(distDir, popupHtml))), `Popup HTML exists: ${popupHtml}`);

  // Verify content scripts
  if (Array.isArray(manifest.content_scripts)) {
    for (const cs of manifest.content_scripts) {
      if (Array.isArray(cs.js)) {
        for (const jsFile of cs.js) {
          const filePath = path.join(distDir, jsFile);
          assert(fs.existsSync(filePath), `Content script exists: ${jsFile}`);
        }
      }
    }
  }

  // Verify web accessible resources
  if (Array.isArray(manifest.web_accessible_resources)) {
    for (const war of manifest.web_accessible_resources) {
      for (const res of war.resources || []) {
        // May contain wildcards
        if (!res.includes('*')) {
          assert(fs.existsSync(path.join(distDir, res)), `Web accessible resource exists: ${res}`);
        }
      }
    }
  }
}

// 2. Verify Startup Isolation in Production Bundles
console.log('\n[2/4] Checking WhatsApp & AWS startup isolation in compiled bundles...');
const pageHooksContent = fs.readFileSync(path.join(distDir, 'pageHooks.js'), 'utf8');
const shieldNavContent = fs.readFileSync(path.join(distDir, 'shieldNav.js'), 'utf8');

assert(pageHooksContent.includes('web.whatsapp.com'), 'pageHooks.js includes web.whatsapp.com exclusion');
assert(pageHooksContent.includes('aws.amazon.com'), 'pageHooks.js includes aws.amazon.com exclusion');
assert(pageHooksContent.includes('signin.aws'), 'pageHooks.js includes signin.aws exclusion');
assert(pageHooksContent.includes('awsapps.com'), 'pageHooks.js includes awsapps.com exclusion');

assert(shieldNavContent.includes('web.whatsapp.com'), 'shieldNav.js includes web.whatsapp.com exclusion');
assert(shieldNavContent.includes('aws.amazon.com'), 'shieldNav.js includes aws.amazon.com exclusion');
assert(shieldNavContent.includes('signin.aws'), 'shieldNav.js includes signin.aws exclusion');
assert(shieldNavContent.includes('awsapps.com'), 'shieldNav.js includes awsapps.com exclusion');

// 3. Size and Sanity Checks
console.log('\n[3/4] Verifying bundle sizes and asset presence...');
const requiredFiles = [
  'background.js',
  'content.js',
  'cardFrame.js',
  'popup.js',
  'popup.html',
  'pageHooks.js',
  'shieldNav.js',
  'offscreen.html',
  'offscreen.js'
];

for (const file of requiredFiles) {
  const filePath = path.join(distDir, file);
  if (fs.existsSync(filePath)) {
    const stats = fs.statSync(filePath);
    assert(stats.size > 200, `${file} is non-empty (${(stats.size / 1024).toFixed(1)} KB)`);
  } else {
    assert(false, `${file} missing from dist`);
  }
}

// 4. Verify No Leak of Internal Dev URLs
console.log('\n[4/4] Verifying production environment constraints...');
assert(!pageHooksContent.includes('dev-app.xorapass.com'), 'pageHooks.js does not contain dev URLs');
assert(!shieldNavContent.includes('dev-app.xorapass.com'), 'shieldNav.js does not contain dev URLs');

console.log('\n----------------------------------------------');
if (failures === 0) {
  console.log('✅ ALL SMOKE TESTS PASSED! Extension is release-ready.');
  process.exit(0);
} else {
  console.error(`❌ ${failures} SMOKE TEST(S) FAILED.`);
  process.exit(1);
}
