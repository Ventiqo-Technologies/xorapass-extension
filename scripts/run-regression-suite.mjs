import { spawnSync } from 'node:child_process';
import process from 'node:process';

const steps = [
  {
    name: 'Tier 1: Production Compilation & Bundle Generation (Vite + Rollup + Tailwind v4)',
    cmd: 'node',
    args: ['scripts/build-prod.mjs'],
  },
  {
    name: 'Tier 2: Unit & Bundle Isolation Regressions (Vitest)',
    cmd: 'npx',
    args: ['vitest', 'run'],
  },
  {
    name: 'Tier 3A: Chromium Webmail Reading Pane & SPA Mutation Regressions',
    cmd: 'node',
    args: ['scripts/test-webmail-mutations.mjs'],
  },
  {
    name: 'Tier 3B: Chromium Outlook Header Sender Extraction Fixtures',
    cmd: 'node',
    args: ['scripts/test-outlook-headers.mjs'],
  },
  {
    name: 'Tier 3C: Chromium Email Panel Render & Viewport Fixtures',
    cmd: 'node',
    args: ['scripts/test-email-panel-results.mjs'],
  },
  {
    name: 'Tier 4: Production Smoke, Manifest & Isolation Verifications',
    cmd: 'node',
    args: ['scripts/smoke-test.mjs'],
  },
];

console.log('================================================================');
console.log('🛡️  XoraPass Extension — Comprehensive Regression Test Suite  🛡️');
console.log('================================================================\n');

const suiteStartTime = Date.now();
const results = [];

for (let i = 0; i < steps.length; i++) {
  const step = steps[i];
  console.log(`\n▶ [${i + 1}/${steps.length}] Running ${step.name}...`);
  const stepStartTime = Date.now();

  const proc = spawnSync(step.cmd, step.args, {
    stdio: 'inherit',
    shell: true,
  });

  const durationSec = ((Date.now() - stepStartTime) / 1000).toFixed(2);

  if (proc.status !== 0) {
    console.error(`\n❌ Step [${i + 1}/${steps.length}] FAILED: ${step.name} (exit code ${proc.status})`);
    process.exit(proc.status || 1);
  }

  results.push({ name: step.name, duration: `${durationSec}s`, status: 'PASSED' });
}

const totalTime = ((Date.now() - suiteStartTime) / 1000).toFixed(2);

console.log('\n================================================================');
console.log('🏆 COMPREHENSIVE REGRESSION SUITE EXECUTION SUMMARY');
console.log('================================================================');
for (const res of results) {
  console.log(`  ✓ ${res.name.padEnd(58)} [${res.duration}]`);
}
console.log('----------------------------------------------------------------');
console.log(`✅ ALL ${steps.length} REGRESSION TIERS PASSED SUCCESSFULLY in ${totalTime}s!`);
console.log('================================================================\n');
