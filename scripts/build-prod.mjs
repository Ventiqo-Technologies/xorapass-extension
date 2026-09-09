// Runs the real build with VITE_API_BASE_URL / VITE_WEB_APP_URL force-set to
// production, overriding anything already present in the calling shell's
// environment. `npm run build` must always produce a prod-pointed artifact —
// this is what the release workflow (.github/workflows/extension.yml) relies
// on, and a stray VITE_API_BASE_URL left over in a dev shell was exactly what
// shipped a dev-pointed extension build previously.
import { spawnSync } from 'node:child_process';

const PROD_URL = 'https://app.xorapass.com';

const env = {
  ...process.env,
  VITE_API_BASE_URL: PROD_URL,
  VITE_WEB_APP_URL: PROD_URL,
};

const steps = [
  ['npx', ['tsc']],
  ['npx', ['vite', 'build']],
  ['npx', ['vite', 'build', '--mode', 'content']],
  ['node', ['scripts/verify-production.mjs']],
];

for (const [cmd, args] of steps) {
  const result = spawnSync(cmd, args, { stdio: 'inherit', env, shell: true });
  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
