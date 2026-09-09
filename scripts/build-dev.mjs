// Builds the extension pointing to the development environment (https://dev-app.xorapass.com)
// and updates the dist/manifest.json host permissions and externally_connectable entries.
import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';

const DEV_URL = 'https://dev-app.xorapass.com';

const env = {
  ...process.env,
  VITE_API_BASE_URL: DEV_URL,
  VITE_WEB_APP_URL: DEV_URL,
};

const steps = [
  ['npx', ['tsc']],
  ['npx', ['vite', 'build']],
  ['npx', ['vite', 'build', '--mode', 'content']],
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

// Update dist/manifest.json for dev
const manifestPath = 'dist/manifest.json';
try {
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  
  if (Array.isArray(manifest.host_permissions) && !manifest.host_permissions.includes(`${DEV_URL}/*`)) {
    manifest.host_permissions.push(`${DEV_URL}/*`);
  }

  if (manifest.externally_connectable?.matches && !manifest.externally_connectable.matches.includes(`${DEV_URL}/*`)) {
    manifest.externally_connectable.matches.push(`${DEV_URL}/*`);
  }

  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`Successfully built extension configured for ${DEV_URL}`);
} catch (err) {
  console.error('Failed to configure dev manifest:', err);
  process.exit(1);
}
