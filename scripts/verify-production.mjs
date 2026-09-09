import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const forbidden = [
  'dev-app.xorapass.com',
];

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await filesUnder(path)));
    } else {
      files.push(path);
    }
  }

  return files;
}

const files = await filesUnder('dist');
const matches = [];

for (const file of files) {
  const contents = await readFile(file, 'utf8');
  for (const value of forbidden) {
    if (contents.includes(value)) {
      matches.push(`${file}: ${value}`);
    }
  }
}

if (matches.length > 0) {
  console.error('Development URL found in production artifact:');
  console.error(matches.join('\n'));
  process.exit(1);
}

console.log('Production artifact contains no development URLs.');