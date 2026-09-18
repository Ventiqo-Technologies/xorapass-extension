// Download protection decisions (pure, unit-tested).
//
// The background watches new downloads (optional `downloads` permission).
// A browser extension can't read a downloaded file's bytes, so the check is
// about WHERE it comes from and WHAT it is: the source's blocklist / threat
// verdict and domain age, and whether the file type can run code.

export const RUNNABLE_EXTENSIONS = new Set([
  'exe', 'msi', 'msix', 'scr', 'bat', 'cmd', 'com', 'pif', 'cpl', 'lnk', 'hta', 'js', 'jse', 'vbs', 'vbe',
  'wsf', 'ps1', 'jar', 'reg', 'iso', 'img', 'vhd', 'vhdx', 'apk', 'dmg', 'pkg', 'app', 'appimage', 'deb', 'rpm',
  'sh', 'command', 'xll', 'one',
]);

const ARCHIVES = new Set(['zip', 'rar', '7z', 'cab', 'tar', 'gz', 'tgz']);

export function fileExtension(nameOrUrl: string): string {
  const base = (nameOrUrl || '').split(/[?#]/)[0].split(/[\\/]/).pop() || '';
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase() : '';
}

export interface DownloadInput {
  filename: string; // may be '' when the browser hasn't decided yet
  url: string;
  mime?: string;
  blocklisted: boolean; // confirmed blocklist hit for the source URL
  remoteDecision?: 'allow' | 'warn' | 'require_approval' | 'block' | null;
  domainAgeDays: number; // -1 unknown
  isHttp: boolean;
}

export interface DownloadVerdict {
  action: 'allow' | 'warn' | 'block';
  reasons: string[];
}

export function decideDownload(d: DownloadInput): DownloadVerdict {
  const ext = fileExtension(d.filename) || fileExtension(d.url);
  const runnable =
    RUNNABLE_EXTENSIONS.has(ext) ||
    /x-msdownload|x-msdos-program|x-ms-installer|x-apple-diskimage|java-archive|vnd\.android\.package-archive|x-iso9660/i.test(d.mime || '');
  const archive = ARCHIVES.has(ext);
  const reasons: string[] = [];

  if (d.blocklisted) {
    return { action: 'block', reasons: ['This file comes from a site on a list of known dangerous sites.'] };
  }
  if (d.remoteDecision === 'block') {
    return { action: 'block', reasons: ['XoraPass Shield flagged the site this file comes from as dangerous.'] };
  }

  const newDomain = d.domainAgeDays >= 0 && d.domainAgeDays <= 30;
  if (runnable || archive) {
    if (newDomain) reasons.push(`It comes from a website registered only ${d.domainAgeDays} day${d.domainAgeDays === 1 ? '' : 's'} ago.`);
    if (d.remoteDecision === 'warn' || d.remoteDecision === 'require_approval') reasons.push('The site it comes from looks suspicious.');
    if (d.isHttp) reasons.push('It is downloaded over an unencrypted (HTTP) connection.');
    if (reasons.length > 0) {
      reasons.unshift(runnable ? `.${ext || 'this'} files can run programs on your computer.` : 'Archives can hide programs that run on your computer.');
      return { action: 'warn', reasons };
    }
  }
  return { action: 'allow', reasons: [] };
}
