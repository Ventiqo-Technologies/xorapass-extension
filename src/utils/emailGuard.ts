// Email Guard (pure, unit-tested): links, attachments and Reply-To inside the
// OPEN message of a supported webmail. Runs entirely on the device — no email
// content is sent anywhere.

import { extractHostname, registrableDomain } from './siteTrust';
import { assessDomainRisk } from './domainRisk';
import { unwrapLink, isShortenerUrl } from './linkInspect';
import { KNOWN_BRAND_DOMAINS } from './promptSafety';

export interface EmailFinding {
  level: 'danger' | 'caution';
  reasons: string[];
}

const DOMAIN_IN_TEXT = /^(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i;
const IP_HOST = /^\d{1,3}(\.\d{1,3}){3}$/;

/** The domain a link's visible text claims, if the text looks like a URL/domain. */
export function domainClaimedByText(text: string): string | null {
  const t = (text || '').trim().replace(/[\s​]+/g, '');
  if (!t || t.length > 200) return null;
  const m = t.match(DOMAIN_IN_TEXT);
  if (!m) return null;
  return registrableDomain(m[1].toLowerCase()) || null;
}

/**
 * Analyses one link in an email. `knownHosts` are the user's saved sites
 * (when unlocked) — lookalikes of those, or of well-known brands, are flagged.
 */
export function analyzeEmailLink(text: string, href: string, knownHosts: readonly string[] = []): EmailFinding | null {
  if (!href || /^(mailto|tel|sms|cid|#)/i.test(href)) return null;
  const { url: finalUrl, hops } = unwrapLink(href);
  if (!/^https?:\/\//i.test(finalUrl)) {
    return /^(javascript|data|vbscript):/i.test(finalUrl)
      ? { level: 'danger', reasons: ['Link runs code instead of opening a web page'] }
      : null;
  }
  const host = extractHostname(finalUrl);
  if (!host) return null;
  const reasons: string[] = [];
  let level: EmailFinding['level'] | null = null;
  const raise = (l: EmailFinding['level'], r: string) => {
    reasons.push(r);
    if (l === 'danger' || !level) level = l;
  };

  const claimed = domainClaimedByText(text);
  const actual = registrableDomain(host);
  if (claimed && actual && claimed !== actual) {
    raise('danger', `Link text shows ${claimed} but it really goes to ${actual}`);
  }

  const risk = assessDomainRisk(host, Array.from(new Set([...knownHosts, ...KNOWN_BRAND_DOMAINS])), [], finalUrl);
  if (risk.signals.isHomograph || risk.signals.hasPunycode) raise('danger', `Uses look-alike characters to imitate ${risk.matchedTarget || 'a real site'}`);
  else if (risk.signals.typosquatTarget) raise('danger', `Misspelled look-alike of ${risk.signals.typosquatTarget}`);
  else if (risk.signals.brandAbuse) raise('danger', `Uses the ${risk.signals.brandAbuse.brand} name on a site it doesn't own`);

  if (IP_HOST.test(host)) raise('danger', 'Goes to a raw IP address instead of a website name');
  if (isShortenerUrl(finalUrl)) raise('caution', 'Hides its destination behind a link shortener');
  if (/^http:\/\//i.test(finalUrl) && !level) raise('caution', 'Opens an unencrypted (HTTP) page');
  if (risk.signals.isHighRiskTld && !level) raise('caution', 'Uses a web address ending often used for scams');
  if (hops.length >= 2 && !level) raise('caution', 'Passes through several redirectors');

  return level ? { level, reasons } : null;
}

const DANGEROUS_EXT = new Set([
  'exe', 'scr', 'msi', 'msix', 'bat', 'cmd', 'com', 'pif', 'cpl', 'lnk', 'hta', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh',
  'ps1', 'psm1', 'jar', 'reg', 'iso', 'img', 'vhd', 'vhdx', 'apk', 'dmg', 'pkg', 'app', 'appimage', 'one', 'xll',
]);
const CAUTION_EXT = new Set(['html', 'htm', 'shtml', 'xhtml', 'svg', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'zip', 'rar', '7z', 'cab', 'ace']);
const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'rtf', 'csv']);

/** Flags risky attachment names (executables, HTML smuggling, disguised double extensions). */
export function analyzeAttachmentName(name: string): EmailFinding | null {
  const n = (name || '').trim().toLowerCase().replace(/[‮‎‏]/g, '');
  if (!n || n.length > 260) return null;
  if (/[‮]/.test(name)) return { level: 'danger', reasons: ['File name uses a hidden character to disguise its real type'] };
  const parts = n.split('.');
  if (parts.length < 2) return null;
  const ext = parts[parts.length - 1];
  const prev = parts.length > 2 ? parts[parts.length - 2] : '';
  if (DANGEROUS_EXT.has(ext)) {
    const reasons = [`.${ext} files can run programs on your computer`];
    if (DOC_EXT.has(prev)) reasons.unshift(`Disguised as a .${prev} but is really a .${ext}`);
    return { level: 'danger', reasons };
  }
  if (CAUTION_EXT.has(ext)) {
    const why = ['html', 'htm', 'shtml', 'xhtml', 'svg'].includes(ext)
      ? 'Web-page attachments are often fake login pages'
      : ext.endsWith('m') || ext === 'xlam'
        ? 'Office files with macros can install malware'
        : 'Archives can hide dangerous files';
    return { level: 'caution', reasons: [why] };
  }
  return null;
}

/** Reply-To pointing at a different organisation than the sender. */
export function analyzeReplyTo(senderEmail: string, replyToEmail: string): EmailFinding | null {
  const sd = registrableDomain((senderEmail.split('@')[1] || '').toLowerCase());
  const rd = registrableDomain((replyToEmail.split('@')[1] || '').toLowerCase());
  if (!sd || !rd || sd === rd) return null;
  const free = new Set(['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'proton.me', 'protonmail.com', 'icloud.com', 'gmx.com', 'mail.com']);
  return {
    level: free.has(rd) ? 'danger' : 'caution',
    reasons: [`Replies go to ${rd}, not the sender's ${sd}`],
  };
}

/** Extracts a Reply-To address from header text ("reply-to: name <a@b.c>"). */
export function findReplyTo(headerText: string): string | null {
  const m = (headerText || '').match(/reply[- ]to:?\s*(?:[^<\n]*<)?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/i);
  return m ? m[1].toLowerCase() : null;
}
