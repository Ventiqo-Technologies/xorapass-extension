// Scam BEHAVIOUR detection (pure, unit-tested).
//
// Page text can be disguised; behaviour can't. The MAIN-world hook script
// (content/pageHooks.ts) reports what the page actually DOES — go full
// screen, lock the keyboard, trap the back button, write a command to the
// clipboard, ask a crypto wallet to hand over token control, beg for
// notification permission — and this module turns those events into
// verdicts.

// ── ClickFix: malicious commands written to the clipboard ──────────────────

const COMMAND_PATTERNS: ReadonlyArray<RegExp> = [
  /\bpowershell(\.exe)?\b/i,
  /\bpwsh(\.exe)?\b/i,
  /\bmshta(\.exe)?\b/i,
  /\bcmd(\.exe)?\s+\/[ck]\b/i,
  /\b(iex|invoke-expression|invoke-webrequest|iwr|invoke-restmethod|irm)\b/i,
  /\b(downloadstring|downloadfile|frombase64string)\b/i,
  /\b(certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec)(\.exe)?\b/i,
  /\b(curl|wget)\b[^\n|]*\|\s*(ba|z)?sh\b/i,
  /\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(ba|z)?sh\b/i,
  /\bbash\s+-c\b/i,
  /\bosascript\s+-e\b/i,
  /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}/i,
  /\bstart-process\b/i,
];

/**
 * True when text written to the clipboard looks like a shell command meant to
 * be pasted into Run / a terminal — the "ClickFix" / fake-CAPTCHA trick.
 */
export function isMaliciousClipboardCommand(text: string): boolean {
  const s = (text || '').trim();
  if (s.length < 8 || s.length > 20_000) return false;
  let hits = 0;
  for (const re of COMMAND_PATTERNS) if (re.test(s)) hits++;
  if (hits === 0) return false;
  // One strong executor is enough when the text is command-shaped (no
  // ordinary prose around it) or disguises itself with a fake "verification"
  // comment — e.g. `powershell -w h -c "iwr ..." # I am not a robot`.
  const commandShaped = s.split(/\s+/).length < 80 && !/\.\s+[A-Z][a-z]+\s+[a-z]+/.test(s.split('#')[0]);
  const fakeVerification = /#.*\b(not a robot|verif|captcha|human|cloudflare|ray id)/i.test(s);
  return hits >= 2 || commandShaped || fakeVerification;
}

const RUN_DIALOG_INSTRUCTIONS =
  /(\b(win(dows)?(\s*key)?|⊞)\s*\+\s*r\b|press\s+(ctrl|⌘|cmd|command)\s*\+\s*v|open (the )?(run (dialog|box|window)|terminal)|verification steps?|verify (that )?you are (a )?human|i'?m not a robot|complete (the )?verification)/i;
const ALWAYS_HOSTILE = [/\bmshta(\.exe)?\b/i, /-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{40,}/i, /#.*\b(not a robot|verif|captcha|human|cloudflare|ray id)/i];

/**
 * Whether a clipboard write should be BLOCKED. A command alone isn't enough —
 * install docs legitimately offer "copy" buttons for `curl … | sh` or
 * `iwr … | iex`. ClickFix pages pair the command with Run-dialog / paste
 * instructions or a fake "verification" comment, or use tooling no install
 * guide uses (mshta, encoded PowerShell).
 */
export function shouldBlockClipboardWrite(text: string, pageText: string): boolean {
  if (!isMaliciousClipboardCommand(text)) return false;
  if (ALWAYS_HOSTILE.some((re) => re.test(text))) return true;
  return RUN_DIALOG_INSTRUCTIONS.test(pageText || '');
}

// ── Crypto wallet drainers ─────────────────────────────────────────────────

const SELECTORS: Record<string, string> = {
  '0x095ea7b3': 'approve',
  '0xa22cb465': 'setApprovalForAll',
  '0x39509351': 'increaseAllowance',
  '0xd505accf': 'permit',
};

const UNLIMITED_ALLOWANCE = /f{32,}$/i;

export interface WalletRisk {
  level: 'danger' | 'caution' | null;
  kind?: string;
  summary: string;
}

/** Classifies an EIP-1193 request that could hand over control of assets. */
export function classifyWalletRequest(method: string, params: unknown): WalletRisk {
  const m = String(method || '');
  const list = Array.isArray(params) ? params : [];

  if (m === 'eth_sign') {
    return { level: 'danger', kind: 'blind_sign', summary: 'The site wants a "blind" signature that can authorise almost anything — including draining your wallet.' };
  }
  if (m === 'eth_signTypedData_v4' || m === 'eth_signTypedData_v3' || m === 'eth_signTypedData') {
    const raw = list.find((p) => typeof p === 'string' && p.trim().startsWith('{')) as string | undefined;
    let data: any = null;
    try {
      data = raw ? JSON.parse(raw) : list.find((p) => p && typeof p === 'object');
    } catch {
      data = null;
    }
    const primary = String(data?.primaryType || '');
    if (/^(Permit|PermitSingle|PermitBatch|PermitTransferFrom|PermitBatchTransferFrom|PermitWitnessTransferFrom)$/.test(primary)) {
      return { level: 'danger', kind: 'permit', summary: 'The site asks you to sign a token PERMIT — a signature that lets someone else spend your tokens without another confirmation.' };
    }
    if (/order|listing|seaport/i.test(primary) || /seaport/i.test(String(data?.domain?.name || ''))) {
      return { level: 'caution', kind: 'marketplace_order', summary: 'The site asks you to sign a marketplace order. Scam sites use these to list your NFTs for nothing.' };
    }
    return { level: null, summary: '' };
  }
  if (m === 'eth_sendTransaction') {
    const tx = (list[0] || {}) as { data?: string; input?: string };
    const data = String(tx.data || tx.input || '').toLowerCase();
    const sel = data.slice(0, 10);
    const fn = SELECTORS[sel];
    if (fn === 'setApprovalForAll' && /1$/.test(data.slice(10 + 64, 10 + 128))) {
      return { level: 'danger', kind: fn, summary: 'This transaction gives another address control of ALL your NFTs in a collection (setApprovalForAll).' };
    }
    if (fn === 'approve' || fn === 'increaseAllowance') {
      const amount = data.slice(10 + 64, 10 + 128);
      if (UNLIMITED_ALLOWANCE.test(amount)) {
        return { level: 'danger', kind: 'unlimited_approval', summary: 'This transaction gives another address UNLIMITED permission to spend your tokens.' };
      }
      return { level: 'caution', kind: fn, summary: 'This transaction lets another address spend some of your tokens.' };
    }
    if (fn === 'permit') {
      return { level: 'danger', kind: 'permit', summary: 'This transaction submits a token permit that lets someone else spend your tokens.' };
    }
  }
  return { level: null, summary: '' };
}

// ── Fake tech-support / browser-lock behaviour ─────────────────────────────

export type BehaviorKind =
  | 'fullscreen'
  | 'keyboard_lock'
  | 'pointer_lock'
  | 'beforeunload'
  | 'history_flood'
  | 'autoplay_audio'
  | 'notification_request'
  | 'fingerprint';

const BEHAVIOR_WEIGHTS: Record<BehaviorKind, number> = {
  fullscreen: 25,
  keyboard_lock: 35,
  pointer_lock: 15,
  beforeunload: 10,
  history_flood: 25,
  autoplay_audio: 10,
  notification_request: 0,
  fingerprint: 0,
};

/**
 * Tech-support-scam score from observed behaviours plus the page's text cues
 * (see utils/pageContent.ts detectScamCues). Any single behaviour has
 * legitimate uses (video players go full screen, games lock the pointer), so
 * a verdict needs several together, or one plus scam wording.
 */
export function techSupportScamScore(behaviors: ReadonlySet<BehaviorKind>, cues: readonly string[]): number {
  let score = 0;
  for (const b of behaviors) score += BEHAVIOR_WEIGHTS[b] ?? 0;
  if (cues.includes('tech_support')) score += 35;
  if (cues.includes('urgency')) score += 10;
  // Behaviour alone (no scam wording) is capped below the warning threshold
  // unless it's the classic lock-in trio.
  const lockIn = behaviors.has('keyboard_lock') && behaviors.has('fullscreen');
  if (!cues.includes('tech_support') && !lockIn) score = Math.min(score, 55);
  return Math.min(100, score);
}

export const TECH_SUPPORT_WARN = 60;

/**
 * Notification-permission bait: "click Allow to prove you're not a robot"
 * wording, or asking straight away (no user interaction) on a page that
 * already shows scam cues, is how push-spam networks recruit victims. A
 * plain news site asking on load is annoying but not flagged.
 */
export function isNotificationBait(hadUserActivation: boolean, pageText: string, cues: readonly string[] = []): boolean {
  const bait = /\b(click|press|tap) ["“']?allow["”']? (to|if) (verify|confirm|prove|continue|watch|download|access|you('re| are) not a robot|you are (a )?human)/i.test(pageText);
  const scammy = cues.some((c) => ['tech_support', 'prize_scam', 'crypto_scam', 'fake_download', 'clickfix'].includes(c));
  return bait || (!hadUserActivation && scammy);
}
