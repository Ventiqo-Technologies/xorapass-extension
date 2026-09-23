// Page text extraction + local scam cues for Shield's AI scam analysis.
//
// The content script uses detectScamCues() locally, on-device, to decide
// whether a page is worth an AI look at all. Only when it is (or the page's
// risk is already elevated) does a SMALL, REDACTED extract leave the device:
// title, a few headings / button / form-label texts and ~2k chars of visible
// text. Never form values, never anything the user typed, and emails, phone
// numbers, long digit runs and URL query strings are stripped first (the
// server re-applies the same redaction).
//
// Everything except collectPageText() is pure and unit-tested.

export interface ScanPageText {
  title: string;
  headings: string[];
  buttons: string[];
  labels: string[];
  text: string;
  cues: string[];
}

const LIMITS = { title: 200, item: 120, items: 15, text: 2000 };

export function redactText(input: string, max: number): string {
  let s = (input || '').replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '');
  s = s.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]');
  s = s.replace(/(https?:\/\/[^\s?#]+)[?#]\S*/g, '$1');
  s = s.replace(/\+?\d[\d\s().-]{7,}\d/g, '[phone]');
  s = s.replace(/\d{5,}/g, '[number]');
  s = s.replace(/\s+/g, ' ').trim();
  return Array.from(s).slice(0, max).join('');
}

function redactList(items: string[]): string[] {
  const out: string[] = [];
  for (const it of items) {
    if (out.length >= LIMITS.items) break;
    const r = redactText(it, LIMITS.item);
    if (r && !out.includes(r)) out.push(r);
  }
  return out;
}

/** Local scam cue patterns, by category. Deliberately specific. */
const CUE_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['tech_support', /\b(virus(es)? (detected|found)|your (computer|pc|device|system) (is|has been) (infected|locked|blocked|compromised)|call (microsoft|apple|windows) (support|help)|toll[- ]free|do not (close|restart|shut down) (this|your))\b/i],
  ['clickfix', /\b(win(dows)?\s*(\+|key\s*\+)\s*r|press\s+(ctrl|⌘|cmd)\s*\+\s*v|paste (it|the (code|command)) (in|into)|open (powershell|terminal|run dialog)|verify you are (a )?human.{0,80}(press|paste|run))\b/i],
  ['crypto_scam', /\b(send \d+(\.\d+)? ?(btc|eth|usdt|sol)|double your (crypto|bitcoin|btc|eth|coins)|crypto giveaway|seed phrase|recovery phrase|connect (your )?wallet to (claim|receive|verify)|airdrop claim)\b/i],
  ['prize_scam', /\b(you('ve| have) (won|been selected)|claim your (prize|reward|gift)|congratulations[!,. ].{0,60}(winner|won|selected)|lucky (visitor|winner)|reward(s)? points? (are ready|available|to redeem)|check rewards points|claim rewards?|canje(a|ar)? tus (puntos|millas)|reclama tu (premio|recompensa)|(puntos|millas) acumulad(os|as))\b/i],
  ['fake_download', /\b((your )?(browser|chrome|flash player|media player) (is )?(out of date|needs (an )?update|update required)|download (the )?(required )?(codec|plugin|update) to (continue|view|play))\b/i],
  ['investment_scam', /\b(guaranteed (returns?|profits?)|(\d{2,3})% (daily|weekly) (returns?|profits?)|risk[- ]free (investment|trading)|earn \$?\d[\d,]* (per|a) (day|hour) (trading|from home))\b/i],
  ['fake_shop', /\b((9\d|8\d)% off (everything|all items|today only)|closing down sale.{0,40}(9\d|8\d)%|payment (only )?(via|by) (gift ?cards?|bitcoin|crypto|western union|wire transfer))\b/i],
  ['notification_bait', /\b(click|press|tap) ["“']?allow["”']? (to|if) (verify|confirm|prove|continue|watch|download|access|you('re| are) not a robot|you are (a )?human)/i],
  ['urgency', /\b(your account (will be|has been) (suspended|closed|locked)|act (now|immediately)|within 24 hours|final (warning|notice)|su cuenta (ha sido|ser[aá]) (suspendida|bloqueada)|act[uú]e (de inmediato|ahora))\b/i],
];

/** Scam cue categories found in the given text (on-device). */
export function detectScamCues(text: string): string[] {
  const found: string[] = [];
  for (const [cat, re] of CUE_PATTERNS) {
    if (re.test(text)) found.push(cat);
  }
  // A phone number shown next to "virus"/"infected" wording is the fake
  // tech-support pattern even when the exact phrases above aren't used.
  if (!found.includes('tech_support') && PHONE_NUMBER.test(text) && INFECTION_WORDS.test(text)) found.push('tech_support');
  return found;
}

const PHONE_NUMBER = /(\+?1[\s.-]?)?\(?(8(00|33|44|55|66|77|88))\)?[\s.-]?\d{3}[\s.-]?\d{4}|\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}/;
const INFECTION_WORDS = /\b(virus|infected|infection|malware|trojan|spyware|ransomware|hacked|security (alert|breach|warning)|firewall (alert|warning))\b/i;

/**
 * Whether a page is worth an AI scan: it shows at least one specific scam cue
 * (a lone "urgency" cue isn't enough), or local/server checks already scored
 * it as risky.
 */
export function shouldAiScan(cues: string[], localRiskScore: number, minRisk = 25): boolean {
  const specific = cues.filter((c) => c !== 'urgency');
  return specific.length > 0 || (cues.includes('urgency') && localRiskScore >= 10) || localRiskScore >= minRisk;
}

function texts(root: ParentNode, selector: string, attr?: string): string[] {
  const out: string[] = [];
  root.querySelectorAll(selector).forEach((el) => {
    if (out.length >= 40) return;
    const v = attr ? (el as Element).getAttribute(attr) : (el as HTMLElement).innerText ?? el.textContent;
    if (v && v.trim()) out.push(v.trim());
  });
  return out;
}

/** DOM adapter: builds the redacted extract for the current document. */
export function collectPageText(doc: Document = document): ScanPageText {
  const body = doc.body;
  const visible = body ? (body.innerText || body.textContent || '').slice(0, 8000) : '';
  const headings = texts(doc, 'h1, h2, h3');
  const buttons = [
    ...texts(doc, 'button, [role="button"], a.button, a.btn'),
    ...texts(doc, 'input[type="submit"], input[type="button"]', 'value'),
  ];
  const labels = [...texts(doc, 'label'), ...texts(doc, 'input[placeholder], textarea[placeholder]', 'placeholder')];
  const title = doc.title || '';

  const cues = detectScamCues([title, ...headings, ...buttons, visible].join('\n'));
  return {
    title: redactText(title, LIMITS.title),
    headings: redactList(headings),
    buttons: redactList(buttons),
    labels: redactList(labels),
    text: redactText(visible, LIMITS.text),
    cues,
  };
}
