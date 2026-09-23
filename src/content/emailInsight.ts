// XoraPass email check — a small panel above the OPEN email in a supported
// webmail: who really sent it, what the subject is, where every link really
// goes, and the on-device findings. "Analyze with AI" (paid Shield, rolled
// out) sends a minimised, redacted version for AI analysis; it also runs
// automatically when the on-device checks already found red flags.
//
// Sent for AI analysis (only then): sender name + address, Reply-To, subject,
// link text + destination (no query strings), attachment names, and up to
// 1,500 characters of body text with e-mail addresses, phone and long numbers
// removed. Nothing else, and nothing is stored.

import browser from 'webextension-polyfill';
import { summarizeEmailLocal, findReplyTo, type EmailLocalSummary } from '../utils/emailGuard';
import { unwrapLink } from '../utils/linkInspect';
import { extractHostname } from '../utils/siteTrust';
import { redactText } from '../utils/pageContent';
import { featureOn } from './secureBrowsing';
import { findOpenEmailRoot, providerHeader, attachmentNames } from './webmailProviders';

interface OpenEmail {
  key: string;
  /** The panel goes right before this element. */
  anchor: Element;
  senderName: string;
  senderEmail: string;
  replyTo: string | null;
  subject: string;
  links: { text: string; href: string }[];
  attachments: string[];
  bodyText: string;
}

interface AiResult {
  verdict: 'phishing' | 'scam' | 'suspicious' | 'legit' | 'unavailable';
  risk_score?: number;
  title?: string;
  message?: string;
  impersonated_brand?: string;
  sender_domain?: string;
  sender_matches_brand?: boolean;
  red_flags?: string[];
  links?: { index: number; host: string; reason: string }[];
  reason?: string;
}

const EMAIL_RE = /([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/;

const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}


function textOf(el: Element | null | undefined): string {
  return ((el as HTMLElement | null)?.innerText || el?.textContent || '').trim();
}

/** Text without XoraPass's own inline badges (they must not change the email's identity). */
function cleanText(el: Element): string {
  const clone = el.cloneNode(true) as Element;
  clone.querySelectorAll('[data-xorapass-badge], [data-xorapass-email-insight]').forEach((b) => b.remove());
  return (clone.textContent || '').replace(/\s+/g, ' ').trim();
}

/** Best-effort extraction of the email currently open in the webmail. */
export function extractOpenEmail(host: string): OpenEmail | null {
  const r = findOpenEmailRoot(host);
  if (!r) return null;
  const { container, root } = r;
  const h = providerHeader(host, container);
  let senderEmail = (h.senderEmail || '').trim();
  let senderName = (h.senderName || '').trim();
  const subjectFromProvider = (h.subject || '').trim();

  if (!senderEmail) {
    // Generic: an element carrying the address in an attribute, else the
    // header text above the body.
    const attrEl = container.querySelector('[email], [title*="@"], [aria-label*="@"]');
    const attr = attrEl?.getAttribute('email') || attrEl?.getAttribute('title') || attrEl?.getAttribute('aria-label') || '';
    senderEmail = attr.match(EMAIL_RE)?.[1] || '';
    if (senderEmail) {
      senderName = senderName || textOf(attrEl).replace(EMAIL_RE, '').replace(/[<>]/g, '').trim();
    } else {
      const head = textOf(container).split(cleanText(root).slice(0, 40))[0] || '';
      senderEmail = head.match(EMAIL_RE)?.[1] || '';
      senderName = senderName || head.split(/[<\n]/)[0]?.trim() || '';
    }
  }
  const doc = container.ownerDocument || document;
  const subject =
    subjectFromProvider ||
    textOf(container.querySelector('h1, h2, [role="heading"]')) ||
    textOf(doc.querySelector('[role="main"] [role="heading"][aria-level="2"], h1')) ||
    '';

  const links = Array.from(root.querySelectorAll('a[href]'))
    .map((a) => ({ text: cleanText(a).slice(0, 200), href: (a as HTMLAnchorElement).href }))
    .filter((l) => /^https?:/i.test(l.href))
    .slice(0, 20);
  const attachments = attachmentNames(host)
    .map(({ el, name }) => name || cleanText(el))
    .filter(Boolean)
    .slice(0, 10);
  const bodyText = cleanText(root);
  const replyTo = findReplyTo(textOf(container).slice(0, 4000));
  const key = hash(`${senderEmail}|${subject}|${bodyText.slice(0, 300)}`);
  return {
    key,
    anchor: r.anchor,
    senderName: senderName.slice(0, 120),
    senderEmail: senderEmail.toLowerCase(),
    replyTo,
    subject: subject.slice(0, 300),
    links,
    attachments,
    bodyText,
  };
}

// ── Panel ───────────────────────────────────────────────────────────────────

const CSS = `
:host { all: initial; display: block; margin: 0 0 10px; font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a; }
.card { border: 1px solid #e2e8f0; border-radius: 12px; background: #fff; overflow: hidden; }
.card.danger { border-color: #fecaca; } .card.caution { border-color: #fde68a; }
.bar { display: flex; align-items: center; gap: 8px; padding: 8px 10px; }
.logo { width: 16px; height: 16px; flex: none; }
.summary { flex: 1; min-width: 0; font-weight: 600; }
.summary.danger { color: #b42318; } .summary.caution { color: #8a5300; } .summary.ok { color: #0f766e; }
button { font: 600 12px system-ui, sans-serif; border-radius: 8px; padding: 5px 10px; cursor: pointer; border: 1px solid #cbd5e1; background: #fff; color: #0f172a; }
button.primary { background: #0f172a; color: #fff; border-color: #0f172a; }
button:disabled { opacity: .55; cursor: default; }
.details { border-top: 1px solid #f1f5f9; padding: 8px 12px 10px; display: grid; gap: 6px; }
.row { display: grid; grid-template-columns: 74px 1fr; gap: 8px; }
.k { color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; padding-top: 2px; }
.v { word-break: break-word; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
ul { margin: 0; padding-left: 16px; } li { margin: 2px 0; }
.bad { color: #b42318; } .warn { color: #8a5300; } .muted { color: #64748b; font-size: 11px; }
.ai { border-radius: 10px; padding: 8px 10px; background: #f8fafc; }
.ai.danger { background: #fef2f2; } .ai.caution { background: #fffbeb; } .ai.ok { background: #f0fdfa; }
.ai h4 { margin: 0 0 2px; font-size: 13px; }
a { color: inherit; }
`;

let current: { key: string; host: HTMLElement; root: ShadowRoot } | null = null;
const autoRan = new Set<string>();

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function payloadFor(m: OpenEmail, local: EmailLocalSummary) {
  return {
    sender_name: redactText(m.senderName, 120),
    sender_email: m.senderEmail.slice(0, 254),
    reply_to: (m.replyTo || '').slice(0, 254),
    subject: redactText(m.subject, 300),
    links: m.links.map((l) => ({ text: redactText(l.text, 120), href: l.href.split(/[?#]/)[0].slice(0, 2048) })),
    attachments: m.attachments.map((a) => a.slice(0, 120)),
    body_excerpt: redactText(m.bodyText, 1500),
    local_flags: local.flags.slice(0, 12),
  };
}

function render(m: OpenEmail, local: EmailLocalSummary, ai: AiResult | null, busy: boolean, aiAllowed: boolean): void {
  if (!current) return;
  const root = current.root;
  root.innerHTML = '';
  const style = el('style');
  style.textContent = CSS;
  root.appendChild(style);

  const aiBad = ai && (ai.verdict === 'phishing' || ai.verdict === 'scam');
  const aiWarn = ai && ai.verdict === 'suspicious';
  const level = aiBad || local.danger ? 'danger' : aiWarn || local.cautions > 0 ? 'caution' : 'ok';
  const card = el('div', `card ${level === 'ok' ? '' : level}`);
  const bar = el('div', 'bar');
  const logo = el('img', 'logo');
  logo.src = browser.runtime.getURL('icons/icon16.png');
  logo.alt = 'XoraPass';
  bar.appendChild(logo);
  const n = local.findings.length;
  const summary =
    ai && ai.verdict !== 'unavailable'
      ? aiBad
        ? ai.verdict === 'phishing'
          ? 'Likely phishing email — don\'t click its links'
          : 'Likely scam email — don\'t reply or pay'
        : aiWarn
          ? 'Suspicious email — check carefully'
          : n
            ? `AI found no scam, but ${n} thing${n === 1 ? '' : 's'} to check`
            : 'AI found no signs of a scam'
      : local.danger
        ? `XoraPass found ${n} warning${n === 1 ? '' : 's'} on this email`
        : n
          ? `${n} thing${n === 1 ? '' : 's'} to check on this email`
          : 'XoraPass email check: nothing suspicious found';
  bar.appendChild(el('div', `summary ${level}`, summary));
  const toggle = el('button', '', 'Details');
  bar.appendChild(toggle);
  const blocked = ['quota', 'daily_limit', 'budget', 'not_available'];
  const retryable = !!ai && ai.verdict === 'unavailable' && !blocked.includes(ai.reason || '');
  if (aiAllowed && (!ai || retryable)) {
    const btn = el('button', 'primary', busy ? 'Analyzing…' : retryable && ai?.reason !== 'auto_limit' ? 'Retry AI analysis' : 'Analyze with AI');
    btn.disabled = busy;
    btn.title = 'Uses 1 AI check';
    btn.addEventListener('click', () => void runAi(m, local, 'button'));
    bar.appendChild(btn);
  }
  card.appendChild(bar);

  const details = el('div', 'details');
  details.style.display = level === 'ok' && !ai ? 'none' : 'grid';
  toggle.addEventListener('click', () => {
    details.style.display = details.style.display === 'none' ? 'grid' : 'none';
  });

  if (ai && ai.verdict !== 'unavailable' && (aiBad || aiWarn)) {
    const box = el('div', `ai ${aiBad ? 'danger' : 'caution'}`);
    box.appendChild(el('h4', aiBad ? 'bad' : 'warn', ai.title || 'Suspicious email'));
    if (ai.message) box.appendChild(el('div', '', ai.message));
    if (ai.red_flags?.length) {
      const ul = el('ul');
      for (const f of ai.red_flags) ul.appendChild(el('li', '', f));
      box.appendChild(ul);
    }
    details.appendChild(box);
  } else if (ai?.verdict === 'unavailable' && ai.reason && AI_LIMIT_TEXT[ai.reason]) {
    details.appendChild(el('div', 'muted', AI_LIMIT_TEXT[ai.reason]));
  }

  const row = (k: string, v: Node | string) => {
    const r = el('div', 'row');
    r.appendChild(el('div', 'k', k));
    const vv = el('div', 'v');
    if (typeof v === 'string') vv.textContent = v;
    else vv.appendChild(v);
    r.appendChild(vv);
    details.appendChild(r);
  };

  const from = el('span');
  from.appendChild(el('span', '', m.senderName ? `${m.senderName} ` : ''));
  from.appendChild(el('span', 'mono', m.senderEmail ? `<${m.senderEmail}>` : 'address not found'));
  if (ai?.impersonated_brand && ai.sender_matches_brand === false) {
    from.appendChild(el('div', 'bad', `Pretends to be ${cap(ai.impersonated_brand)}, but sent from ${ai.sender_domain || 'another domain'}`));
  } else if (local.claimedBrand && local.flags.includes('sender_brand_mismatch')) {
    from.appendChild(el('div', 'bad', `Name says ${cap(local.claimedBrand)}, but sent from ${local.senderDomain || 'another domain'}`));
  }
  row('From', from);
  if (m.replyTo && local.flags.includes('reply_to_mismatch')) row('Reply-To', el('span', 'warn', m.replyTo));
  if (m.subject) row('Subject', m.subject);

  const aiLinks = new Map((ai?.links || []).map((l) => [l.index, l.reason] as const));
  if (m.links.length) {
    const ul = el('ul');
    const seen = new Set<string>();
    m.links.forEach((l, i) => {
      const dest = extractHostname(unwrapLink(l.href).url) || l.href;
      const why = aiLinks.get(i);
      if (seen.has(dest) && !why) return;
      seen.add(dest);
      const li = el('li', why ? 'bad' : '');
      li.appendChild(el('span', 'mono', dest));
      if (why) li.appendChild(el('span', '', ` — ${why}`));
      ul.appendChild(li);
    });
    row(`Links (${seen.size})`, ul);
  }
  if (local.findings.length) {
    const ul = el('ul');
    for (const f of local.findings.slice(0, 8)) ul.appendChild(el('li', f.level === 'danger' ? 'bad' : 'warn', f.reasons.join(' · ')));
    row('Checks', ul);
  }
  if (ai && ai.verdict !== 'unavailable') {
    details.appendChild(
      el('div', 'muted', 'AI analysis (OpenAI): sender, subject, link addresses and a redacted excerpt were checked. Nothing is stored.')
    );
  } else if (aiAllowed) {
    details.appendChild(el('div', 'muted', 'Checked on your device. "Analyze with AI" sends the sender, subject, link addresses and a redacted excerpt — nothing is stored.'));
  }
  card.appendChild(details);
  root.appendChild(card);
}

/** Why an AI check didn't run (the on-device checks above still apply). */
const AI_LIMIT_TEXT: Record<string, string> = {
  quota: 'You have used this month\'s AI checks. Add more from the XoraPass popup, or wait for the monthly reset. On-device checks still run.',
  daily_limit: 'Daily AI check limit reached. It resets at midnight UTC. On-device checks still run.',
  budget: 'AI checks are paused for today. On-device checks still run.',
};

/** trigger: 'auto' when XoraPass ran it on its own (free, fair-use limit),
 *  'button' when the user asked (uses 1 AI check). */
async function runAi(m: OpenEmail, local: EmailLocalSummary, trigger: 'auto' | 'button'): Promise<void> {
  if (!current || current.key !== m.key) return;
  render(m, local, null, true, true);
  const res = (await browser.runtime
    .sendMessage({ type: 'SHIELD_EMAIL_SCAN', payload: { email: payloadFor(m, local), trigger } })
    .catch(() => null)) as AiResult | null;
  if (!current || current.key !== m.key) return;
  render(m, local, res || { verdict: 'unavailable' }, false, true);
}

/** Called (throttled) whenever the webmail DOM changes. */
export function updateEmailInsight(host: string): void {
  const m = extractOpenEmail(host);
  if (!m) {
    if (current && !current.host.isConnected) current = null;
    return;
  }
  if (current && current.key === m.key && current.host.isConnected) return;
  if (current && current.key !== m.key) current.host.remove();

  const hostEl = document.createElement('div');
  hostEl.setAttribute('data-xorapass-email-insight', '1');
  const root = hostEl.attachShadow({ mode: 'closed' });
  m.anchor.parentElement?.insertBefore(hostEl, m.anchor);
  current = { key: m.key, host: hostEl, root };

  const local = summarizeEmailLocal({
    sender: m.senderName ? `${m.senderName} <${m.senderEmail}>` : m.senderEmail,
    replyTo: m.replyTo,
    links: m.links,
    attachments: m.attachments,
  });
  const aiAllowed = featureOn('email_ai');
  render(m, local, null, false, aiAllowed);
  // Auto: only when the device already found red flags; once per email.
  if (aiAllowed && (local.danger || local.cautions >= 2) && !autoRan.has(m.key)) {
    autoRan.add(m.key);
    void runAi(m, local, 'auto');
  }
}
