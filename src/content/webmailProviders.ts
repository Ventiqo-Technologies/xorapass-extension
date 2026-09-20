// Where the OPEN email lives in each supported webmail.
//
// Verified against source: Proton Mail (github.com/ProtonMail/WebClients —
// message body is a same-origin sandboxed iframe, data-testid
// "content-iframe"). Gmail, Outlook, Yahoo/AOL and Zoho use known selectors.
// iCloud Mail, Fastmail, GMX / Mail.com and Yandex use a generic finder
// (message-body-like elements and same-origin frames) — best effort; verify
// in a real inbox before widening the rollout.

export interface EmailRoot {
  /** Element the panel is inserted before (in its own document). */
  anchor: Element;
  /** Element whose links / text are the email body (may be in an iframe). */
  root: Element;
  /** Header container to look for sender / subject in. */
  container: Element;
}

export interface HeaderInfo {
  senderName: string;
  senderEmail: string;
  subject: string;
}

type Provider = {
  test: (host: string) => boolean;
  body?: string;
  frame?: string;
  attachments?: string;
  container?: string;
  header?: (container: Element, doc: Document) => Partial<HeaderInfo>;
  generic?: boolean;
};

const txt = (el: Element | null | undefined) => ((el as HTMLElement | null)?.innerText || el?.textContent || '').trim();

const GENERIC_BODY =
  '[class*="message-body" i], [class*="messagebody" i], [class*="mail-body" i], [class*="mailbody" i], [class*="message__body" i], [class*="MessageBody"], [data-testid*="message-body" i], [role="document"]';

const PROVIDERS: Provider[] = [
  {
    test: (h) => h === 'mail.google.com',
    body: '.a3s',
    attachments: '.aV3, .aQA span[title]',
    container: '.adn, .gs',
    header: (c, doc) => {
      const s = c.querySelector('span.gD[email], span[email]');
      return { senderEmail: s?.getAttribute('email') || '', senderName: s?.getAttribute('name') || txt(s), subject: txt(doc.querySelector('h2.hP')) };
    },
  },
  {
    test: (h) => h.includes('outlook.') || h === 'outlook.cloud.microsoft',
    body: '[aria-label="Message body"], [role="document"].allowTextSelection, div[id^="UniqueMessageBody"]',
    attachments: '[data-testid="AttachmentCard"] [title]',
    container: '[role="region"], [role="main"]',
  },
  {
    test: (h) => h === 'mail.yahoo.com' || h.endsWith('.mail.yahoo.com') || h === 'mail.aol.com',
    body: '[data-test-id="message-view-body-content"]',
    attachments: '[data-test-id="attachment-name"]',
    container: '[data-test-id="message-view"], [role="main"]',
    header: (_c, doc) => ({ subject: txt(doc.querySelector('[data-test-id="message-group-subject-text"]')) }),
  },
  {
    test: (h) => h.startsWith('mail.zoho.'),
    body: '.zmMailContent, .zmPVContent',
    attachments: '.zmAttName, .SC_att_name',
    header: (_c, doc) => ({ subject: txt(doc.querySelector('.zmSubject, [class*="subject" i]')) }),
  },
  {
    test: (h) => h === 'mail.proton.me' || h === 'mail.protonmail.com',
    body: '[data-testid="message-content:body"]',
    frame: 'iframe[data-testid="content-iframe"]',
    attachments: '[data-testid^="attachment-item:"][data-testid$="--primary-action"]',
    container: '[data-testid^="message-view-"]',
    header: (c, doc) => {
      const s = c.querySelector('[data-testid="recipients:sender"]');
      return {
        senderEmail: txt(s?.querySelector('[data-testid="recipient-address"]')).replace(/[<>]/g, ''),
        senderName: txt(s?.querySelector('[data-testid="recipient-label"]')),
        subject: txt(doc.querySelector('[data-testid="conversation-header:subject"]')),
      };
    },
  },
  // Generic finder (layouts not verified against source).
  { test: (h) => h === 'www.icloud.com', generic: true },
  { test: (h) => /(^|\.)fastmail\.com$/.test(h), generic: true },
  { test: (h) => /^(navigator|3c)(-[a-z]+)?\.(gmx\.(net|com|de|at|ch|fr|es|co\.uk)|mail\.com)$/.test(h), generic: true },
  { test: (h) => /^mail\.yandex\.(com|ru|com\.tr|kz|by)$/.test(h), generic: true },
];

function providerFor(host: string): Provider | undefined {
  return PROVIDERS.find((p) => p.test(host.toLowerCase()));
}

function visible(el: Element): boolean {
  const r = (el as HTMLElement).getBoundingClientRect?.();
  return !!r && r.width > 0 && r.height > 0;
}

function sameOriginDoc(frame: Element): Document | null {
  try {
    const d = (frame as HTMLIFrameElement).contentDocument;
    return d && d.body ? d : null;
  } catch {
    return null;
  }
}

function genericRoots(doc: Document, depth: number, out: EmailRoot[]): void {
  for (const el of Array.from(doc.querySelectorAll(GENERIC_BODY)).slice(0, 30)) {
    if (!visible(el) || txt(el).length < 40) continue;
    // Skip nested matches (keep the outermost body).
    if (out.some((r) => r.root.contains(el))) continue;
    out.push({ anchor: el, root: el, container: el.closest('[role="main"], [role="region"], [role="article"], main, article') || el.parentElement || el });
  }
  if (depth >= 2) return;
  for (const f of Array.from(doc.querySelectorAll('iframe')).slice(0, 10)) {
    if (!visible(f)) continue;
    const d = sameOriginDoc(f);
    if (!d) continue;
    const before = out.length;
    genericRoots(d, depth + 1, out);
    if (out.length === before && txt(d.body).length >= 40 && d.querySelector('a[href]')) {
      out.push({ anchor: f, root: d.body, container: f.closest('[role="main"], [role="region"], main, article') || f.parentElement || f });
    }
  }
}

/** All message bodies currently shown (for link badges). */
export function findEmailRoots(host: string): EmailRoot[] {
  const p = providerFor(host);
  if (!p) return [];
  const out: EmailRoot[] = [];
  if (p.generic) {
    genericRoots(document, 0, out);
    return out;
  }
  for (const el of Array.from(document.querySelectorAll(p.body!)).slice(0, 20)) {
    if (!visible(el)) continue;
    const container = (p.container && el.closest(p.container)) || el.closest('[role="main"], [role="region"], [role="article"]') || el.parentElement || el;
    if (p.frame) {
      const f = el.querySelector(p.frame);
      const d = f ? sameOriginDoc(f) : null;
      if (d) out.push({ anchor: el, root: d.body, container });
      continue;
    }
    out.push({ anchor: el, root: el, container });
  }
  return out;
}

/** The email the user is most likely reading (last visible / largest). */
export function findOpenEmailRoot(host: string): EmailRoot | null {
  const roots = findEmailRoots(host);
  if (!roots.length) return null;
  if (providerFor(host)?.generic) {
    return roots.reduce((a, b) => (txt(b.root).length > txt(a.root).length ? b : a));
  }
  return roots[roots.length - 1];
}

export function providerHeader(host: string, container: Element): Partial<HeaderInfo> {
  const p = providerFor(host);
  try {
    return p?.header ? p.header(container, container.ownerDocument || document) : {};
  } catch {
    return {};
  }
}

/** Attachment names (not contents). */
export function attachmentNames(host: string): { el: Element; name: string }[] {
  const p = providerFor(host);
  if (!p?.attachments) return [];
  return Array.from(document.querySelectorAll(p.attachments))
    .slice(0, 50)
    .map((el) => {
      const id = el.getAttribute('data-testid') || '';
      const fromId = id.startsWith('attachment-item:') ? id.slice('attachment-item:'.length).replace(/--primary-action$/, '') : '';
      return { el, name: (fromId || el.getAttribute('title') || '').trim() };
    });
}
