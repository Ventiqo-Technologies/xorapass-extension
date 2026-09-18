// XoraPass Shield — page-behaviour hooks (MAIN world, document_start).
//
// Runs in the PAGE's JavaScript world (manifest "world": "MAIN") before any
// page script, so it can see what the page actually does:
//
//   • ClickFix / fake CAPTCHA — a command (PowerShell, mshta, curl | sh …)
//     written to the clipboard is BLOCKED here, synchronously, before it
//     reaches the clipboard.
//   • Crypto wallet drainers — dangerous wallet requests (blind eth_sign,
//     token permits, unlimited approvals, setApprovalForAll) are held until
//     the user answers XoraPass's warning (fails open after 60 s).
//   • Fake tech-support lock-in — full screen, keyboard/pointer lock,
//     beforeunload traps, back-button flooding, autoplaying audio.
//   • Notification-permission requests and browser fingerprinting.
//
// It has no extension APIs; it reports to the isolated-world Shield script
// (shieldNav.ts) with window.postMessage. LIMITATION: messages on `window`
// are visible to the page, so a page written specifically to evade XoraPass
// can observe them (e.g. forge a wallet "allow"). The warnings themselves are
// raised by the isolated world and can't be suppressed that way, and the
// wallet's own confirmation remains.
//
// Built as its own self-contained IIFE (vite --mode pagehooks); NO imports
// other than pure utilities.

import { shouldBlockClipboardWrite, classifyWalletRequest } from '../utils/scamBehavior';

(() => {
  const TAG = '__xoraShield';
  const w = window as any;
  if (w[TAG + 'Hooked']) return;
  Object.defineProperty(w, TAG + 'Hooked', { value: true });

  const post = (kind: string, data: Record<string, unknown> = {}) => {
    try {
      window.postMessage({ [TAG]: 'v1', kind, ...data }, '*');
    } catch {
      /* ignore */
    }
  };
  const activated = () => !!(navigator as any).userActivation?.hasBeenActive;
  const once = new Set<string>();
  const report = (kind: string, data: Record<string, unknown> = {}) => {
    if (once.has(kind)) return;
    once.add(kind);
    post(kind, data);
  };

  // ── ClickFix: block malicious clipboard writes ──────────────────────────
  const blockedCommand = () => post('clickfix');
  const pageText = () => {
    try {
      return `${document.title}\n${(document.body?.innerText || '').slice(0, 8000)}`;
    } catch {
      return '';
    }
  };
  const isMaliciousClipboardCommand = (text: string) => shouldBlockClipboardWrite(text, pageText());

  try {
    const clip = navigator.clipboard as any;
    if (clip?.writeText) {
      const orig = clip.writeText.bind(clip);
      clip.writeText = function (text: string) {
        if (isMaliciousClipboardCommand(String(text))) {
          blockedCommand();
          return Promise.resolve();
        }
        return orig(text);
      };
    }
    if (clip?.write) {
      const origWrite = clip.write.bind(clip);
      clip.write = async function (items: any[]) {
        try {
          for (const item of items || []) {
            if (item?.types?.includes('text/plain')) {
              const text = await (await item.getType('text/plain')).text();
              if (isMaliciousClipboardCommand(text)) {
                blockedCommand();
                return;
              }
            }
          }
        } catch {
          /* fall through */
        }
        return origWrite(items);
      };
    }
  } catch {
    /* clipboard API unavailable */
  }

  try {
    const origSetData = DataTransfer.prototype.setData;
    DataTransfer.prototype.setData = function (format: string, data: string) {
      if (/text/i.test(format) && isMaliciousClipboardCommand(String(data))) {
        blockedCommand();
        return;
      }
      return origSetData.call(this, format, data);
    };
    const origExec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (this: Document, cmd: string, ...rest: any[]) {
      if (/^(copy|cut)$/i.test(String(cmd))) {
        const el = document.activeElement as HTMLInputElement | HTMLTextAreaElement | null;
        const selected =
          el && typeof el.value === 'string' && el.selectionStart != null
            ? el.value.slice(el.selectionStart, el.selectionEnd ?? undefined)
            : String(window.getSelection?.() ?? '');
        if (isMaliciousClipboardCommand(selected)) {
          blockedCommand();
          return false;
        }
      }
      return origExec.call(this, cmd, ...(rest as [boolean?, string?]));
    } as typeof Document.prototype.execCommand;
  } catch {
    /* ignore */
  }

  // ── Wallet requests ─────────────────────────────────────────────────────
  const pending = new Map<string, (allow: boolean) => void>();
  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (ev.source !== window || !d || d.__xoraShieldReply !== 'v1' || typeof d.id !== 'string') return;
    const resolve = pending.get(d.id);
    if (resolve) {
      pending.delete(d.id);
      resolve(d.allow !== false);
    }
  });

  const askUser = (method: string, summary: string, level: string): Promise<boolean> =>
    new Promise((resolve) => {
      const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
      pending.set(id, resolve);
      post('wallet_check', { id, method, summary, level });
      setTimeout(() => {
        if (pending.delete(id)) resolve(true); // fail open: the wallet still asks
      }, 60_000);
    });

  const wrapped = new WeakSet<object>();
  const wrapProvider = (p: any) => {
    if (!p || typeof p !== 'object' || wrapped.has(p) || typeof p.request !== 'function') return;
    wrapped.add(p);
    const origRequest = p.request.bind(p);
    const guarded = async (args: any) => {
      const risk = classifyWalletRequest(args?.method, args?.params);
      if (risk.level) {
        const allow = await askUser(String(args?.method), risk.summary, risk.level);
        if (!allow) {
          const err: any = new Error('User rejected the request (blocked by XoraPass Shield).');
          err.code = 4001;
          throw err;
        }
      }
      return origRequest(args);
    };
    try {
      Object.defineProperty(p, 'request', { value: guarded, configurable: true, writable: true });
    } catch {
      try {
        p.request = guarded;
      } catch {
        /* frozen provider */
      }
    }
  };

  try {
    let current = w.ethereum;
    wrapProvider(current);
    Object.defineProperty(w, 'ethereum', {
      configurable: true,
      get: () => current,
      set: (v) => {
        current = v;
        wrapProvider(v);
      },
    });
  } catch {
    /* property not configurable */
  }
  window.addEventListener('eip6963:announceProvider', (ev: any) => wrapProvider(ev?.detail?.provider));

  // ── Lock-in / tech-support behaviours ──────────────────────────────────
  const hook = (proto: any, name: string, onCall: (self: any, args: any[]) => void) => {
    try {
      const orig = proto?.[name];
      if (typeof orig !== 'function') return;
      proto[name] = function (this: any, ...args: any[]) {
        try {
          onCall(this, args);
        } catch {
          /* never break the page */
        }
        return orig.apply(this, args);
      };
    } catch {
      /* ignore */
    }
  };

  hook(Element.prototype, 'requestFullscreen', () => report('fullscreen'));
  hook(Element.prototype, 'webkitRequestFullscreen', () => report('fullscreen'));
  hook(Element.prototype, 'requestPointerLock', () => report('pointer_lock'));
  try {
    const kb = (navigator as any).keyboard;
    if (kb?.lock) hook(Object.getPrototypeOf(kb), 'lock', () => report('keyboard_lock'));
  } catch {
    /* ignore */
  }

  hook(EventTarget.prototype, 'addEventListener', (self, args) => {
    if (self === window && args[0] === 'beforeunload') report('beforeunload');
  });
  try {
    const desc = Object.getOwnPropertyDescriptor(Window.prototype, 'onbeforeunload') ||
      Object.getOwnPropertyDescriptor(HTMLBodyElement.prototype, 'onbeforeunload');
    if (desc?.set) {
      Object.defineProperty(window, 'onbeforeunload', {
        configurable: true,
        get: () => desc.get?.call(window),
        set: (v) => {
          if (v) report('beforeunload');
          desc.set!.call(window, v);
        },
      });
    }
  } catch {
    /* ignore */
  }

  let pushes: number[] = [];
  hook(History.prototype, 'pushState', () => {
    const now = Date.now();
    pushes = pushes.filter((t) => now - t < 3000);
    pushes.push(now);
    if (pushes.length >= 10 && !activated()) report('history_flood');
  });

  hook(HTMLMediaElement.prototype, 'play', (self) => {
    if (!self.muted && self.volume > 0 && !activated()) report('autoplay_audio');
  });

  // ── Notification permission ────────────────────────────────────────────
  try {
    const N = (window as any).Notification;
    if (N?.requestPermission) {
      const orig = N.requestPermission.bind(N);
      N.requestPermission = (...args: any[]) => {
        post('notification_request', { activated: !!(navigator as any).userActivation?.isActive });
        return orig(...args);
      };
    }
  } catch {
    /* ignore */
  }

  // ── Fingerprinting ─────────────────────────────────────────────────────
  const fp = new Set<string>();
  const fonts = new Set<string>();
  const noteFp = (t: string) => {
    fp.add(t);
    if (fp.size >= 2) report('fingerprint', { techniques: Array.from(fp) });
  };
  const bigCanvas = (c: any) => !c || (c.width || 0) * (c.height || 0) <= 16 * 16 * 1000;
  hook(HTMLCanvasElement.prototype, 'toDataURL', (self) => bigCanvas(self) && noteFp('canvas'));
  hook(HTMLCanvasElement.prototype, 'toBlob', (self) => bigCanvas(self) && noteFp('canvas'));
  hook(CanvasRenderingContext2D.prototype, 'getImageData', () => noteFp('canvas'));
  hook(CanvasRenderingContext2D.prototype, 'measureText', (self) => {
    fonts.add(String(self.font));
    if (fonts.size > 30) noteFp('fonts');
  });
  const glParam = (_self: any, args: any[]) => {
    if (args[0] === 37445 || args[0] === 37446) noteFp('webgl');
  };
  if (typeof WebGLRenderingContext !== 'undefined') hook(WebGLRenderingContext.prototype, 'getParameter', glParam);
  if (typeof WebGL2RenderingContext !== 'undefined') hook(WebGL2RenderingContext.prototype, 'getParameter', glParam);
  try {
    const OAC = (window as any).OfflineAudioContext;
    if (OAC) {
      (window as any).OfflineAudioContext = new Proxy(OAC, {
        construct(target, args) {
          noteFp('audio');
          return Reflect.construct(target, args);
        },
      });
    }
  } catch {
    /* ignore */
  }
})();
