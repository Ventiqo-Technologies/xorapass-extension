// URL canonicalization, lookup expressions and hash prefixes for the Shield
// blocklist — the same scheme as Google Safe Browsing / Web Risk, so our list
// and Google's can share one prefix set:
//
//   1. canonicalize the URL (lower-case host, resolve dot segments, collapse
//      slashes, drop the fragment, normalise percent-escapes, ...)
//   2. derive up to 5 host suffixes × 6 path prefixes ("expressions"),
//      e.g. "a.b.c/1/2.html?param=1", "a.b.c/1/2.html", "a.b.c/", "b.c/1/" ...
//   3. SHA-256 each expression; the first 4 bytes are the prefix looked up in
//      the downloaded list. Only on a prefix hit is the prefix (never the URL)
//      sent to the server to confirm the full hash.
//
// Pure; hashing uses WebCrypto (available in the service worker and in Node).

function fullyUnescape(s: string): string {
  let prev = s;
  for (let i = 0; i < 1024; i++) {
    const next = prev.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    if (next === prev) return next;
    prev = next;
  }
  return prev;
}

/**
 * Percent-escapes chars <= 0x20, >= 0x7f, '#' and '%' (upper-case hex).
 * After fullyUnescape, each %XX became one char in 0x00-0xFF standing for a
 * single BYTE, so those are re-escaped as that byte. Real non-Latin-1
 * characters (never produced by unescaping) are escaped as UTF-8.
 */
function escapeCanonical(s: string): string {
  let out = '';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (code <= 0x20 || code >= 0x7f || ch === '#' || ch === '%') {
      const bytes = code <= 0xff ? [code] : Array.from(new TextEncoder().encode(ch));
      for (const b of bytes) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
    } else {
      out += ch;
    }
  }
  return out;
}

/** Normalises an IPv4 host written as dotted decimal/hex/octal or one integer. */
function normalizeIPv4(host: string): string | null {
  const parts = host.split('.');
  if (parts.length === 0 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    if (p === '') return null;
    let n: number;
    if (/^0x[0-9a-f]*$/i.test(p)) n = parseInt(p.slice(2) || '0', 16);
    else if (/^0[0-7]+$/.test(p)) n = parseInt(p, 8);
    else if (/^\d+$/.test(p)) n = parseInt(p, 10);
    else return null;
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.pop()!;
  for (const n of nums) if (n > 255) return null;
  const rest = 4 - nums.length;
  if (last >= 2 ** (8 * rest)) return null;
  const tail: number[] = [];
  let v = last;
  for (let i = 0; i < rest; i++) {
    tail.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return [...nums, ...tail].join('.');
}

export interface CanonicalUrl {
  host: string;
  path: string; // starts with '/', escaped
  query: string | null; // without '?', escaped; null when absent
  isIp: boolean;
}

/**
 * Canonicalizes an http(s) URL per the Safe Browsing rules. Returns null for
 * anything that isn't an http(s) URL with a host.
 */
export function canonicalizeUrl(raw: string): CanonicalUrl | null {
  let s = (raw || '').trim().replace(/[\t\r\n]/g, '');
  const hashIdx = s.indexOf('#');
  if (hashIdx >= 0) s = s.slice(0, hashIdx);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // "javascript:", "mailto:", "data:" ... (but not "host:8080/path")
    if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s)) return null;
    s = 'http://' + s;
  }
  const m = s.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?]*)([^?]*)(\?.*)?$/i);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') return null;

  // Authority: drop userinfo and port.
  let authority = m[2];
  const at = authority.lastIndexOf('@');
  if (at >= 0) authority = authority.slice(at + 1);
  authority = authority.replace(/:\d*$/, '');

  let host = fullyUnescape(authority).toLowerCase();
  host = host.replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.');
  if (!host) return null;
  const ip = normalizeIPv4(host);
  const isIp = ip !== null;
  if (ip) host = ip;

  let path = fullyUnescape(m[3] || '/');
  if (!path.startsWith('/')) path = '/' + path;
  // Resolve dot segments and collapse repeated slashes.
  const segs: string[] = [];
  const endsWithSlash = /\/(\.{1,2})?$/.test(path);
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      segs.pop();
      continue;
    }
    segs.push(seg);
  }
  path = '/' + segs.join('/');
  if (endsWithSlash && segs.length > 0) path += '/';

  const rawQuery = m[4] !== undefined ? m[4].slice(1) : null;
  const query = rawQuery !== null ? escapeCanonical(fullyUnescape(rawQuery)) : null;

  return { host: escapeCanonical(host), path: escapeCanonical(path), query, isIp };
}

/** Host suffix variants: exact host + up to 4 formed from the last 5 labels. */
export function hostVariants(host: string, isIp: boolean): string[] {
  const out = [host];
  if (isIp) return out;
  const labels = host.split('.');
  const start = Math.max(1, labels.length - 5);
  for (let i = start; i <= labels.length - 2; i++) {
    const h = labels.slice(i).join('.');
    if (!out.includes(h)) out.push(h);
  }
  return out.slice(0, 5);
}

/** Path variants: exact path+query, exact path, and up to 4 root prefixes. */
export function pathVariants(path: string, query: string | null): string[] {
  const out: string[] = [];
  const add = (p: string) => {
    if (!out.includes(p)) out.push(p);
  };
  if (query !== null) add(`${path}?${query}`);
  add(path);
  const parts = path.split('/').filter(Boolean);
  // Directory components only: the last component is a file unless the path
  // ends with '/'.
  const dirs = path.endsWith('/') ? parts : parts.slice(0, -1);
  add('/');
  let acc = '/';
  for (let i = 0; i < dirs.length && out.length < 6; i++) {
    acc += dirs[i] + '/';
    // Root + at most 3 more directory prefixes (4 in total).
    if (i >= 3) break;
    add(acc);
  }
  return out.slice(0, 6);
}

/** All lookup expressions for a URL (≤ 30), most specific first. */
export function urlExpressions(url: string): string[] {
  const c = canonicalizeUrl(url);
  if (!c) return [];
  const out: string[] = [];
  for (const h of hostVariants(c.host, c.isIp)) {
    for (const p of pathVariants(c.path, c.query)) {
      out.push(h + p);
    }
  }
  return out;
}

export async function sha256Bytes(text: string): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return new Uint8Array(buf);
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function prefixOf(hash: Uint8Array): number {
  return ((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]) >>> 0;
}

export interface ExpressionHash {
  expression: string;
  fullHashHex: string;
  prefix: number;
}

export async function hashUrlExpressions(url: string): Promise<ExpressionHash[]> {
  const exprs = urlExpressions(url);
  return Promise.all(
    exprs.map(async (expression) => {
      const h = await sha256Bytes(expression);
      return { expression, fullHashHex: toHex(h), prefix: prefixOf(h) };
    })
  );
}
