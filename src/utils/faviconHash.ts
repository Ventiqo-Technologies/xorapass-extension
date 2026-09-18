// Favicon impersonation, computed ON THE DEVICE.
//
// Phishing kits copy the real brand's favicon so the tab looks right. We take
// a 64-bit difference hash (dHash) of the page's own favicon and compare it
// with the hashes of commonly impersonated brands' real icons (bundled, see
// faviconBrands.ts). Only the matched brand NAME is sent to the server as a
// page signal — no image, no hash, no third-party icon service, and the
// server never connects to the suspect site.

// Of 64 bits. Measured on 41 popular non-brand icons: one letter-shaped icon
// came within 4 of a brand, so a match is only a SIGNAL — the server counts it
// strongly only when the page also names that brand (see domain_risk.go).
export const FAVICON_MATCH_MAX_DISTANCE = 4;

/**
 * dHash of RGBA pixels: 9x8 box-averaged luminance grid (transparent pixels
 * composited on white), one bit per horizontal neighbour comparison.
 * Returns 16 hex chars, or null for a flat (blank / single-colour) icon.
 */
export function dHashRGBA(data: Uint8ClampedArray | number[], w: number, h: number): string | null {
  if (w <= 0 || h <= 0 || data.length < w * h * 4) return null;
  const gray: number[][] = [];
  let min = Infinity;
  let max = -Infinity;
  for (let y = 0; y < 8; y++) {
    const row: number[] = [];
    for (let x = 0; x < 9; x++) {
      const x0 = Math.floor((x * w) / 9);
      let x1 = Math.floor(((x + 1) * w) / 9);
      const y0 = Math.floor((y * h) / 8);
      let y1 = Math.floor(((y + 1) * h) / 8);
      if (x1 <= x0) x1 = x0 + 1;
      if (y1 <= y0) y1 = y0 + 1;
      let sum = 0;
      let n = 0;
      for (let yy = y0; yy < y1 && yy < h; yy++) {
        for (let xx = x0; xx < x1 && xx < w; xx++) {
          const i = (yy * w + xx) * 4;
          const a = data[i + 3] / 255;
          const lum = (0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]) / 255;
          sum += lum * a + (1 - a);
          n++;
        }
      }
      const v = n ? sum / n : 1;
      row.push(v);
      if (v < min) min = v;
      if (v > max) max = v;
    }
    gray.push(row);
  }
  if (max - min < 0.04) return null;
  let hex = '';
  for (let y = 0; y < 8; y++) {
    let byte = 0;
    for (let x = 0; x < 8; x++) byte = (byte << 1) | (gray[y][x] > gray[y][x + 1] ? 1 : 0);
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

export function hammingHex(a: string, b: string): number {
  if (a.length !== 16 || b.length !== 16) return 64;
  let d = 0;
  for (let i = 0; i < 16; i += 2) {
    let x = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16);
    while (x) {
      d += x & 1;
      x >>= 1;
    }
  }
  return d;
}

export interface FaviconBrand {
  brand: string; // BrandLexicon token (server re-validates)
  domains: string[]; // registrable domains allowed to wear the icon
  hashes: string[];
}

/** Brand whose real icon this hash matches, unless pageDomain belongs to it. */
export function matchFaviconBrand(hash: string | null, pageDomain: string, brands: readonly FaviconBrand[]): string | null {
  if (!hash) return null;
  let best: { brand: string; d: number } | null = null;
  for (const b of brands) {
    if (b.domains.some((d) => pageDomain === d || pageDomain.endsWith(`.${d}`))) {
      // The page IS this brand (or a sibling domain it owns).
      if (b.hashes.some((h) => hammingHex(hash, h) <= FAVICON_MATCH_MAX_DISTANCE)) return null;
      continue;
    }
    for (const h of b.hashes) {
      const d = hammingHex(hash, h);
      if (d <= FAVICON_MATCH_MAX_DISTANCE && (!best || d < best.d)) best = { brand: b.brand, d };
    }
  }
  return best?.brand ?? null;
}

/** Draws a loaded image (≤256 px) and hashes it. Throws on a tainted canvas. */
export function hashImageElement(img: HTMLImageElement): string | null {
  let w = img.naturalWidth;
  let h = img.naturalHeight;
  if (!w || !h) return null;
  const scale = Math.min(1, 256 / Math.max(w, h));
  w = Math.max(1, Math.round(w * scale));
  h = Math.max(1, Math.round(h * scale));
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0, w, h);
  return dHashRGBA(ctx.getImageData(0, 0, w, h).data, w, h);
}

/** Loads an icon URL and hashes it; null on any failure or timeout. */
export function loadAndHashIcon(url: string, timeoutMs = 2000): Promise<string | null> {
  return new Promise((resolve) => {
    const img = new Image();
    const t = setTimeout(() => resolve(null), timeoutMs);
    img.onload = () => {
      clearTimeout(t);
      try {
        resolve(hashImageElement(img));
      } catch {
        resolve(null); // cross-origin redirect → tainted canvas
      }
    };
    img.onerror = () => {
      clearTimeout(t);
      resolve(null);
    };
    img.src = url;
  });
}
