// Pure helpers backing the content script's field detection and overlay
// placement. Kept free of DOM access so they can be unit-tested in the plain
// `node` Vitest environment alongside the other src/utils suites.

/** The subset of input attributes the username heuristic looks at. */
export interface FieldAttrs {
  type?: string | null;
  autocomplete?: string | null;
  name?: string | null;
  id?: string | null;
  placeholder?: string | null;
  ariaLabel?: string | null;
}

const USERNAME_HINT = /user|email|login|account|phone|mobile|identifier/i;

// Fields that look username-ish by name but must never receive a username —
// checked before the positive hints so "search-user" style inputs stay excluded.
const NEGATIVE_HINT = /search|query|coupon|promo|captcha|otp|token|code|zip|postal/i;

/**
 * Heuristic for "is this the username/email input paired with a password
 * field?". Mirrors what mainstream password managers do: trust an explicit
 * autocomplete token first, then fall back to type plus name/id/label hints.
 */
export function looksLikeUsername(attrs: FieldAttrs): boolean {
  const type = (attrs.type || 'text').toLowerCase();
  if (type === 'password' || type === 'hidden' || type === 'submit') return false;

  const ac = (attrs.autocomplete || '').toLowerCase();
  // An explicit autocomplete token is authoritative in both directions.
  if (ac.includes('username') || ac.includes('email')) return true;
  if (ac === 'off' || ac === 'new-password') return false;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel]
    .filter(Boolean)
    .join(' ');

  if (NEGATIVE_HINT.test(hints)) return false;
  if (type === 'email') return true;
  if (type !== 'text' && type !== 'tel') return false;

  return USERNAME_HINT.test(hints);
}

/** Minimal rectangle shape — matches the fields we need from a DOMRect. */
export interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

export interface Point {
  left: number;
  top: number;
}

export interface Viewport {
  width: number;
  height: number;
}

/**
 * Places the autofill icon inside the input's right edge, vertically centred.
 * Coordinates are viewport-relative because the overlay host is position:fixed,
 * which is what lets us avoid reparenting the page's own input elements.
 */
export function computeIconPosition(rect: Rect, iconSize: number, padding = 8): Point {
  return {
    left: rect.left + rect.width - iconSize - padding,
    top: rect.top + rect.height / 2 - iconSize / 2,
  };
}

/**
 * Places the credential dropdown under the field, flipping above it when the
 * menu would overflow the bottom of the viewport, and clamping horizontally so
 * it never renders off-screen on narrow layouts.
 */
export function computeDropdownPosition(
  rect: Rect,
  menu: { width: number; height: number },
  viewport: Viewport,
  gap = 6
): Point & { flipped: boolean } {
  const belowTop = rect.top + rect.height + gap;
  const aboveTop = rect.top - menu.height - gap;

  // Flip only when there genuinely isn't room below but there is room above.
  const overflowsBelow = belowTop + menu.height > viewport.height;
  const fitsAbove = aboveTop >= 0;
  const flipped = overflowsBelow && fitsAbove;

  const top = flipped ? aboveTop : belowTop;
  const maxLeft = Math.max(0, viewport.width - menu.width - 4);
  const left = Math.min(Math.max(4, rect.left), maxLeft);

  return { left, top, flipped };
}

/**
 * True when a rect is large enough and inside the viewport to be worth
 * decorating. Zero-size rects mean the field is hidden by CSS.
 */
export function isRectVisible(rect: Rect, viewport: Viewport): boolean {
  if (rect.width < 24 || rect.height < 12) return false;
  if (rect.top + rect.height < 0 || rect.top > viewport.height) return false;
  if (rect.left + rect.width < 0 || rect.left > viewport.width) return false;
  return true;
}
