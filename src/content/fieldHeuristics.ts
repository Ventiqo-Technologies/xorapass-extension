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

const NEW_PASSWORD_HINT = /new|signup|sign-up|register|create|confirm|repeat|retype|verify/i;

/**
 * Whether a password field is being used to choose a *new* password (sign-up,
 * password change) rather than to enter an existing one. The autocomplete
 * token is authoritative when present — it is exactly what it exists for —
 * with name/id/placeholder hints as the fallback.
 *
 * `hasSibling` should be true when the page has more than one password field,
 * which on its own is a strong sign of a "password + confirm" pair.
 */
export function looksLikeNewPassword(attrs: FieldAttrs, hasSibling = false): boolean {
  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('new-password')) return true;
  if (ac.includes('current-password')) return false;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel]
    .filter(Boolean)
    .join(' ');

  if (NEW_PASSWORD_HINT.test(hints)) return true;
  return hasSibling;
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
 *
 * `offset` shifts the icon further left, to clear a control the site already
 * put at the right edge — most often a show/hide-password eye button.
 */
export function computeIconPosition(rect: Rect, iconSize: number, padding = 8, offset = 0): Point {
  return {
    left: rect.left + rect.width - iconSize - padding - offset,
    top: rect.top + rect.height / 2 - iconSize / 2,
  };
}

/**
 * How far left to shift the autofill icon so it does not sit on top of a
 * control the page already placed at the field's right edge (a reveal-password
 * eye, a clear button, a spinner). Given the field rect and the rects of nearby
 * candidate controls, returns the horizontal offset to pass to
 * computeIconPosition. Zero when the icon's default slot is clear.
 *
 * Kept pure — the DOM gathering of candidate rects lives in the overlay — so the
 * geometry can be unit tested without a browser.
 */
export function computeTrailingOffset(
  field: Rect,
  controls: Rect[],
  iconSize: number,
  padding = 8,
  gap = 6
): number {
  const base = field.left + field.width - padding; // the icon's right edge at offset 0
  const centerY = field.top + field.height / 2;
  // Only controls sitting in the field's right region are trailing adornments;
  // ignore anything spanning the left/centre (labels, the input itself).
  const rightZoneLeft = field.left + field.width - iconSize * 4;

  // Left edge of the leftmost trailing control. The icon is placed to the left
  // of the whole cluster rather than trying to nestle between controls, so two
  // stacked adornments (e.g. clear + eye) are both cleared in one shift.
  let clusterLeft = Infinity;
  for (const c of controls) {
    const cRight = c.left + c.width;
    if (c.width > field.width * 0.6) continue; // too wide to be an adornment
    if (c.height > field.height + 6) continue; // taller than the field
    if (centerY < c.top - 2 || centerY > c.top + c.height + 2) continue; // off the centre line
    if (cRight < rightZoneLeft) continue; // not near the right edge
    clusterLeft = Math.min(clusterLeft, c.left);
  }

  if (clusterLeft === Infinity) return 0; // nothing in the way

  const offset = base - (clusterLeft - gap);
  // Never push the icon past the field's left padding.
  const maxOffset = Math.max(0, field.width - iconSize - padding * 2);
  return Math.min(Math.max(0, offset), maxOffset);
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
