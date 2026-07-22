import { describe, it, expect } from 'vitest';
import {
  looksLikeUsername,
  looksLikeNewPassword,
  computeIconPosition,
  computeTrailingOffset,
  computeDropdownPosition,
  isRectVisible,
} from './fieldHeuristics';

describe('looksLikeUsername', () => {
  it('accepts an explicit autocomplete token regardless of name', () => {
    expect(looksLikeUsername({ type: 'text', autocomplete: 'username', name: 'q' })).toBe(true);
    expect(looksLikeUsername({ type: 'text', autocomplete: 'email', name: 'zzz' })).toBe(true);
  });

  it('accepts email inputs and username-ish names', () => {
    expect(looksLikeUsername({ type: 'email' })).toBe(true);
    expect(looksLikeUsername({ type: 'text', name: 'user_login' })).toBe(true);
    expect(looksLikeUsername({ type: 'text', id: 'accountEmail' })).toBe(true);
    expect(looksLikeUsername({ type: 'tel', placeholder: 'Mobile number' })).toBe(true);
    expect(looksLikeUsername({ type: 'text', ariaLabel: 'Your email address' })).toBe(true);
  });

  it('rejects password, hidden and submit inputs outright', () => {
    expect(looksLikeUsername({ type: 'password', name: 'user' })).toBe(false);
    expect(looksLikeUsername({ type: 'hidden', name: 'user' })).toBe(false);
    expect(looksLikeUsername({ type: 'submit', name: 'login' })).toBe(false);
  });

  it('rejects search and one-time-code fields that mention user/login', () => {
    expect(looksLikeUsername({ type: 'text', name: 'user_search' })).toBe(false);
    expect(looksLikeUsername({ type: 'text', id: 'login-otp' })).toBe(false);
    expect(looksLikeUsername({ type: 'text', name: 'account', placeholder: 'Promo code' })).toBe(false);
  });

  it('treats autocomplete=off and new-password as disqualifying', () => {
    expect(looksLikeUsername({ type: 'text', autocomplete: 'off', name: 'username' })).toBe(false);
    expect(looksLikeUsername({ type: 'text', autocomplete: 'new-password', name: 'email' })).toBe(false);
  });

  it('rejects unrelated text inputs', () => {
    expect(looksLikeUsername({ type: 'text', name: 'street_address' })).toBe(false);
    expect(looksLikeUsername({ type: 'checkbox', name: 'email' })).toBe(false);
    expect(looksLikeUsername({})).toBe(false);
  });
});

describe('looksLikeNewPassword', () => {
  it('trusts the autocomplete token in both directions', () => {
    expect(looksLikeNewPassword({ autocomplete: 'new-password' })).toBe(true);
    // current-password wins even on a page with a confirm field.
    expect(looksLikeNewPassword({ autocomplete: 'current-password', name: 'confirm' }, true)).toBe(false);
  });

  it('recognises sign-up and confirm wording', () => {
    expect(looksLikeNewPassword({ name: 'new_password' })).toBe(true);
    expect(looksLikeNewPassword({ id: 'confirmPassword' })).toBe(true);
    expect(looksLikeNewPassword({ placeholder: 'Repeat password' })).toBe(true);
    expect(looksLikeNewPassword({ ariaLabel: 'Create a password' })).toBe(true);
  });

  it('treats a second password field as a sign-up signal', () => {
    expect(looksLikeNewPassword({ name: 'password' }, true)).toBe(true);
    expect(looksLikeNewPassword({ name: 'password' }, false)).toBe(false);
  });

  it('leaves an ordinary login password alone', () => {
    expect(looksLikeNewPassword({ name: 'password', id: 'login-pw' })).toBe(false);
    expect(looksLikeNewPassword({ autocomplete: 'current-password' })).toBe(false);
  });
});

describe('computeIconPosition', () => {
  it('sits inside the right edge and vertically centred', () => {
    const pos = computeIconPosition({ top: 100, left: 50, width: 200, height: 40 }, 20, 8);
    // right edge 250 - 20 icon - 8 padding
    expect(pos.left).toBe(222);
    // 100 + 20 (half height) - 10 (half icon)
    expect(pos.top).toBe(110);
  });
});

describe('computeTrailingOffset', () => {
  // A 300px-wide field at x=50, 40px tall, icon 20px, default padding 8.
  const field = { top: 100, left: 50, width: 300, height: 40 };

  it('is zero when nothing sits in the icon slot', () => {
    expect(computeTrailingOffset(field, [], 20)).toBe(0);
    // A control on the far left never collides with the trailing icon.
    const leftControl = { top: 108, left: 54, width: 24, height: 24 };
    expect(computeTrailingOffset(field, [leftControl], 20)).toBe(0);
  });

  it('shifts left of a reveal-password eye at the right edge', () => {
    // Eye button occupying the field's right ~28px: left 314, right 338.
    const eye = { top: 108, left: 314, width: 24, height: 24 };
    const offset = computeTrailingOffset(field, [eye], 20);
    // iconRight = 50+300-8 = 342; offset = 342 - 314 + 6 = 34.
    expect(offset).toBe(34);
    // With that offset the icon now clears the eye's left edge.
    const pos = computeIconPosition(field, 20, 8, offset);
    expect(pos.left + 20).toBeLessThanOrEqual(eye.left);
  });

  it('clears the leftmost of two stacked trailing controls', () => {
    const clear = { top: 110, left: 288, width: 20, height: 20 };
    const eye = { top: 110, left: 314, width: 20, height: 20 };
    const offset = computeTrailingOffset(field, [clear, eye], 20);
    // Must move left of `clear` (the leftmost): 342 - 288 + 6 = 60.
    expect(offset).toBe(60);
  });

  it('ignores controls off the field centre line', () => {
    // A control well above the field's vertical centre is unrelated.
    const above = { top: 40, left: 314, width: 24, height: 20 };
    expect(computeTrailingOffset(field, [above], 20)).toBe(0);
  });

  it('ignores wide elements that are not adornments', () => {
    // The input's own overlay or a full-width child should not count.
    const wide = { top: 100, left: 50, width: 300, height: 40 };
    expect(computeTrailingOffset(field, [wide], 20)).toBe(0);
  });

  it('never pushes the icon past the field padding', () => {
    // A wide-but-valid trailing control whose left edge sits far in; the offset
    // must stay clamped to the field's usable width.
    const wideTrailing = { top: 108, left: 90, width: 180, height: 24 };
    const offset = computeTrailingOffset(field, [wideTrailing], 20);
    expect(offset).toBeLessThanOrEqual(300 - 20 - 16);
    expect(offset).toBeGreaterThan(0);
  });
});

describe('computeDropdownPosition', () => {
  const viewport = { width: 1000, height: 800 };
  const menu = { width: 260, height: 200 };

  it('opens below the field when there is room', () => {
    const pos = computeDropdownPosition({ top: 100, left: 50, width: 200, height: 40 }, menu, viewport);
    expect(pos.flipped).toBe(false);
    expect(pos.top).toBe(146); // 100 + 40 + 6
    expect(pos.left).toBe(50);
  });

  it('flips above when the menu would overflow the bottom', () => {
    const pos = computeDropdownPosition({ top: 700, left: 50, width: 200, height: 40 }, menu, viewport);
    expect(pos.flipped).toBe(true);
    expect(pos.top).toBe(494); // 700 - 200 - 6
  });

  it('stays below when neither side fits, rather than going off-screen', () => {
    const tall = { width: 260, height: 780 };
    const pos = computeDropdownPosition({ top: 400, left: 50, width: 200, height: 40 }, tall, viewport);
    expect(pos.flipped).toBe(false);
  });

  it('clamps horizontally so the menu never leaves the viewport', () => {
    const pos = computeDropdownPosition({ top: 100, left: 960, width: 40, height: 40 }, menu, viewport);
    expect(pos.left).toBe(736); // 1000 - 260 - 4
    expect(pos.left + menu.width).toBeLessThanOrEqual(viewport.width);
  });

  it('clamps negative left values to a small margin', () => {
    const pos = computeDropdownPosition({ top: 100, left: -80, width: 200, height: 40 }, menu, viewport);
    expect(pos.left).toBe(4);
  });
});

describe('isRectVisible', () => {
  const viewport = { width: 1000, height: 800 };

  it('accepts a normal on-screen field', () => {
    expect(isRectVisible({ top: 100, left: 50, width: 200, height: 40 }, viewport)).toBe(true);
  });

  it('rejects collapsed (CSS-hidden) rects', () => {
    expect(isRectVisible({ top: 100, left: 50, width: 0, height: 0 }, viewport)).toBe(false);
    expect(isRectVisible({ top: 100, left: 50, width: 200, height: 4 }, viewport)).toBe(false);
  });

  it('rejects fields scrolled out of view', () => {
    expect(isRectVisible({ top: -200, left: 50, width: 200, height: 40 }, viewport)).toBe(false);
    expect(isRectVisible({ top: 900, left: 50, width: 200, height: 40 }, viewport)).toBe(false);
    expect(isRectVisible({ top: 100, left: 1200, width: 200, height: 40 }, viewport)).toBe(false);
  });
});
