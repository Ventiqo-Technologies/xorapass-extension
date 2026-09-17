import { describe, it, expect } from 'vitest';
import {
  looksLikeUsername,
  looksLikeNewPassword,
  looksLikeAwsAccountId,
  inferFormIntent,
  type FormContext,
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

  it('treats autocomplete=off as allowed, but new-password as disqualifying', () => {
    expect(looksLikeUsername({ type: 'text', autocomplete: 'off', name: 'username' })).toBe(true);
    expect(looksLikeUsername({ type: 'text', autocomplete: 'new-password', name: 'email' })).toBe(false);
  });

  it('rejects unrelated text inputs', () => {
    expect(looksLikeUsername({ type: 'text', name: 'street_address' })).toBe(false);
    expect(looksLikeUsername({ type: 'checkbox', name: 'email' })).toBe(false);
    expect(looksLikeUsername({})).toBe(false);
  });
});

describe('looksLikeAwsAccountId', () => {
  it('accepts field with id resolving_input', () => {
    expect(looksLikeAwsAccountId({ id: 'resolving_input' })).toBe(true);
  });

  it('accepts field with name account or accountid', () => {
    expect(looksLikeAwsAccountId({ name: 'account' })).toBe(true);
    expect(looksLikeAwsAccountId({ name: 'accountId' })).toBe(true);
  });

  it('accepts placeholder containing account id or account alias', () => {
    expect(looksLikeAwsAccountId({ placeholder: '12-digit Account ID or account alias' })).toBe(true);
  });

  it('rejects general non-AWS inputs', () => {
    expect(looksLikeAwsAccountId({ name: 'username' })).toBe(false);
    expect(looksLikeAwsAccountId({ placeholder: 'Search...' })).toBe(false);
    expect(looksLikeAwsAccountId({})).toBe(false);
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

  it('uses page URL path as a fallback when field attrs are generic', () => {
    // Zoho signup.html — id="password", no autocomplete, no sibling
    expect(looksLikeNewPassword({ name: 'password', id: 'password' }, false, 'https://zoho.com/signup.html')).toBe(true);
    // GitHub join page
    expect(looksLikeNewPassword({ name: 'user[password]', id: 'user_password' }, false, 'https://github.com/join')).toBe(true);
    // Generic /register path
    expect(looksLikeNewPassword({ name: 'password' }, false, 'https://example.com/register')).toBe(true);
    // create-account in path
    expect(looksLikeNewPassword({ name: 'password' }, false, 'https://example.com/create-account')).toBe(true);
    // onboarding flow
    expect(looksLikeNewPassword({ name: 'password' }, false, 'https://app.example.com/onboarding')).toBe(true);
    // Ordinary login page should NOT be affected
    expect(looksLikeNewPassword({ name: 'password' }, false, 'https://accounts.zoho.com/signin')).toBe(false);
    expect(looksLikeNewPassword({ name: 'password' }, false, 'https://login.github.com/')).toBe(false);
  });
});

// Helper to build a minimal FormContext, overriding only the keys under test.
function ctx(overrides: Partial<FormContext> = {}): FormContext {
  return {
    submitButtonText: '',
    headingText: '',
    pageTitle: '',
    formAction: '',
    nearbyLinkText: '',
    hasTermsCheckbox: false,
    nonPasswordInputCount: 2,
    ...overrides,
  };
}

describe('inferFormIntent', () => {
  it('classifies signup by submit button text alone (weight ±3)', () => {
    expect(inferFormIntent(ctx({ submitButtonText: 'Sign Up' }))).toBe('signup');
    expect(inferFormIntent(ctx({ submitButtonText: 'Create account' }))).toBe('signup');
    expect(inferFormIntent(ctx({ submitButtonText: 'Register' }))).toBe('signup');
    expect(inferFormIntent(ctx({ submitButtonText: 'Join now' }))).toBe('signup');
    expect(inferFormIntent(ctx({ submitButtonText: 'Get Started' }))).toBe('signup');
  });

  it('classifies login by submit button text alone', () => {
    expect(inferFormIntent(ctx({ submitButtonText: 'Sign In' }))).toBe('login');
    expect(inferFormIntent(ctx({ submitButtonText: 'Log in' }))).toBe('login');
    expect(inferFormIntent(ctx({ submitButtonText: 'Continue' }))).toBe('login');
  });

  it('classifies signup by heading text (weight ±2)', () => {
    expect(inferFormIntent(ctx({ headingText: 'Create your free account' }))).toBe('signup');
    expect(inferFormIntent(ctx({ headingText: 'Welcome back' }))).toBe('login');
  });

  it('uses page title as a weak signal (weight ±1)', () => {
    // Title alone is not enough to tip score — needs a second signal
    expect(inferFormIntent(ctx({ pageTitle: 'Sign Up | Zoho', nonPasswordInputCount: 3 }))).toBe('signup');
    expect(inferFormIntent(ctx({ pageTitle: 'Sign In | GitHub', nonPasswordInputCount: 1 }))).toBe('login');
  });

  it('classifies by form action URL (weight ±2)', () => {
    expect(inferFormIntent(ctx({ formAction: '/api/signup' }))).toBe('signup');
    expect(inferFormIntent(ctx({ formAction: '/auth/login' }))).toBe('login');
    expect(inferFormIntent(ctx({ formAction: '/session/new' }))).toBe('login');
  });

  it('reads cross-links correctly (weight ±2)', () => {
    // "Already have an account?" appears on signup pages
    expect(inferFormIntent(ctx({ nearbyLinkText: 'Already have an account? Sign in' }))).toBe('signup');
    // "Don't have an account?" appears on login pages
    expect(inferFormIntent(ctx({ nearbyLinkText: "Don't have an account? Sign up" }))).toBe('login');
  });

  it('treats terms checkbox as a signup signal (weight +2)', () => {
    expect(inferFormIntent(ctx({ hasTermsCheckbox: true }))).toBe('signup');
  });

  it('uses field count as a tiebreaker (weight ±1)', () => {
    // 3+ inputs → signup bias
    expect(inferFormIntent(ctx({ nonPasswordInputCount: 4 }))).toBe('signup');
    // 1 input → login bias
    expect(inferFormIntent(ctx({ nonPasswordInputCount: 1 }))).toBe('login');
    // 2 inputs → neutral → unknown
    expect(inferFormIntent(ctx({ nonPasswordInputCount: 2 }))).toBe('unknown');
  });

  it('combines signals — Zoho signup page scenario', () => {
    // zoho.com/signup.html: title has "Sign up", terms checkbox present,
    // nearby link "Already have a Zoho Account? SIGN IN", 3 inputs (email, phone, ...)
    expect(inferFormIntent(ctx({
      pageTitle: 'Create New Account | Sign up to Zoho',
      nearbyLinkText: 'Already have a Zoho Account? SIGN IN',
      hasTermsCheckbox: true,
      nonPasswordInputCount: 3,
    }))).toBe('signup');
  });

  it('combines signals — standard login page scenario', () => {
    expect(inferFormIntent(ctx({
      submitButtonText: 'Sign in',
      headingText: 'Welcome back',
      nearbyLinkText: "Don't have an account? Create one",
      nonPasswordInputCount: 1,
    }))).toBe('login');
  });

  it('returns unknown when evidence is evenly balanced', () => {
    expect(inferFormIntent(ctx())).toBe('unknown');
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
