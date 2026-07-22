import { describe, it, expect } from 'vitest';
import {
  CLIPBOARD_CLEAR_OPTIONS,
  DEFAULT_CLIPBOARD_CLEAR_SECONDS,
  MIN_CLIPBOARD_CLEAR_SECONDS,
  clearDelayInMinutes,
  normalizeClearSeconds,
} from './clipboardPolicy';

describe('normalizeClearSeconds', () => {
  it('keeps a usable delay as-is', () => {
    expect(normalizeClearSeconds(30)).toBe(30);
    expect(normalizeClearSeconds(120)).toBe(120);
  });

  it('treats zero and negatives as explicitly disabled', () => {
    expect(normalizeClearSeconds(0)).toBe(0);
    expect(normalizeClearSeconds(-5)).toBe(0);
  });

  it('raises delays Chrome would silently clamp anyway', () => {
    expect(normalizeClearSeconds(1)).toBe(MIN_CLIPBOARD_CLEAR_SECONDS);
    expect(normalizeClearSeconds(29)).toBe(MIN_CLIPBOARD_CLEAR_SECONDS);
  });

  it('falls back to the default — never to "never" — on garbage input', () => {
    // A corrupt setting must not be the reason a password stays on the
    // clipboard forever.
    for (const bad of [undefined, null, 'soon', NaN, Infinity, {}]) {
      expect(normalizeClearSeconds(bad)).toBe(DEFAULT_CLIPBOARD_CLEAR_SECONDS);
    }
  });

  it('floors fractional seconds', () => {
    expect(normalizeClearSeconds(90.7)).toBe(90);
  });
});

describe('clearDelayInMinutes', () => {
  it('converts seconds to the alarm unit', () => {
    expect(clearDelayInMinutes(30)).toBe(0.5);
    expect(clearDelayInMinutes(120)).toBe(2);
  });

  it('returns null when disabled so no alarm is armed', () => {
    expect(clearDelayInMinutes(0)).toBeNull();
  });
});

describe('CLIPBOARD_CLEAR_OPTIONS', () => {
  it('only offers delays that survive normalization', () => {
    // An option the worker would silently rewrite would leave the popup
    // showing a delay that is not the one in effect.
    for (const option of CLIPBOARD_CLEAR_OPTIONS) {
      expect(normalizeClearSeconds(option.value)).toBe(option.value);
    }
  });

  it('includes the default', () => {
    expect(CLIPBOARD_CLEAR_OPTIONS.map((o) => o.value)).toContain(
      DEFAULT_CLIPBOARD_CLEAR_SECONDS
    );
  });
});
