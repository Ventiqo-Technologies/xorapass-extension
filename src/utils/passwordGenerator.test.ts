import { describe, it, expect } from 'vitest';
import {
  generatePassword,
  entropyBits,
  strengthTier,
  randomInt,
  LOWER,
  UPPER,
  DIGITS,
  SYMBOLS,
  MIN_LENGTH,
  MAX_LENGTH,
} from './passwordGenerator';

const has = (s: string, set: string) => Array.from(s).some((c) => set.includes(c));

describe('randomInt', () => {
  it('stays within bounds', () => {
    for (let i = 0; i < 500; i++) {
      const v = randomInt(10);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(10);
    }
  });

  it('rejects non-positive bounds', () => {
    expect(() => randomInt(0)).toThrow();
    expect(() => randomInt(-1)).toThrow();
    expect(() => randomInt(1.5)).toThrow();
  });

  it('covers the whole range rather than collapsing to one value', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 500; i++) seen.add(randomInt(8));
    expect(seen.size).toBe(8);
  });
});

describe('generatePassword', () => {
  it('honours the requested length', () => {
    expect(generatePassword({ length: 24 })).toHaveLength(24);
    expect(generatePassword({ length: 32 })).toHaveLength(32);
  });

  it('clamps lengths outside the supported range', () => {
    expect(generatePassword({ length: 2 })).toHaveLength(MIN_LENGTH);
    expect(generatePassword({ length: 5000 })).toHaveLength(MAX_LENGTH);
  });

  it('includes at least one character from every enabled class', () => {
    // Repeated because the guarantee is probabilistic if implemented wrongly.
    for (let i = 0; i < 40; i++) {
      const pw = generatePassword({ length: 12 });
      expect(has(pw, LOWER)).toBe(true);
      expect(has(pw, UPPER)).toBe(true);
      expect(has(pw, DIGITS)).toBe(true);
      expect(has(pw, SYMBOLS)).toBe(true);
    }
  });

  it('omits classes that are turned off', () => {
    for (let i = 0; i < 25; i++) {
      const pw = generatePassword({ length: 16, symbols: false, digits: false });
      expect(has(pw, SYMBOLS)).toBe(false);
      expect(has(pw, DIGITS)).toBe(false);
    }
  });

  it('excludes ambiguous glyphs when asked', () => {
    for (let i = 0; i < 25; i++) {
      const pw = generatePassword({ length: 40, avoidAmbiguous: true });
      expect(/[Il1O0o|]/.test(pw)).toBe(false);
    }
  });

  it('falls back to lowercase when every class is disabled', () => {
    const pw = generatePassword({
      length: 12,
      lowercase: false,
      uppercase: false,
      digits: false,
      symbols: false,
    });
    expect(pw).toHaveLength(12);
    expect(/^[a-z]+$/.test(pw)).toBe(true);
  });

  it('does not park the guaranteed characters in a fixed prefix', () => {
    // Without a shuffle the first character would always come from the same
    // class, which is a real pattern an attacker could exploit.
    const firsts = new Set<string>();
    for (let i = 0; i < 60; i++) firsts.add(generatePassword({ length: 16 })[0]);
    expect(firsts.size).toBeGreaterThan(5);
  });

  it('produces different passwords across calls', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) seen.add(generatePassword({ length: 20 }));
    expect(seen.size).toBe(50);
  });
});

describe('entropyBits', () => {
  it('grows with length and with pool size', () => {
    const short = entropyBits({ length: 12 });
    const long = entropyBits({ length: 24 });
    expect(long).toBeGreaterThan(short);

    const narrow = entropyBits({ length: 16, symbols: false, digits: false, uppercase: false });
    const wide = entropyBits({ length: 16 });
    expect(wide).toBeGreaterThan(narrow);
  });

  it('matches the expected value for a known configuration', () => {
    // 26 lowercase only, 16 chars => 16 * log2(26) ≈ 75.2
    expect(entropyBits({ length: 16, uppercase: false, digits: false, symbols: false })).toBe(75);
  });
});

describe('strengthTier', () => {
  it('maps bits onto the expected tiers', () => {
    expect(strengthTier(30).tone).toBe('weak');
    expect(strengthTier(50).tone).toBe('fair');
    expect(strengthTier(80).tone).toBe('good');
    expect(strengthTier(130).tone).toBe('strong');
  });
});
