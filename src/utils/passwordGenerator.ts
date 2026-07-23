// Password generation. Pure apart from crypto.getRandomValues, so it is unit
// tested in the plain node environment alongside the other utils.

export const LOWER = 'abcdefghijklmnopqrstuvwxyz';
export const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const DIGITS = '0123456789';
export const SYMBOLS = '!@#$%^&*()-_=+[]{}:;,.?';

// Glyphs that are easy to confuse when a password has to be read aloud or
// typed from a screen.
const AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0', 'o', '|']);

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export const DEFAULT_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

/**
 * Uniform random integer in [0, maxExclusive).
 *
 * Rejection sampling rather than `% maxExclusive` on its own: 2^32 is not a
 * multiple of most bounds, so a bare modulo makes the low values fractionally
 * more likely. Discarding the ragged tail removes that bias.
 */
export function randomInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error('randomInt: bound must be a positive integer');
  }
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  let value = 0;
  do {
    crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= limit);
  return value % maxExclusive;
}

function strip(set: string, avoidAmbiguous: boolean): string {
  if (!avoidAmbiguous) return set;
  return Array.from(set)
    .filter((c) => !AMBIGUOUS.has(c))
    .join('');
}

/** The character sets enabled by the options, already filtered. */
function activeSets(opts: GeneratorOptions): string[] {
  const sets: string[] = [];
  if (opts.lowercase) sets.push(strip(LOWER, opts.avoidAmbiguous));
  if (opts.uppercase) sets.push(strip(UPPER, opts.avoidAmbiguous));
  if (opts.digits) sets.push(strip(DIGITS, opts.avoidAmbiguous));
  if (opts.symbols) sets.push(strip(SYMBOLS, opts.avoidAmbiguous));
  return sets.filter((s) => s.length > 0);
}

function pick(set: string): string {
  return set[randomInt(set.length)];
}

/** In-place Fisher-Yates using the same unbiased source. */
function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

/**
 * Generates a password. Every enabled character class is guaranteed to appear
 * at least once — sites commonly reject passwords that happen to omit one —
 * and the result is shuffled so those guaranteed characters are not stuck in a
 * predictable prefix.
 */
export function generatePassword(options: Partial<GeneratorOptions> = {}): string {
  const opts: GeneratorOptions = { ...DEFAULT_OPTIONS, ...options };
  const sets = activeSets(opts);

  // Every class turned off would leave nothing to draw from; lowercase is the
  // least surprising fallback.
  if (sets.length === 0) sets.push(strip(LOWER, opts.avoidAmbiguous));

  const length = Math.max(MIN_LENGTH, Math.min(MAX_LENGTH, Math.floor(opts.length) || MIN_LENGTH));
  const pool = sets.join('');

  // One from each class first, then fill the remainder from the whole pool.
  const chars: string[] = sets.slice(0, length).map(pick);
  while (chars.length < length) chars.push(pick(pool));

  return shuffle(chars).join('');
}

/** Shannon entropy in bits, assuming each position is drawn from the pool. */
export function entropyBits(options: Partial<GeneratorOptions> = {}): number {
  const opts: GeneratorOptions = { ...DEFAULT_OPTIONS, ...options };
  const sets = activeSets(opts);
  const poolSize = (sets.length === 0 ? strip(LOWER, opts.avoidAmbiguous) : sets.join('')).length;
  const length = Math.max(MIN_LENGTH, Math.min(MAX_LENGTH, Math.floor(opts.length) || MIN_LENGTH));
  if (poolSize <= 1) return 0;
  return Math.round(length * Math.log2(poolSize));
}

export interface StrengthTier {
  label: string;
  tone: 'weak' | 'fair' | 'good' | 'strong';
}

/** Thresholds follow the usual guidance: 60 bits is the floor worth having. */
export function strengthTier(bits: number): StrengthTier {
  if (bits < 45) return { label: 'Weak', tone: 'weak' };
  if (bits < 70) return { label: 'Fair', tone: 'fair' };
  if (bits < 110) return { label: 'Good', tone: 'good' };
  return { label: 'Strong', tone: 'strong' };
}
