// Policy for how long a copied password is allowed to sit in the OS clipboard.
//
// Kept separate from the background worker so the clamping rules are unit
// testable without a browser: the worker only translates the result into an
// alarm.

/** Seconds after a copy at which the clipboard is overwritten. 0 = never. */
export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30;

/**
 * Chrome clamps `alarms.create({ delayInMinutes })` to a 30 second floor for
 * packed extensions, so anything shorter would silently stretch out anyway.
 * Advertising delays we cannot honour would be worse than not offering them.
 */
export const MIN_CLIPBOARD_CLEAR_SECONDS = 30;

export const CLIPBOARD_CLEAR_OPTIONS = [
  { label: '30 sec', value: 30 },
  { label: '1 min', value: 60 },
  { label: '2 min', value: 120 },
  { label: '5 min', value: 300 },
  { label: 'Never', value: 0 },
];

/**
 * Coerces a stored or user-supplied value into a delay we can actually honour.
 * Anything unusable falls back to the default rather than to "never", so a
 * corrupt setting cannot quietly leave passwords in the clipboard forever.
 */
export function normalizeClearSeconds(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  }
  if (value <= 0) return 0; // explicitly disabled
  return Math.max(MIN_CLIPBOARD_CLEAR_SECONDS, Math.floor(value));
}

/** The `delayInMinutes` value for a given delay, or null when disabled. */
export function clearDelayInMinutes(seconds: number): number | null {
  const normalized = normalizeClearSeconds(seconds);
  return normalized > 0 ? normalized / 60 : null;
}

/**
 * What we put in the clipboard in place of the password. `execCommand('copy')`
 * is a no-op on an empty selection, so a single space is the shortest string
 * that reliably replaces the previous contents.
 */
export const CLIPBOARD_PLACEHOLDER = ' ';
