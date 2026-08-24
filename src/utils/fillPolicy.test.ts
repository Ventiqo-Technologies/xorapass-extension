import { describe, it, expect } from 'vitest';
import { isFillableCategory } from './fillPolicy';

describe('isFillableCategory', () => {
  it('allows the two categories that really hold a web login', () => {
    expect(isFillableCategory('login')).toBe(true);
    expect(isFillableCategory('other')).toBe(true);
  });

  it('refuses card entries', () => {
    // The important one. A card stores the CARD NUMBER in `username` and the
    // CVV in `value`, so offering it to a login form would type payment data
    // into whatever page sits on the matching domain.
    expect(isFillableCategory('card')).toBe(false);
  });

  it('refuses notes', () => {
    // A note's `value` is the literal sentinel "SECURE_NOTE" — filling it puts
    // that string in the password box, which is the visible symptom users hit.
    expect(isFillableCategory('note')).toBe(false);
  });

  it('refuses ssh keys', () => {
    // `value` is the key passphrase; random enough to look like ciphertext in a
    // form, and not a web credential in any case.
    expect(isFillableCategory('sshkey')).toBe(false);
  });

  it('treats a missing category as a login', () => {
    // Entries created before categories existed carry none, and they are all
    // logins. Failing closed here would silently break autofill for the oldest
    // (and most-used) items in a vault.
    expect(isFillableCategory(undefined)).toBe(true);
    expect(isFillableCategory('')).toBe(true);
  });

  it('refuses unknown categories', () => {
    // A category this build does not know about may overload username/value in
    // some new way, so it is not fillable until someone decides it is.
    expect(isFillableCategory('identity')).toBe(false);
    expect(isFillableCategory('crypto_wallet')).toBe(false);
  });

  it('is case-sensitive by design', () => {
    // The vault writes these values; a differently-cased one means something
    // upstream changed, and guessing would defeat the check.
    expect(isFillableCategory('Login')).toBe(false);
  });
});
