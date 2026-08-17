// Which vault items may be autofilled into a login form.
//
// A vault entry's `username`/`value` pair does NOT mean the same thing in every
// category. The web app overloads those two columns per type (see the save path
// in Dashboard.tsx):
//
//   login  -> username = username,    value = password        ← a real credential
//   other  -> username = identifier,  value = secret          ← a real credential
//   note   -> username = "",          value = "SECURE_NOTE"   ← a sentinel, not a secret
//   card   -> username = CARD NUMBER, value = CVV             ← payment data
//   sshkey -> username = username,    value = key passphrase  ← not a web login
//
// So filling any non-login category into a page is wrong in every case, and for
// `card` it is a genuine leak: the card number would be typed into the username
// field and the CVV into the password field of whatever login form happens to
// sit on a domain the user attached to that card.
//
// The category is therefore an authorization input, not a display detail, which
// is why this lives beside the domain checks rather than in the UI.

/** Categories whose username/value pair really is a web login credential. */
export const FILLABLE_CATEGORIES: ReadonlySet<string> = new Set(['login', 'other']);

/**
 * Whether an item may be offered for, or released to, an autofill.
 *
 * Defaults to "login" for a missing category so that pre-category entries (and
 * anything the server adds without one) keep working — those predate the typed
 * categories and are all logins.
 */
export function isFillableCategory(category?: string): boolean {
  return FILLABLE_CATEGORIES.has(category || 'login');
}
