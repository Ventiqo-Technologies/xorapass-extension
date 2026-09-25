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
  labelText?: string | null;
  role?: string | null;
  className?: string | null;
}

const USERNAME_HINT =
  /user|email|login|account|phone|mobile|identifier|benutzer|mitglied|kundennummer|utilisateur|courriel|identifiant|compte|usuario|correo|cuenta|identificador|usuário|utilizador|utente|accesso|gebruikersnaam|пользователь|логин|аккаунт|ユーザー|アカウント|メール|用户|账号|手机|邮箱/i;

// Fields that look username-ish by name but must never receive a username —
// checked before the positive hints so "search-user" style inputs stay excluded.
const NEGATIVE_HINT =
  /search|query|filter|find|lookup|keyword|coupon|promo|captcha|otp|token|code|zip|postal|suche|recherche|buscar|pesquisa|cerca|поиск|検索|搜索/i;

/**
 * Heuristic for "is this the username/email input paired with a password
 * field?". Mirrors what mainstream password managers do: trust an explicit
 * autocomplete token first, then fall back to type plus name/id/label hints.
 */
export function looksLikeUsername(attrs: FieldAttrs): boolean {
  const type = (attrs.type || 'text').toLowerCase();
  if (type === 'password' || type === 'hidden' || type === 'submit' || type === 'search') return false;

  const role = (attrs.role || '').toLowerCase();
  if (role === 'searchbox') return false;

  const ac = (attrs.autocomplete || '').toLowerCase();
  // An explicit autocomplete token is authoritative in both directions.
  if (ac.includes('username') || ac.includes('email')) return true;
  if (ac.includes('new-password')) return false;

  const id = (attrs.id || '').toLowerCase();
  // AWS CloudScape Design System input: awsui-input-*
  if (id.startsWith('awsui-input')) return true;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel, attrs.labelText, attrs.className]
    .filter(Boolean)
    .join(' ');

  if (NEGATIVE_HINT.test(hints)) return false;
  if (type === 'email') return true;
  if (type !== 'text' && type !== 'tel') return false;

  return USERNAME_HINT.test(hints);
}

/**
 * Heuristic for detecting the AWS Account ID or alias input field.
 * In the AWS Management Console login page, this is typically '#resolving_input'.
 */
export function looksLikeAwsAccountId(attrs: FieldAttrs): boolean {
  const id = (attrs.id || '').toLowerCase();
  const name = (attrs.name || '').toLowerCase();
  const placeholder = (attrs.placeholder || '').toLowerCase();
  const ariaLabel = (attrs.ariaLabel || '').toLowerCase();
  
  if (id === 'resolving_input') return true;
  if (name === 'account' || name === 'accountid' || id === 'account' || id === 'accountid') return true;
  if (placeholder.includes('account id') || placeholder.includes('account alias') || placeholder.includes('account')) return true;
  if (ariaLabel.includes('account id') || ariaLabel.includes('account alias') || ariaLabel.includes('account')) return true;

  return false;
}

const NEW_PASSWORD_HINT =
  /new|signup|sign-up|register|create|confirm|repeat|retype|verify|neu|erstellen|bestätigen|wiederholen|registrieren|nouveau|nouvelle|créer|confirmer|répéter|inscrire|nueva|nuevo|crear|confirmar|repetir|registrar|nova|cadastrar|nuova|nuovo|conferma|ripeti|registra|新密码|确认|重复|注册|创建|新規|新しい|確認|再入力|作成|登録/i;

const CURRENT_PASSWORD_HINT =
  /current|existing|old|previous|alt|aktuell|bisherig|actuel|ancien|actual|anterior|atual|antiga|attuale|当前|原密码|旧密码|現在|以前/i;

/**
 * Whether a password field represents entering the user's *current/existing*
 * password on a change-password or re-authentication form.
 */
export function looksLikeCurrentPassword(attrs: FieldAttrs): boolean {
  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('current-password')) return true;
  if (ac.includes('new-password')) return false;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel, attrs.labelText]
    .filter(Boolean)
    .join(' ');

  return CURRENT_PASSWORD_HINT.test(hints);
}

// URL path/search tokens that reliably indicate a sign-up or account-creation
// page, used as a page-level fallback when field attributes give no signal
// (e.g. Zoho signup.html uses id="password", no autocomplete, no placeholder).
const SIGNUP_URL_HINT =
  /signup|sign-up|register|join|create[_-]?account|new[_-]?account|enroll|onboarding|registrieren|inscrire|cadastrar/i;

/**
 * Whether a password field is being used to choose a *new* password (sign-up,
 * password change) rather than to enter an existing one. The autocomplete
 * token is authoritative when present — it is exactly what it exists for —
 * with name/id/placeholder hints as the fallback.
 *
 * `hasSibling` should be true when the page has more than one password field,
 * which on its own is a strong sign of a "password + confirm" pair.
 *
 * `pageUrl` (optional) is the full page URL. When the path/search contains a
 * signup/register keyword, a lone generic password field is treated as new.
 *
 * When field attrs and URL give no signal, pass the password field's owning
 * `<form>` element (or null) to `inferFormIntent` and use that result.
 */
export function looksLikeNewPassword(
  attrs: FieldAttrs,
  hasSibling = false,
  pageUrl?: string
): boolean {
  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('new-password')) return true;
  if (ac.includes('current-password')) return false;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel]
    .filter(Boolean)
    .join(' ');

  if (CURRENT_PASSWORD_HINT.test(hints)) return false;
  if (NEW_PASSWORD_HINT.test(hints)) return true;
  if (hasSibling) return true;

  // Page-level URL fallback: if the path or query string signals a sign-up
  // flow, treat the field as new so a generate-password option is offered.
  if (pageUrl) {
    try {
      const url = new URL(pageUrl);
      const pathAndSearch = url.pathname + url.search;
      if (SIGNUP_URL_HINT.test(pathAndSearch)) return true;
    } catch {
      // Malformed URL — ignore.
    }
  }

  return false;
}

// ─── Form Intent Scorer ───────────────────────────────────────────────────────
//
// Instead of maintaining per-site lists, we read the surrounding DOM the same
// way a human would to answer "is this a signup or login form?".  Seven
// independent signals are scored; the sum decides the intent.
//
// Score > 0  → signup   (generate-password offered)
// Score < 0  → login    (only autofill offered)
// Score = 0  → unknown  (caller falls back to its own logic)

/** Signals observed about a form from its surrounding DOM. */
export interface FormContext {
  /** Text content of the submit button(s) inside / nearest to the form. */
  submitButtonText: string;
  /** Combined text of the nearest h1 / h2 / h3 visible on the page. */
  headingText: string;
  /** document.title */
  pageTitle: string;
  /** The form's action attribute (URL or path), if present. */
  formAction: string;
  /** Text of links near the form (e.g. "Already have an account? Sign in"). */
  nearbyLinkText: string;
  /** True when a checkbox whose label/name mentions terms/privacy is present in the form. */
  hasTermsCheckbox: boolean;
  /** Number of non-password, non-hidden inputs visible inside the same form. */
  nonPasswordInputCount: number;
}

export type FormIntent = 'signup' | 'login' | 'password_change' | 'unknown';

// Words indicating password change / reset / update flows
const PASSWORD_CHANGE_WORDS =
  /(?:\b(?:change[ -]?password|reset[ -]?password|update[ -]?password|new[ -]?password|set[ -]?password|passwort[ -]?ändern|kennwort[ -]?ändern|wachtwoord[ -]?wijzigen)\b|update.{0,10}password|change.{0,10}password|reset.{0,10}password|changer.{0,10}mot de passe|modifier.{0,10}mot de passe|cambiar.{0,10}contraseña|modificar.{0,10}contraseña|alterar.{0,10}senha|mudar.{0,10}senha|cambia.{0,10}password|сменить[ -]?пароль|изменить[ -]?пароль|パスワード(の)?変更|修改密码|更改密码)/i;

// Words that strongly suggest the form's purpose is account creation.
const SIGNUP_WORDS =
  /(?:\b(?:sign[ -]?up|create|register|join|get started|start free|new account|open account|enrol{1,2}|onboard|registrieren|konto erstellen|neues konto|registrarse|crear cuenta|registro|cadastrar|cadastre-se|criar conta|registrati|crea account|iscriviti|registreren|account aanmaken)\b|créer.{0,10}compte|s'inscrire|inscription|регистрация|создать аккаунт|新規登録|アカウント作成|注册|创建账户|新建账号)/i;

// Words that strongly suggest the form's purpose is authentication.
const LOGIN_WORDS =
  /(?:\b(?:sign[ -]?in|log[ -]?in|login|continue|enter|access|unlock|welcome back|anmelden|einloggen|connexion|ingresar|entrar|accedi|accesso|inloggen)\b|se connecter|iniciar sesión|iniciar sessão|войти|вход|авторизация|ログイン|サインイン|登录|登入)/i;

// "Already have an account?" style cross-links appear on signup pages.
// Note: avoid bare "have an account" which is a substring of "Don't have an account".
const HAVE_ACCOUNT_LINK = /already.{0,20}account|back to (sign|log)/i;

// "Don't have an account?" / "New here?" style cross-links appear on login pages.
const NO_ACCOUNT_LINK = /don.t have|no account|new (here|user|to)|create.{0,10}account|sign.?up/i;

/**
 * Scores the surrounding DOM context of a password field to determine whether
 * its containing form is a sign-up form, sign-in form, or password change form.
 *
 * All DOM reading is done by the caller (content.ts), which passes a plain
 * `FormContext` object so this function stays pure and fully unit-testable.
 *
 * Returns 'signup', 'login', 'password_change', or 'unknown' when the evidence is inconclusive.
 */
export function inferFormIntent(ctx: FormContext): FormIntent {
  // ① Priority check: Password change / reset intent
  let changeScore = 0;
  if (PASSWORD_CHANGE_WORDS.test(ctx.submitButtonText)) changeScore += 4;
  if (PASSWORD_CHANGE_WORDS.test(ctx.headingText))      changeScore += 3;
  if (PASSWORD_CHANGE_WORDS.test(ctx.pageTitle))        changeScore += 2;
  if (/change|reset|update-password|password_reset|password-change/i.test(ctx.formAction)) changeScore += 2;
  if (changeScore >= 3) return 'password_change';

  let score = 0;

  // ② Submit button text  (strongest single signal, weight ±3)
  if (SIGNUP_WORDS.test(ctx.submitButtonText)) score += 3;
  if (LOGIN_WORDS.test(ctx.submitButtonText))  score -= 3;

  // ③ Page heading (h1/h2/h3)  (weight ±2)
  if (SIGNUP_WORDS.test(ctx.headingText)) score += 2;
  if (LOGIN_WORDS.test(ctx.headingText))  score -= 2;

  // ④ Page <title>  (weight ±1 — titles are less reliable)
  if (SIGNUP_WORDS.test(ctx.pageTitle)) score += 1;
  if (LOGIN_WORDS.test(ctx.pageTitle))  score -= 1;

  // ⑤ Form action URL  (weight ±2)
  if (SIGNUP_URL_HINT.test(ctx.formAction)) score += 2;
  if (/login|signin|sign-in|auth|session/i.test(ctx.formAction)) score -= 2;

  // ⑥ Cross-links near the form  (weight ±2)
  //    "Already have an account? Sign in" → we are on a signup page
  //    "Don't have an account? Sign up"   → we are on a login page
  if (HAVE_ACCOUNT_LINK.test(ctx.nearbyLinkText)) score += 2;
  if (NO_ACCOUNT_LINK.test(ctx.nearbyLinkText))   score -= 2;

  // ⑦ Terms / privacy checkbox (weight +2 — almost never on login forms)
  if (ctx.hasTermsCheckbox) score += 2;

  // ⑧ Field count: signup forms usually have 3+ inputs (name, email, phone…)
  //    login forms usually have 1–2 (email + password)
  if (ctx.nonPasswordInputCount >= 3) score += 1;
  if (ctx.nonPasswordInputCount <= 1) score -= 1;

  if (score > 0) return 'signup';
  if (score < 0) return 'login';
  return 'unknown';
}

/**
 * Reads the DOM context around `field` and returns a FormContext object that
 * can be passed directly to `inferFormIntent`. Call this from content.ts where
 * live DOM access is available.
 */
export function collectFormContext(field: HTMLInputElement): FormContext {
  // Walk up to the closest <form>; fall back to document.body so the
  // heuristic still works on formless pages (many SPA login widgets).
  const form: HTMLElement = field.closest('form') ?? document.body;

  // ① Submit button text — the button that submits this form.
  const buttons = Array.from(
    form.querySelectorAll<HTMLElement>(
      'button[type="submit"], input[type="submit"], button:not([type="reset"])'
    )
  );
  const submitButtonText = buttons.map((b) => b.textContent || '').join(' ').trim();

  // ② Heading — nearest h1/h2/h3 anywhere in the form or on the whole page.
  const headingEl =
    form.querySelector('h1,h2,h3') ??
    document.querySelector('h1,h2,h3');
  const headingText = (headingEl?.textContent ?? '').trim();

  // ③ Page title.
  const pageTitle = document.title;

  // ④ Form action URL.
  const formEl = field.closest('form');
  const formAction = formEl?.getAttribute('action') ?? '';

  // ⑤ Nearby link text — links inside the form + up to one parent container.
  const linkContainer: HTMLElement =
    (form === document.body
      ? field.closest('section,div,main') ?? document.body
      : form) as HTMLElement;
  const links = Array.from(linkContainer.querySelectorAll<HTMLAnchorElement>('a'));
  const nearbyLinkText = links.map((a) => a.textContent || '').join(' ').trim();

  // ⑥ Terms/privacy checkbox — any checkbox whose name, id, or associated
  //    label mentions terms, privacy, or agree.
  const checkboxes = Array.from(form.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'));
  const hasTermsCheckbox = checkboxes.some((cb) => {
    const label =
      cb.labels?.[0]?.textContent ??
      document.querySelector(`label[for="${cb.id}"]`)?.textContent ?? '';
    const hint = [cb.name, cb.id, label].join(' ').toLowerCase();
    return /terms|privacy|agree|consent|gdpr/i.test(hint);
  });

  // ⑦ Non-password, non-hidden, visible inputs.
  const allInputs = Array.from(
    form.querySelectorAll<HTMLInputElement>('input')
  );
  const nonPasswordInputCount = allInputs.filter(
    (i) =>
      i.type !== 'password' &&
      i.type !== 'hidden' &&
      i.type !== 'submit' &&
      i.type !== 'checkbox' &&
      i.type !== 'radio' &&
      i.offsetParent !== null
  ).length;

  return {
    submitButtonText,
    headingText,
    pageTitle,
    formAction,
    nearbyLinkText,
    hasTermsCheckbox,
    nonPasswordInputCount,
  };
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
  if (rect.width < 50 || rect.height < 20) return false;
  if (rect.top + rect.height < 0 || rect.top > viewport.height) return false;
  if (rect.left + rect.width < 0 || rect.left > viewport.width) return false;
  return true;
}
