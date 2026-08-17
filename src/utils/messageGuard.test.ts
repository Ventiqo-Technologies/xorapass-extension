import { describe, it, expect, vi } from 'vitest';

// messageGuard imports the webextension-polyfill default export, which throws if
// loaded outside a real extension context, so we mock it with the minimal
// surface the guard uses. The factory is hoisted above module scope, so the
// literals below cannot reference outer variables.
vi.mock('webextension-polyfill', () => ({
  default: {
    runtime: {
      id: 'own-extension-id',
      getURL: (path: string) => `chrome-extension://own-extension-id/${path}`,
    },
  },
}));

const OWN_ID = 'own-extension-id';
const OWN_BASE = `chrome-extension://${OWN_ID}/`;

import { validateMessage } from './messageGuard';

const popupSender = (): any => ({ id: OWN_ID, url: `${OWN_BASE}popup.html` });

const contentSender = (): any => ({ id: OWN_ID, url: 'https://example.com/login', tab: { id: 1 } });

describe('validateMessage — origin', () => {
  it('rejects messages from other extensions', () => {
    const res = validateMessage({ type: 'GET_STATUS' }, { id: 'other', url: `chrome-extension://other/x` } as any);
    expect(res.ok).toBe(false);
    expect(res.reason).toBe('foreign-sender');
  });
});

describe('validateMessage — shape', () => {
  it('rejects malformed messages', () => {
    expect(validateMessage(null, popupSender()).ok).toBe(false);
    expect(validateMessage({}, popupSender()).ok).toBe(false);
    expect(validateMessage('GET_STATUS', popupSender()).ok).toBe(false);
  });
  it('rejects unknown types', () => {
    const res = validateMessage({ type: 'DO_EVIL' }, popupSender());
    expect(res.reason).toBe('unknown-type');
  });
});

const unlockPayload = () => ({
  decryptedItems: [],
  email: 'a@b.c',
  token: 'jwt-token',
  encKey: 'a1b2c3',
});

describe('validateMessage — privileged operations', () => {
  it('allows UNLOCK_VAULT from the extension page', () => {
    const res = validateMessage(
      { type: 'UNLOCK_VAULT', payload: unlockPayload() },
      popupSender()
    );
    expect(res.ok).toBe(true);
  });
  it('rejects UNLOCK_VAULT from a content script', () => {
    const res = validateMessage(
      { type: 'UNLOCK_VAULT', payload: unlockPayload() },
      contentSender()
    );
    expect(res.reason).toBe('privileged-from-content');
  });
  it('rejects UNLOCK_VAULT missing the refresh credentials', () => {
    const { token, ...noToken } = unlockPayload();
    expect(
      validateMessage({ type: 'UNLOCK_VAULT', payload: noToken }, popupSender()).reason
    ).toBe('bad-payload');

    const { encKey, ...noKey } = unlockPayload();
    expect(
      validateMessage({ type: 'UNLOCK_VAULT', payload: noKey }, popupSender()).reason
    ).toBe('bad-payload');
  });
  it('rejects GET_STATUS originating from a web page', () => {
    expect(validateMessage({ type: 'GET_STATUS' }, contentSender()).reason).toBe('privileged-from-content');
  });
});

describe('validateMessage — payload validation', () => {
  it('accepts a well-formed GET_MATCHING_CREDENTIALS from a content script', () => {
    const res = validateMessage(
      { type: 'GET_MATCHING_CREDENTIALS', payload: { hostname: 'example.com' } },
      contentSender()
    );
    expect(res.ok).toBe(true);
  });
  it('rejects GET_MATCHING_CREDENTIALS without a hostname', () => {
    const res = validateMessage({ type: 'GET_MATCHING_CREDENTIALS', payload: {} }, contentSender());
    expect(res.reason).toBe('bad-payload');
  });
  it('rejects SET_SITE_DISABLED with a bad payload', () => {
    const res = validateMessage(
      { type: 'SET_SITE_DISABLED', payload: { hostname: 'example.com', disabled: 'yes' } },
      popupSender()
    );
    expect(res.reason).toBe('bad-payload');
  });
  it('accepts a valid SET_SITE_DISABLED', () => {
    const res = validateMessage(
      { type: 'SET_SITE_DISABLED', payload: { hostname: 'example.com', disabled: true } },
      popupSender()
    );
    expect(res.ok).toBe(true);
  });
  it('accepts a valid SET_AUTO_LOCK from the popup', () => {
    const res = validateMessage({ type: 'SET_AUTO_LOCK', payload: { minutes: 15 } }, popupSender());
    expect(res.ok).toBe(true);
  });
  it('rejects SET_AUTO_LOCK with a non-numeric payload', () => {
    const res = validateMessage({ type: 'SET_AUTO_LOCK', payload: { minutes: 'soon' } }, popupSender());
    expect(res.reason).toBe('bad-payload');
  });
  it('rejects SET_AUTO_LOCK / GET_SETTINGS from a content script (privileged)', () => {
    expect(validateMessage({ type: 'GET_SETTINGS' }, contentSender()).reason).toBe('privileged-from-content');
    expect(
      validateMessage({ type: 'SET_AUTO_LOCK', payload: { minutes: 5 } }, contentSender()).reason
    ).toBe('privileged-from-content');
  });
  it('accepts a valid SET_CLIPBOARD_CLEAR from the popup', () => {
    const res = validateMessage(
      { type: 'SET_CLIPBOARD_CLEAR', payload: { seconds: 30 } },
      popupSender()
    );
    expect(res.ok).toBe(true);
  });
  it('rejects SET_CLIPBOARD_CLEAR with a non-numeric payload', () => {
    const res = validateMessage(
      { type: 'SET_CLIPBOARD_CLEAR', payload: { seconds: 'later' } },
      popupSender()
    );
    expect(res.reason).toBe('bad-payload');
  });
  it('accepts a payload-free CLIPBOARD_COPIED from the popup', () => {
    expect(validateMessage({ type: 'CLIPBOARD_COPIED' }, popupSender()).ok).toBe(true);
  });

  // AI_FILL_RESULT is what tells the server a brokered credential really was
  // applied, so a malformed one must never reach the API — an unrecognised
  // outcome is coerced to "failed" there, which would mask a broken caller.
  it('accepts a well-formed AI_FILL_RESULT from a content script', () => {
    // Content-reachable on purpose: the content script is the thing that typed,
    // so it is the only context that knows the outcome.
    expect(
      validateMessage(
        { type: 'AI_FILL_RESULT', payload: { fillId: 'f1', outcome: 'filled' } },
        contentSender()
      ).ok
    ).toBe(true);
    expect(
      validateMessage(
        { type: 'AI_FILL_RESULT', payload: { fillId: 'f1', outcome: 'failed', reason: 'domain_mismatch' } },
        contentSender()
      ).ok
    ).toBe(true);
  });
  it('rejects AI_FILL_RESULT with an outcome outside the enum', () => {
    for (const outcome of ['ok', 'FILLED', 'success', true, 1, undefined]) {
      expect(
        validateMessage({ type: 'AI_FILL_RESULT', payload: { fillId: 'f1', outcome } }, contentSender())
          .reason
      ).toBe('bad-payload');
    }
  });
  it('rejects AI_FILL_RESULT without a fillId, or with a non-string reason', () => {
    expect(
      validateMessage({ type: 'AI_FILL_RESULT', payload: { outcome: 'filled' } }, contentSender()).reason
    ).toBe('bad-payload');
    expect(
      validateMessage(
        { type: 'AI_FILL_RESULT', payload: { fillId: 'f1', outcome: 'failed', reason: { a: 1 } } },
        contentSender()
      ).reason
    ).toBe('bad-payload');
  });
  it('rejects clipboard messages from a content script (privileged)', () => {
    // A page could otherwise re-arm the timer repeatedly and postpone the
    // clear indefinitely.
    expect(validateMessage({ type: 'CLIPBOARD_COPIED' }, contentSender()).reason).toBe(
      'privileged-from-content'
    );
    expect(
      validateMessage(
        { type: 'SET_CLIPBOARD_CLEAR', payload: { seconds: 0 } },
        contentSender()
      ).reason
    ).toBe('privileged-from-content');
  });
});
