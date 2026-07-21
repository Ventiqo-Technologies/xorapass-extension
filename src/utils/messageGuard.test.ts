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
});
