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

// externally_connectable senders (app.xorapass.com) have no extension id at
// all -- that is precisely how the guard tells them apart from a content
// script, which always carries this extension's own id.
const externalWebSender = (): any => ({ url: 'https://app.xorapass.com/', origin: 'https://app.xorapass.com' });

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
  it('accepts a valid SET_LOCK_ON_SCREEN_LOCK from the popup', () => {
    const res = validateMessage(
      { type: 'SET_LOCK_ON_SCREEN_LOCK', payload: { enabled: false } },
      popupSender()
    );
    expect(res.ok).toBe(true);
  });
  it('rejects SET_LOCK_ON_SCREEN_LOCK with a non-boolean payload', () => {
    // Truthy-but-not-boolean must not sneak through: `enabled: 0` or
    // `enabled: 'no'` coerced by the handler would flip the control the wrong
    // way round.
    for (const enabled of ['no', 0, 1, null, undefined]) {
      expect(
        validateMessage({ type: 'SET_LOCK_ON_SCREEN_LOCK', payload: { enabled } }, popupSender())
          .reason
      ).toBe('bad-payload');
    }
  });
  it('rejects SET_LOCK_ON_SCREEN_LOCK from a content script (privileged)', () => {
    // This is the load-bearing case: a page that could send this would be able
    // to disable the control protecting an unattended machine.
    expect(
      validateMessage(
        { type: 'SET_LOCK_ON_SCREEN_LOCK', payload: { enabled: false } },
        contentSender()
      ).reason
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

describe('validateMessage — companion-device linking bridge', () => {
  it('allows a payload-free WEB_BRIDGE_DEVICE_INFO from app.xorapass.com', () => {
    expect(validateMessage({ type: 'WEB_BRIDGE_DEVICE_INFO' }, externalWebSender()).ok).toBe(true);
  });

  // token/email travel INSIDE the sealed envelope now (see
  // deviceLinkBridge.test.ts for the real-crypto round trip) -- the guard
  // can only validate the envelope's shape, not its contents.
  const sealedFixture = () => ({
    ciphertext: 'ciphertext-b64',
    tag: 'tag-b64',
    nonce: 'nonce-b64',
    keyVersion: 1,
  });
  const ephemeralPublicKeyFixture = () => ({ kty: 'EC', crv: 'P-256', x: 'x-coord', y: 'y-coord' });

  it('accepts a well-formed WEB_BRIDGE_DELIVER_KEY from app.xorapass.com', () => {
    const res = validateMessage(
      {
        type: 'WEB_BRIDGE_DELIVER_KEY',
        payload: {
          ephemeralPublicKey: ephemeralPublicKeyFixture(),
          sealed: sealedFixture(),
        },
      },
      externalWebSender()
    );
    expect(res.ok).toBe(true);
  });

  it('rejects WEB_BRIDGE_DELIVER_KEY missing the sealed envelope', () => {
    const res = validateMessage(
      {
        type: 'WEB_BRIDGE_DELIVER_KEY',
        payload: { ephemeralPublicKey: ephemeralPublicKeyFixture() },
      },
      externalWebSender()
    );
    expect(res.reason).toBe('bad-payload');
  });

  it('rejects WEB_BRIDGE_DELIVER_KEY missing the ephemeral public key', () => {
    const res = validateMessage(
      {
        type: 'WEB_BRIDGE_DELIVER_KEY',
        payload: { sealed: sealedFixture() },
      },
      externalWebSender()
    );
    expect(res.reason).toBe('bad-payload');
  });

  it('rejects WEB_BRIDGE_DELIVER_KEY with a malformed sealed envelope', () => {
    const res = validateMessage(
      {
        type: 'WEB_BRIDGE_DELIVER_KEY',
        payload: {
          ephemeralPublicKey: ephemeralPublicKeyFixture(),
          sealed: { ciphertext: 'x' }, // missing tag/nonce
        },
      },
      externalWebSender()
    );
    expect(res.reason).toBe('bad-payload');
  });

  it('still rejects a privileged, non-bridge type from an external web page', () => {
    expect(validateMessage({ type: 'GET_STATUS' }, externalWebSender()).reason).toBe(
      'unauthorized-external-type'
    );
  });

  it('accepts a well-formed WEB_BRIDGE_REQUEST_SESSION from app.xorapass.com', () => {
    const res = validateMessage(
      { type: 'WEB_BRIDGE_REQUEST_SESSION', payload: { ephemeralPublicKey: ephemeralPublicKeyFixture() } },
      externalWebSender()
    );
    expect(res.ok).toBe(true);
  });

  it('rejects WEB_BRIDGE_REQUEST_SESSION missing the ephemeral public key', () => {
    const res = validateMessage({ type: 'WEB_BRIDGE_REQUEST_SESSION', payload: {} }, externalWebSender());
    expect(res.reason).toBe('bad-payload');
  });
});
