import { describe, it, expect } from 'vitest';
import { isAuthError, isOfflineError } from './netErrors';

describe('isOfflineError', () => {
  it('treats a response-less failure as offline', () => {
    expect(isOfflineError({ code: 'ERR_NETWORK', message: 'Network Error' })).toBe(true);
    expect(isOfflineError(new Error('boom'))).toBe(true);
  });

  it('does not treat a refused credential as offline', () => {
    // The whole point: a 401 must never open the offline path, or a wrong
    // master password would appear to work whenever the server says no.
    expect(isOfflineError({ response: { status: 401 } })).toBe(false);
    expect(isOfflineError({ response: { status: 403 } })).toBe(false);
  });

  it('treats a 5xx as offline', () => {
    // A broken server can't confirm the password any more than an
    // unreachable one can -- both should fall back to the cached vault
    // rather than lock the user out because the backend is erroring.
    expect(isOfflineError({ response: { status: 500 } })).toBe(true);
    expect(isOfflineError({ response: { status: 503 } })).toBe(true);
  });

  it('ignores non-objects', () => {
    expect(isOfflineError(null)).toBe(false);
    expect(isOfflineError('offline')).toBe(false);
  });
});

describe('isAuthError', () => {
  it('recognises credential rejections', () => {
    for (const status of [400, 401, 403]) {
      expect(isAuthError({ response: { status } })).toBe(true);
    }
  });

  it('excludes other statuses and transport failures', () => {
    expect(isAuthError({ response: { status: 500 } })).toBe(false);
    expect(isAuthError({ response: { status: 404 } })).toBe(false);
    expect(isAuthError({ code: 'ERR_NETWORK' })).toBe(false);
    expect(isAuthError(null)).toBe(false);
  });
});
