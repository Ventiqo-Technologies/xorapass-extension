import { describe, expect, it } from 'vitest';
import type { Runtime } from 'webextension-polyfill';
import { credentialRequestUrl } from './credentialOrigin';

const sender = (overrides: Partial<Runtime.MessageSender & { origin?: string }> = {}) => ({
  id: 'own-extension',
  tab: { id: 1, url: 'https://victim.example.com/login' } as Runtime.MessageSender['tab'],
  frameId: 0,
  url: 'https://victim.example.com/login',
  origin: 'https://victim.example.com',
  ...overrides,
});

describe('SHIELD-004 credential request origin authorization', () => {
  it('allows the real top-page URL, including its path', () => {
    expect(credentialRequestUrl(sender())).toBe('https://victim.example.com/login');
  });

  it('allows a positively identified same-origin child frame', () => {
    expect(credentialRequestUrl(sender({ frameId: 3 }))).toBe('https://victim.example.com/login');
  });
  it('uses the current top-frame URL after same-document navigation while preserving child frame scope', () => {
    const tab = { id: 1, url: 'https://victim.example.com/other#route' } as Runtime.MessageSender['tab'];
    expect(credentialRequestUrl(sender({ tab }))).toBe('https://victim.example.com/other#route');
    expect(credentialRequestUrl(sender({ tab, frameId: 3 }))).toBe('https://victim.example.com/login');
  });

  it.each([
    'https://evil.invalid/login',
    'https://child.victim.example.com/login',
    'https://victim.example.com:8443/login',
    'http://victim.example.com/login',
  ])('rejects a different frame origin: %s', (url) => {
    expect(credentialRequestUrl(sender({ frameId: 2, url, origin: new URL(url).origin }))).toBeNull();
  });

  it('does not use the trusted top URL when the requesting URL is missing', () => {
    expect(credentialRequestUrl(sender({ url: undefined }))).toBeNull();
  });

  it.each(['about:blank', 'about:srcdoc', 'data:text/html,test', 'blob:https://victim.example.com/id',
    'file:///login.html', 'chrome-extension://own-extension/popup.html', 'not a URL', ''])
  ('rejects non-web/unknown requesting documents: %s', (url) => {
    expect(credentialRequestUrl(sender({ url, frameId: 2 }))).toBeNull();
  });

  it.each(['null', '', 'https://evil.invalid', 'https://victim.example.com:8443'])
  ('rejects opaque or inconsistent browser origin metadata: %s', (origin) => {
    expect(credentialRequestUrl(sender({ frameId: 2, origin }))).toBeNull();
  });

  it('supports a top frame on browsers without origin metadata', () => {
    expect(credentialRequestUrl(sender({ origin: undefined }))).toBe('https://victim.example.com/login');
  });

  it('denies a child frame when its effective origin cannot be verified', () => {
    expect(credentialRequestUrl(sender({ frameId: 2, origin: undefined }))).toBeNull();
  });

  it.each([undefined, -1, 0.5, NaN])('denies missing/invalid frame identifiers: %s', (frameId) => {
    expect(credentialRequestUrl(sender({ frameId }))).toBeNull();
  });

  it('denies callers without a real web tab', () => {
    expect(credentialRequestUrl(sender({ tab: undefined }))).toBeNull();
    expect(credentialRequestUrl(sender({ tab: { id: 1 } as Runtime.MessageSender['tab'] }))).toBeNull();
    expect(credentialRequestUrl(sender({ tab: { id: -1, url: 'https://victim.example.com' } as Runtime.MessageSender['tab'] }))).toBeNull();
  });

  it('uses exact origins rather than www normalization or registrable domains', () => {
    expect(credentialRequestUrl(sender({ url: 'https://www.victim.example.com', origin: 'https://www.victim.example.com' }))).toBeNull();
  });

  it('accepts matching explicit default ports and ordinary HTTP top pages', () => {
    expect(credentialRequestUrl(sender({ url: 'https://victim.example.com:443/login' })))
      .toBe('https://victim.example.com/login');
    expect(credentialRequestUrl(sender({
      tab: { id: 1, url: 'http://localhost:8080/login' } as Runtime.MessageSender['tab'],
      url: 'http://localhost:8080/login', origin: 'http://localhost:8080',
    }))).toBe('http://localhost:8080/login');
  });
});
