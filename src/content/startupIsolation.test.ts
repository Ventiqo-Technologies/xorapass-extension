import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { isStartupIsolatedHost } from '../utils/startupIsolation';

describe('Startup isolation domain matching', () => {
  it('correctly matches WhatsApp domains', () => {
    expect(isStartupIsolatedHost('web.whatsapp.com')).toBe(true);
    expect(isStartupIsolatedHost('sub.web.whatsapp.com')).toBe(true);
    expect(isStartupIsolatedHost('api.whatsapp.com')).toBe(true);
    expect(isStartupIsolatedHost('WEB.WHATSAPP.COM')).toBe(true);
  });

  it('correctly matches AWS Console, signin, and SSO domains', () => {
    expect(isStartupIsolatedHost('aws.amazon.com')).toBe(true);
    expect(isStartupIsolatedHost('console.aws.amazon.com')).toBe(true);
    expect(isStartupIsolatedHost('us-east-1.console.aws.amazon.com')).toBe(true);
    expect(isStartupIsolatedHost('signin.aws')).toBe(true);
    expect(isStartupIsolatedHost('us-east-1.signin.aws')).toBe(true);
    expect(isStartupIsolatedHost('awsapps.com')).toBe(true);
    expect(isStartupIsolatedHost('company.awsapps.com')).toBe(true);
  });

  it('correctly matches Microsoft SharePoint, OneDrive, and Office 365 domains', () => {
    expect(isStartupIsolatedHost('sharepoint.com')).toBe(true);
    expect(isStartupIsolatedHost('contoso.sharepoint.com')).toBe(true);
    expect(isStartupIsolatedHost('contoso-my.sharepoint.com')).toBe(true);
    expect(isStartupIsolatedHost('contoso.sharepoint-df.com')).toBe(true);
    expect(isStartupIsolatedHost('office.com')).toBe(true);
    expect(isStartupIsolatedHost('www.office.com')).toBe(true);
    expect(isStartupIsolatedHost('office.net')).toBe(true);
    expect(isStartupIsolatedHost('res.cdn.office.net')).toBe(true);
    expect(isStartupIsolatedHost('officeapps.live.com')).toBe(true);
    expect(isStartupIsolatedHost('word-edit.officeapps.live.com')).toBe(true);
    expect(isStartupIsolatedHost('excel.officeapps.live.com')).toBe(true);
    expect(isStartupIsolatedHost('powerpoint.officeapps.live.com')).toBe(true);
    expect(isStartupIsolatedHost('view.officeapps.live.com')).toBe(true);
    expect(isStartupIsolatedHost('onedrive.live.com')).toBe(true);
    expect(isStartupIsolatedHost('onedrive.com')).toBe(true);
    expect(isStartupIsolatedHost('microsoft.com')).toBe(true);
    expect(isStartupIsolatedHost('microsoftonline.com')).toBe(true);
    expect(isStartupIsolatedHost('login.microsoftonline.com')).toBe(true);
    expect(isStartupIsolatedHost('microsoft365.com')).toBe(true);
    expect(isStartupIsolatedHost('cloud.microsoft')).toBe(true);
    expect(isStartupIsolatedHost('tenant.cloud.microsoft')).toBe(true);
  });

  it('correctly matches Atlassian Cloud, Google Docs, and creative platforms', () => {
    expect(isStartupIsolatedHost('atlassian.net')).toBe(true);
    expect(isStartupIsolatedHost('ventiqo.atlassian.net')).toBe(true);
    expect(isStartupIsolatedHost('atlassian.com')).toBe(true);
    expect(isStartupIsolatedHost('jira.com')).toBe(true);
    expect(isStartupIsolatedHost('docs.google.com')).toBe(true);
    expect(isStartupIsolatedHost('drive.google.com')).toBe(true);
    expect(isStartupIsolatedHost('figma.com')).toBe(true);
    expect(isStartupIsolatedHost('canva.com')).toBe(true);
  });

  it('does not isolate regular Amazon retail or lookalike domains', () => {
    expect(isStartupIsolatedHost('amazon.com')).toBe(false);
    expect(isStartupIsolatedHost('www.amazon.com')).toBe(false);
    expect(isStartupIsolatedHost('smile.amazon.com')).toBe(false);
    expect(isStartupIsolatedHost('evil-whatsapp.com')).toBe(false);
    expect(isStartupIsolatedHost('not-aws.amazon.com.evil.com')).toBe(false);
    expect(isStartupIsolatedHost('fake-signin.aws.attacker.com')).toBe(false);
    expect(isStartupIsolatedHost('evil-sharepoint.com')).toBe(false);
    expect(isStartupIsolatedHost('not-sharepoint.com.attacker.com')).toBe(false);
    expect(isStartupIsolatedHost('fake-office.com')).toBe(false);
    expect(isStartupIsolatedHost('office.com.malicious.net')).toBe(false);
    expect(isStartupIsolatedHost('fake-microsoft.com')).toBe(false);
    expect(isStartupIsolatedHost('github.com')).toBe(false);
    expect(isStartupIsolatedHost('claude.ai')).toBe(false);
  });
});

describe('Production Bundle Smoke Test: dist/pageHooks.js', () => {
  const distDir = path.resolve(__dirname, '../../dist');
  const pageHooksPath = path.join(distDir, 'pageHooks.js');

  const bundleExists = fs.existsSync(pageHooksPath);
  const bundleCode = bundleExists ? fs.readFileSync(pageHooksPath, 'utf8') : '';

  function createPageHooksContext(hostname: string) {
    const sandbox: Record<string, any> = {};
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.location = {
      hostname,
      protocol: 'https:',
    };
    sandbox.navigator = {
      clipboard: {
        writeText: () => Promise.resolve(),
        readText: () => Promise.resolve(''),
      },
    };
    sandbox.document = {
      title: 'Test',
      createElement: () => ({}),
      addEventListener: () => {},
      removeEventListener: () => {},
    };
    sandbox.HTMLCanvasElement = function () {};
    sandbox.HTMLCanvasElement.prototype = {
      toDataURL: () => 'data:image/png;base64,',
      toBlob: () => {},
    };
    sandbox.CanvasRenderingContext2D = function () {};
    sandbox.CanvasRenderingContext2D.prototype = {
      getImageData: () => {},
    };
    sandbox.Element = function () {};
    sandbox.Element.prototype = {
      requestFullscreen: () => Promise.resolve(),
      requestPointerLock: () => {},
    };
    sandbox.EventTarget = typeof EventTarget !== 'undefined' ? EventTarget : function () {};
    sandbox.DataTransfer = function () {};
    sandbox.DataTransfer.prototype = { setData: () => {} };
    sandbox.Document = function () {};
    sandbox.Document.prototype = { execCommand: () => {} };
    sandbox.Window = function () {};
    sandbox.Window.prototype = {};
    sandbox.History = function () {};
    sandbox.History.prototype = { pushState: () => {} };
    sandbox.HTMLMediaElement = function () {};
    sandbox.HTMLMediaElement.prototype = { play: () => {} };
    sandbox.HTMLBodyElement = function () {};
    sandbox.HTMLBodyElement.prototype = {};
    sandbox.addEventListener = () => {};
    sandbox.removeEventListener = () => {};
    sandbox.postMessage = () => {};
    sandbox.setTimeout = setTimeout;
    sandbox.clearTimeout = clearTimeout;
    sandbox.setInterval = setInterval;
    sandbox.clearInterval = clearInterval;
    return vm.createContext(sandbox);
  }

  it('dist/pageHooks.js bundle exists and is non-empty', () => {
    expect(bundleExists).toBe(true);
    expect(bundleCode.length).toBeGreaterThan(100);
  });

  it('bypasses pageHooks on web.whatsapp.com', () => {
    const ctx = createPageHooksContext('web.whatsapp.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on console.aws.amazon.com', () => {
    const ctx = createPageHooksContext('console.aws.amazon.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on signin.aws', () => {
    const ctx = createPageHooksContext('signin.aws');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on myorg.awsapps.com', () => {
    const ctx = createPageHooksContext('myorg.awsapps.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on contoso.sharepoint.com', () => {
    const ctx = createPageHooksContext('contoso.sharepoint.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on word-edit.officeapps.live.com', () => {
    const ctx = createPageHooksContext('word-edit.officeapps.live.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('bypasses pageHooks on login.microsoftonline.com', () => {
    const ctx = createPageHooksContext('login.microsoftonline.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBeUndefined();
  });

  it('activates pageHooks on standard domain (github.com)', () => {
    const ctx = createPageHooksContext('github.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldHooked).toBe(true);
  });
});

describe('Production Bundle Smoke Test: dist/shieldNav.js', () => {
  const distDir = path.resolve(__dirname, '../../dist');
  const shieldNavPath = path.join(distDir, 'shieldNav.js');

  const bundleExists = fs.existsSync(shieldNavPath);
  const bundleCode = bundleExists ? fs.readFileSync(shieldNavPath, 'utf8') : '';

  function createShieldNavContext(hostname: string) {
    const addedListeners: string[] = [];
    const sandbox: Record<string, any> = {};
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.top = sandbox;
    sandbox.location = {
      hostname,
      protocol: 'https:',
      href: `https://${hostname}/`,
    };
    sandbox.crypto = webcrypto;
    sandbox.URL = URL;
    sandbox.chrome = {
      runtime: {
        id: 'mock-xorapass-extension-id',
        onMessage: { addListener: () => {}, removeListener: () => {}, hasListener: () => false },
        sendMessage: () => Promise.resolve({ action: 'allow' }),
      },
      storage: {
        onChanged: { addListener: () => {}, removeListener: () => {} },
      },
    };
    sandbox.document = {
      title: 'Test Page',
      documentElement: { appendChild: () => {} },
      body: { innerText: '' },
      createElement: () => ({
        style: {},
        appendChild: () => {},
        addEventListener: () => {},
      }),
      getElementById: () => null,
      addEventListener: () => {},
      removeEventListener: () => {},
    };
    sandbox.addEventListener = (event: string) => {
      addedListeners.push(event);
    };
    sandbox.removeEventListener = () => {};
    sandbox.setTimeout = setTimeout;
    sandbox.clearTimeout = clearTimeout;
    sandbox.setInterval = setInterval;
    sandbox.clearInterval = clearInterval;
    return { ctx: vm.createContext(sandbox), addedListeners };
  }

  it('dist/shieldNav.js bundle exists and is non-empty', () => {
    expect(bundleExists).toBe(true);
    expect(bundleCode.length).toBeGreaterThan(100);
  });

  it('bypasses typing guard and navigation interceptor on web.whatsapp.com', () => {
    const { ctx, addedListeners } = createShieldNavContext('web.whatsapp.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('bypasses typing guard and navigation interceptor on console.aws.amazon.com', () => {
    const { ctx, addedListeners } = createShieldNavContext('console.aws.amazon.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('bypasses typing guard and navigation interceptor on signin.aws', () => {
    const { ctx, addedListeners } = createShieldNavContext('signin.aws');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('bypasses typing guard and navigation interceptor on contoso.sharepoint.com', () => {
    const { ctx, addedListeners } = createShieldNavContext('contoso.sharepoint.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('bypasses typing guard and navigation interceptor on word-edit.officeapps.live.com', () => {
    const { ctx, addedListeners } = createShieldNavContext('word-edit.officeapps.live.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('bypasses typing guard and navigation interceptor on login.microsoftonline.com', () => {
    const { ctx, addedListeners } = createShieldNavContext('login.microsoftonline.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeUndefined();
    expect(addedListeners.length).toBe(0);
  });

  it('activates typing guard and navigation interceptor on standard domain (github.com)', () => {
    const { ctx, addedListeners } = createShieldNavContext('github.com');
    vm.runInContext(bundleCode, ctx);
    expect(ctx.__xoraShieldNav).toBeDefined();
    expect(ctx.__xoraShieldNav.host).toBe('github.com');
    expect(addedListeners).toEqual(
      expect.arrayContaining(['keydown', 'keypress', 'beforeinput', 'paste', 'drop'])
    );
  });
});
